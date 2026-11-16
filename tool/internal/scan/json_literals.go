package scan

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/mlfeatures"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
)

type sourceLiteral struct {
	name, value       string
	start, end, group int
	preparedStart     int
	preparedEnd       int
	sourceStarts      []int
	sourceEnds        []int
	raw               bool
	whole             bool
	transform         string
	proof             []model.Evidence
	noPassword        bool
	uiPassword        bool
}

type literalDocument struct {
	componentNamespaces map[int]string
	publicUnknown       map[int]map[string]bool
	firebaseSchema      *firebaseSchemaBindings
	original            string
	text                string
	values              []sourceLiteral
	scalars             map[int]detect.PasswordScalar
	contexts            map[int]string
	bindings            map[int]map[string]string
	roles               map[int]literalRole
	unsafeGroups        map[int]bool
	verificationUnsafe  bool
	lines               *lineIndex
	pragmas             *lineIndex // Optional parser-specific logical line boundaries.
	transform           string
}

func (doc *literalDocument) hasPragma(pos int) bool {
	if doc.pragmas != nil {
		return doc.pragmas.hasPragma(pos)
	}
	return doc.lines.hasPragma(pos)
}

// jsonLiterals preserves duplicate keys and original byte spans. It never unmarshals objects into
// maps, executes substitutions, or silently accepts the Unicode replacement performed by encoding/json.
func jsonLiteralsWithPublic(ctx context.Context, it model.Item, capturePublic bool) *literalDocument {
	if !pathIsFilesystem(it.Source) || strings.ToLower(filepath.Ext(model.SafeLocator(it.Path))) != ".json" {
		return nil
	}
	fail := func(code string) *literalDocument {
		model.Note(ctx, code, it.Path, true)
		return nil
	}
	if len(it.Text) > 1<<20 {
		return fail("json_literal_limit")
	}
	text := strings.TrimPrefix(it.Text, "\uFEFF")
	base := len(it.Text) - len(text)
	if !utf8.ValidString(it.Text) || !json.Valid([]byte(text)) {
		return fail("json_literal_parse")
	}
	type frame struct {
		object, key bool
		name        string
		group       int
		role        literalRole
		keys        map[string]bool
	}
	var stack []frame
	var componentPaths map[int][]string
	if captureComponentNamespaces(ctx) {
		componentPaths = make(map[int][]string)
	}
	group := 0
	consume := func() {
		if len(stack) > 0 && stack[len(stack)-1].object {
			stack[len(stack)-1].key = true
			stack[len(stack)-1].name = ""
		}
	}
	doc := &literalDocument{original: it.Text, lines: newLineIndex(it.Text), transform: "json-string", roles: map[int]literalRole{}, unsafeGroups: map[int]bool{}}
	doc.lines.resetPragmas() // JSON has no comments; strings cannot manufacture allow directives.
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber() // Valid JSON numbers need not fit in a Go float64.
	for count := 0; ; count++ {
		if ctx.Err() != nil {
			return nil
		}
		if count >= 100000 {
			return fail("json_literal_limit")
		}
		before := int(decoder.InputOffset()) + base
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail("json_literal_parse")
		}
		switch token := token.(type) {
		case json.Delim:
			if token == '{' || token == '[' {
				if len(stack) >= 64 {
					return fail("json_literal_limit")
				}
				role := literalRole{}
				var componentPath []string
				if len(stack) > 0 {
					parent := stack[len(stack)-1]
					role = parent.role.child(parent.name)
					if componentPaths != nil {
						componentPath = append(append([]string(nil), componentPaths[parent.group]...), parent.name)
					}
				}
				if capturePublic && len(stack) > 0 {
					parent := stack[len(stack)-1]
					if parent.object {
						doc.markPublicUnknown(parent.group, parent.name)
					}
				}
				consume()
				group++
				doc.roles[group] = role
				if componentPaths != nil {
					if doc.componentNamespaces == nil {
						doc.componentNamespaces = make(map[int]string)
					}
					doc.componentNamespaces[group] = componentNamespace(componentPath)
					componentPaths[group] = componentPath
				}
				stack = append(stack, frame{object: token == '{', key: token == '{', group: group, role: role, keys: map[string]bool{}})
			} else {
				stack = stack[:len(stack)-1]
			}
		case string:
			end := int(decoder.InputOffset()) + base - 1
			start := before
			for start < end && it.Text[start] != '"' {
				start++
			}
			start++
			if !validJSONSurrogates(it.Text[start:end]) {
				return fail("json_literal_unicode")
			}
			if len(token) > 4096 || len(doc.values) >= 10000 {
				return fail("json_literal_limit")
			}
			if len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].key {
				f := &stack[len(stack)-1]
				if f.keys[token] {
					doc.unsafeGroups[f.group] = true
					model.Note(ctx, "json_literal_duplicate", it.Path, true)
				}
				f.keys[token] = true
				// Object keys are strings too: a credential used as a dictionary key must not vanish
				// merely because another field triggers normalization. They have no password binding.
				doc.values = append(doc.values, sourceLiteral{value: token, start: start, end: end, group: stack[len(stack)-1].group})
				stack[len(stack)-1].name = token
				stack[len(stack)-1].key = false
				continue
			}
			v := sourceLiteral{value: token, start: start, end: end}
			if len(stack) > 0 {
				v.name, v.group = stack[len(stack)-1].name, stack[len(stack)-1].group
			}
			doc.values = append(doc.values, v)
			consume()
		default:
			if capturePublic && len(stack) > 0 {
				parent := stack[len(stack)-1]
				if parent.object {
					doc.markPublicUnknown(parent.group, parent.name)
				}
			}
			consume()
		}
	}
	doc.prepare()
	return doc
}

func (doc *literalDocument) prepare() {
	var prepared strings.Builder
	groups := map[int]*strings.Builder{}
	if doc.roles == nil {
		doc.roles = map[int]literalRole{}
	}
	siblings := map[int]map[string]bool{}
	for _, v := range doc.values {
		if !v.raw && uiSiblingText(v.name, v.value) {
			if siblings[v.group] == nil {
				siblings[v.group] = map[string]bool{}
			}
			siblings[v.group][strings.ToLower(v.name)] = true
		}
	}
	doc.scalars = map[int]detect.PasswordScalar{}
	doc.bindings = map[int]map[string]string{}
	for i := range doc.values {
		v := &doc.values[i]
		if v.name != "" && validLiteralBinding(v.name) {
			if doc.bindings[v.group] == nil {
				doc.bindings[v.group] = map[string]string{}
			}
			doc.bindings[v.group][v.name] = v.value
		}
		v.uiPassword = !v.raw && (doc.roles[v.group].ui || len(siblings[v.group]) >= 2) && uiPasswordText(v.value)
		binding := doc.binding(v)
		name := literalBinding(binding)
		if !v.raw {
			prepared.WriteString("\"" + name + "\": \"")
		}
		v.preparedStart = prepared.Len()
		prepared.WriteString(v.value)
		v.preparedEnd = prepared.Len()
		if v.raw {
			doc.scalars[v.preparedStart] = detect.PasswordScalar{Value: v.value, End: v.preparedEnd, Raw: true}
			prepared.WriteByte('\n')
		} else {
			prepared.WriteString("\"\n")
			passwordName := binding
			if v.noPassword || v.uiPassword || !validLiteralBinding(binding) {
				passwordName = ""
			}
			doc.scalars[v.preparedStart] = detect.PasswordScalar{Name: passwordName, Value: v.value, End: v.preparedEnd}
		}
		if groups[v.group] == nil {
			groups[v.group] = &strings.Builder{}
		}
		contextName := v.name
		if !validLiteralBinding(contextName) {
			contextName = ""
		}
		groups[v.group].WriteString(contextName + "=" + v.value + "\n")
	}
	doc.text = prepared.String()
	doc.contexts = map[int]string{}
	for group, b := range groups {
		doc.contexts[group] = b.String()
	}
}

func literalBinding(name string) string {
	if !validLiteralBinding(name) {
		return ""
	}
	// Synthetic wrappers need only a bounded cue-bearing suffix; parser nomination and ML keep the
	// actual full binding. Do not expand a long alias key into unbounded generated source/context.
	start, count := len(name), 0
	for start > 0 && count < 128 {
		_, size := utf8.DecodeLastRuneInString(name[:start])
		if len(name)-(start-size) > 256 {
			break
		}
		start -= size
		count++
	}
	return name[start:]
}

func validLiteralBinding(name string) bool {
	if len(name) > 4096 {
		return false
	}
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("_.-", r) {
			return false
		}
	}
	return true
}

func (doc *literalDocument) recordFor(value string, it model.Item, start int, typ string) mlscore.Record {
	r := recordFor(value, it, start)
	if v := doc.locate(start, start); v != nil && !v.raw && validLiteralBinding(v.name) {
		r.Context.Name = doc.binding(v)
		if typ == "generic_password" && start == v.preparedStart && value == v.value && !v.noPassword && !v.uiPassword && doc.scalars[start].Name != "" {
			r.Context.ParserLiteralSensitive = literalSensitive(r.Value) || !mlfeatures.HasSecretNameKeyword(r.Context.Name)
			r.Context.UINamespace = doc.roles[v.group].ui
		}
	}
	return r
}

// These values require the parser's literal semantics: lexical readers can
// confuse their data with escaping, whitespace, interpolation or markup.
func literalSensitive(value string) bool {
	for _, r := range value {
		if r >= utf8.RuneSelf || unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune("\\\"'<>{}$", r) {
			return true
		}
	}
	return false
}

// JSON permits isolated surrogate escapes; Go replaces them with U+FFFD. That lossy operation
// cannot establish a credential's identity or a value safe to submit to verification.
func validJSONSurrogates(raw string) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if raw[i] != 'u' {
			continue
		}
		u, _ := strconv.ParseUint(raw[i+1:i+5], 16, 16)
		i += 4
		if u >= 0xDC00 && u <= 0xDFFF {
			return false
		}
		if u >= 0xD800 && u <= 0xDBFF {
			if i+6 >= len(raw) || raw[i+1:i+3] != "\\u" {
				return false
			}
			low, _ := strconv.ParseUint(raw[i+3:i+7], 16, 16)
			if low < 0xDC00 || low > 0xDFFF {
				return false
			}
			i += 6
		}
	}
	return true
}

func (doc *literalDocument) locate(start, end int) *sourceLiteral {
	i := sort.Search(len(doc.values), func(i int) bool { return doc.values[i].preparedEnd >= end })
	if i == len(doc.values) || start < doc.values[i].preparedStart || end > doc.values[i].preparedEnd {
		return nil
	}
	return &doc.values[i]
}

// Map each decoded byte to its original encoding once per reported scalar. Inner occurrences
// remain distinct even when the same credential appears twice inside one escaped JSON string.
func (doc *literalDocument) sourceSpan(v *sourceLiteral, start, end int) (int, int) {
	if v.whole {
		return v.start, v.end
	}
	if v.raw {
		return v.start + start - v.preparedStart, v.start + end - v.preparedStart
	}
	if v.sourceStarts == nil {
		raw := doc.original[v.start:v.end]
		for i := 0; i < len(raw); {
			left := i
			if raw[i] != '\\' {
				v.sourceStarts = append(v.sourceStarts, v.start+i)
				v.sourceEnds = append(v.sourceEnds, v.start+i+1)
				i++
				continue
			}
			i += 2
			width := 1
			if raw[left+1] == 'u' {
				u, _ := strconv.ParseUint(raw[i:i+4], 16, 16)
				i += 4
				if u >= 0xD800 && u <= 0xDBFF {
					low, _ := strconv.ParseUint(raw[i+2:i+6], 16, 16)
					u = 0x10000 + (u-0xD800)*1024 + low - 0xDC00
					i += 6
				}
				width = utf8.RuneLen(rune(u))
			}
			for j := 0; j < width; j++ {
				v.sourceStarts = append(v.sourceStarts, v.start+left)
				v.sourceEnds = append(v.sourceEnds, v.start+i)
			}
		}
	}
	left, right := start-v.preparedStart, end-v.preparedStart
	if left < 0 || right > len(v.sourceStarts) || right <= left {
		return v.start, v.end
	}
	return v.sourceStarts[left], v.sourceEnds[right-1]
}
