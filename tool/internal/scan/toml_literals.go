package scan

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"github.com/Lercas/prowl/tool/internal/model"
)

type tomlLiteralToken struct {
	kind       byte
	start, end int
	value      string
	literal    sourceLiteral
}

// tomlLiterals delegates value semantics to the pinned TOML parser, while a bounded token inventory
// preserves byte positions, comments, arrays of tables and the distinction between keys and values.
func tomlLiterals(ctx context.Context, it model.Item) *literalDocument {
	if !pathIsFilesystem(it.Source) || strings.ToLower(filepath.Ext(model.SafeLocator(it.Path))) != ".toml" {
		return nil
	}
	fail := func(code string) *literalDocument {
		model.Note(ctx, code, it.Path, true)
		return nil
	}
	if len(it.Text) > 1<<20 {
		return fail("toml_literal_limit")
	}
	if !utf8.ValidString(it.Text) {
		return fail("toml_literal_parse")
	}
	tokens, code := tomlLiteralTokens(ctx, it.Text)
	if code != "" {
		return fail(code)
	}
	if !tomlQualifiedKeyBudget(tokens) {
		return fail("toml_literal_limit")
	}
	if ctx.Err() != nil {
		return nil
	}
	var parsed any
	if _, err := toml.Decode(it.Text, &parsed); err != nil {
		return fail("toml_literal_parse") // Never log parser errors containing source credentials.
	}
	doc := &literalDocument{original: it.Text, lines: newLineIndex(it.Text), transform: "toml-string", roles: map[int]literalRole{}}
	doc.lines.resetPragmas()
	for _, token := range tokens {
		if token.kind == '#' {
			doc.lines.markCommentPragmas(token.start, token.end)
		}
	}
	type frame struct {
		path, keys []string
		instances  []int
		array      bool
		keyMode    bool
		awaitValue bool
	}
	type arrayTable struct {
		path []string
		id   int
	}
	stack := []frame{{keyMode: true}}
	var active []arrayTable
	serial := 0
	groups := map[string]int{}
	groupFor := func(path []string, instances []int) int {
		encoded, _ := json.Marshal(struct {
			Path      []string
			Instances []int
		}{path, instances})
		key := string(encoded)
		if id, ok := groups[key]; ok {
			return id
		}
		id := len(groups) + 1
		groups[key] = id
		role := literalRole{}
		for _, segment := range path {
			role = role.child(segment)
		}
		doc.roles[id] = role
		return id
	}
	copyAppend := func(a, b []string) []string {
		return append(append([]string(nil), a...), b...)
	}
	limitReached := false
	add := func(token tomlLiteralToken, name string, path []string, instances []int) {
		if len(doc.values) >= 10000 {
			limitReached = true
			return
		}
		v := token.literal
		v.name, v.group = name, groupFor(path, instances)
		doc.values = append(doc.values, v)
	}
	for i := 0; i < len(tokens); i++ {
		if limitReached {
			return fail("toml_literal_limit")
		}
		if ctx.Err() != nil {
			return nil
		}
		t := tokens[i]
		f := &stack[len(stack)-1]
		if t.kind == '#' {
			add(t, "", f.path, f.instances)
			continue
		}
		if t.kind == '\n' {
			if len(stack) == 1 {
				f.keys, f.keyMode, f.awaitValue = nil, true, false
			}
			continue
		}
		if len(stack) == 1 && f.keyMode && len(f.keys) == 0 && t.kind == '[' {
			array := i+1 < len(tokens) && tokens[i+1].kind == '['
			if array {
				i++
			}
			var path []string
			var header []tomlLiteralToken
			for i++; i < len(tokens) && tokens[i].kind != ']'; i++ {
				if tokens[i].kind == 'q' || tokens[i].kind == 'w' {
					path = append(path, tokens[i].value)
					header = append(header, tokens[i])
				}
			}
			if array {
				i++ // The complete document parser already validated the second closing bracket.
				kept := active[:0]
				for _, old := range active {
					if !tomlPathPrefix(path, old.path) {
						kept = append(kept, old)
					}
				}
				serial++
				active = append(kept, arrayTable{path: path, id: serial})
			}
			var instances []int
			for _, a := range active {
				if tomlPathPrefix(a.path, path) {
					instances = append(instances, a.id)
				}
			}
			stack[0] = frame{path: path, instances: instances, keyMode: true}
			for _, key := range header {
				add(key, "", path, instances)
			}
			continue
		}
		switch t.kind {
		case 'q', 'w':
			if f.keyMode && !f.array {
				add(t, "", copyAppend(f.path, f.keys), f.instances)
				f.keys = append(f.keys, t.value)
			} else if t.kind == 'q' {
				name, path := "", f.path
				if f.awaitValue && len(f.keys) > 0 {
					name = f.keys[len(f.keys)-1]
					path = copyAppend(f.path, f.keys[:len(f.keys)-1])
				}
				add(t, name, path, f.instances)
				f.awaitValue = false
			} else {
				f.awaitValue = false
			}
		case '=':
			f.keyMode, f.awaitValue = false, true
		case '{', '[':
			path := f.path
			if f.awaitValue {
				path = copyAppend(path, f.keys)
			}
			instances := append([]int(nil), f.instances...)
			if t.kind == '[' || f.array {
				serial++
				instances = append(instances, serial)
			}
			f.awaitValue = false
			stack = append(stack, frame{path: path, instances: instances, array: t.kind == '[', keyMode: t.kind == '{'})
		case '}', ']':
			if len(stack) < 2 {
				return fail("toml_literal_parse")
			}
			stack = stack[:len(stack)-1]
		case ',':
			if !f.array {
				f.keys, f.keyMode, f.awaitValue = nil, true, false
			}
		}
	}
	if limitReached {
		return fail("toml_literal_limit")
	}
	doc.prepare()
	return doc
}

func tomlPathPrefix(prefix, path []string) bool {
	if len(prefix) > len(path) {
		return false
	}
	for i := range prefix {
		if prefix[i] != path[i] {
			return false
		}
	}
	return true
}

func tomlLiteralTokens(ctx context.Context, text string) ([]tomlLiteralToken, string) {
	var tokens []tomlLiteralToken
	depth, dots := 0, 0
	i := 0
	if strings.HasPrefix(text, "\ufeff") {
		i = len("\ufeff") // The authoritative parser accepts an initial UTF-8 BOM.
	}
	for i < len(text) {
		if ctx.Err() != nil {
			return nil, ""
		}
		if len(tokens) >= 100000 {
			return nil, "toml_literal_limit"
		}
		start, c := i, text[i]
		if c == ' ' || c == '\t' || c == '\r' {
			i++
			continue
		}
		if c == '#' {
			for i < len(text) && text[i] != '\n' {
				i++
			}
			tokens = append(tokens, tomlLiteralToken{kind: '#', start: start, end: i, literal: sourceLiteral{value: text[start:i], start: start, end: i, raw: true}})
			continue
		}
		if c == '"' || c == '\'' {
			width := 1
			if i+2 < len(text) && text[i+1] == c && text[i+2] == c {
				width = 3
			}
			i += width
			closed := false
			for i < len(text) && i-start <= 65536 {
				if c == '"' && text[i] == '\\' {
					i += min(2, len(text)-i)
					continue
				}
				if text[i] == c {
					end := i
					for end < len(text) && text[end] == c {
						end++
					}
					if width == 1 {
						i++
						closed = true
						break
					} else if end-i >= 3 {
						i, closed = end, true
						break
					}
				}
				i++
			}
			if !closed {
				if i-start > 65536 {
					return nil, "toml_literal_limit"
				}
				return nil, "toml_literal_parse"
			}
			var parsed struct{ V string }
			if _, err := toml.Decode("v="+text[start:i], &parsed); err != nil {
				return nil, "toml_literal_parse"
			}
			if len(parsed.V) > 4096 {
				return nil, "toml_literal_limit"
			}
			v := sourceLiteral{value: parsed.V, start: start + width, end: i - width}
			if !tomlStringSourceMap(text, &v, c == '"', width == 3) {
				return nil, "toml_literal_mapping"
			}
			tokens = append(tokens, tomlLiteralToken{kind: 'q', start: start, end: i, value: parsed.V, literal: v})
			continue
		}
		if strings.ContainsRune("[]=.,{}\n", rune(c)) {
			i++
			switch c {
			case '[', '{':
				depth++
			case ']', '}':
				depth--
			}
			switch c {
			case '.':
				dots++
			case '\n', '=', ',':
				dots = 0
			}
			if depth > 64 || dots > 128 {
				return nil, "toml_literal_limit"
			}
			tokens = append(tokens, tomlLiteralToken{kind: c, start: start, end: i})
			continue
		}
		for i < len(text) && !strings.ContainsRune(" \t\r\n[]=.,{}#\"'", rune(text[i])) {
			i++
		}
		if i-start > 4096 {
			return nil, "toml_literal_limit"
		}
		tokens = append(tokens, tomlLiteralToken{kind: 'w', start: start, end: i, value: text[start:i], literal: sourceLiteral{value: text[start:i], start: start, end: i, raw: true}})
	}
	return tokens, ""
}

func tomlStringSourceMap(text string, v *sourceLiteral, basic, multiline bool) bool {
	var decoded strings.Builder
	write := func(value string, start, end int) {
		decoded.WriteString(value)
		for range len(value) {
			v.sourceStarts = append(v.sourceStarts, start)
			v.sourceEnds = append(v.sourceEnds, end)
		}
	}
	i := v.start
	if multiline && i < v.end {
		if text[i] == '\r' && i+1 < v.end && text[i+1] == '\n' {
			i += 2
		} else if text[i] == '\n' {
			i++
		}
	}
	for i < v.end {
		start := i
		if !basic || text[i] != '\\' {
			write(text[i:i+1], i, i+1)
			i++
			continue
		}
		i++
		if i >= v.end {
			return false
		}
		c := text[i]
		i++
		if multiline && strings.ContainsRune(" \t\r\n", rune(c)) {
			for i < v.end && strings.ContainsRune(" \t\r\n", rune(text[i])) {
				i++
			}
			continue
		}
		if c == 'u' || c == 'U' || c == 'x' {
			digits := 4
			switch c {
			case 'U':
				digits = 8
			case 'x':
				digits = 2
			}
			if i+digits > v.end {
				return false
			}
			r, err := strconv.ParseUint(text[i:i+digits], 16, 32)
			if err != nil || r > utf8.MaxRune || r >= 0xD800 && r <= 0xDFFF {
				return false
			}
			i += digits
			write(string(rune(r)), start, i)
		} else {
			value := map[byte]string{'b': "\b", 't': "\t", 'n': "\n", 'f': "\f", 'r': "\r", 'e': "\x1b", '"': "\"", '\\': "\\"}[c]
			if value == "" {
				return false
			}
			write(value, start, i)
		}
	}
	return decoded.String() == v.value
}
