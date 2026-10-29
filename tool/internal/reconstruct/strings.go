// Package reconstruct evaluates a bounded, side-effect-free subset of string expressions.
// It never executes JavaScript or follows unknown bindings.
package reconstruct

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const maxInput = 1 << 20
const maxValue = 64 << 10
const maxResults = 512

type Span struct{ Start, End int }
type Value struct {
	Text       string
	Spans      []Span
	Transform  string
	Expression Span
}
type token struct {
	text, literal string
	start, end    int
	kind          byte
	escaped       bool
	parts         []templatePart
}
type templatePart struct{ text, binding string }
type parser struct {
	tokens    []token
	i, depth  int
	constants map[string]Value
	shadowed  map[string]bool
	decoders  bool
	limited   bool
}

// Extract returns only expressions fully proven by literals and immutable local constants.
// limited means the input/result budget prevented a complete reconstruction pass.
func Extract(text string) (values []Value, limited bool) {
	if len(text) > maxInput {
		return nil, true
	}
	ts, ok := lex(text)
	if !ok {
		return nil, true
	}
	shadowed, limited := arrowParameters(ts)
	if limited {
		return nil, true
	}
	p := parser{tokens: ts, constants: map[string]Value{}, shadowed: shadowed, decoders: true}
	for i, t := range ts {
		if (t.text == "atob" || t.text == "decodeURIComponent") && (i+1 >= len(ts) || ts[i+1].text != "(" || i > 0 && (ts[i-1].text == "." || ts[i-1].text == "const" || ts[i-1].text == "let" || ts[i-1].text == "var" || ts[i-1].text == "function")) {
			p.decoders = false
		}
	}
	seen := map[string]bool{}
	for p.i < len(ts) {
		start := p.i
		if ts[start].text == "{" || ts[start].text == "}" {
			p.constants = map[string]Value{}
			p.i++
			continue
		}
		if ts[start].text == "const" && start+2 < len(ts) && ts[start+1].kind == 'i' && ts[start+2].text == "=" {
			name := ts[start+1].text
			p.i += 3
			expressionStart := p.i
			v, valid := p.expr()
			if valid && p.boundary() {
				v.Expression = Span{ts[expressionStart].start, ts[p.i-1].end}
				p.constants[name] = v
				if v.Transform != "literal" {
					values = add(values, v, seen)
				}
				if len(values) >= maxResults {
					return values, true
				}
				continue
			}
			delete(p.constants, name)
			p.i = start + 1
			continue
		}
		if ts[start].kind == 'i' && start+1 < len(ts) && (ts[start+1].text == "=" || ts[start+1].text == "+=" || ts[start+1].text == "++") {
			delete(p.constants, ts[start].text)
		}
		if !expressionStart(ts, start) {
			p.i++
			continue
		}
		v, valid := p.expr()
		if valid && v.Transform != "literal" && p.boundary() {
			v.Expression = Span{ts[start].start, ts[p.i-1].end}
			values = add(values, v, seen)
		} else {
			p.i = start + 1
		}
		if len(values) >= maxResults {
			return values, true
		}
	}
	return values, p.limited
}

func add(out []Value, v Value, seen map[string]bool) []Value {
	if len(v.Text) < 8 || len(v.Spans) == 0 {
		return out
	}
	key := strconv.Itoa(v.Expression.Start) + ":" + v.Text
	if !seen[key] {
		seen[key] = true
		out = append(out, v)
	}
	return out
}
func (p *parser) boundary() bool {
	if p.i == len(p.tokens) {
		return true
	}
	switch p.tokens[p.i].text {
	case ";", ",", ")", "]", "}":
		return true
	}
	return false
}
func (p *parser) take(s string) bool {
	if p.i < len(p.tokens) && p.tokens[p.i].text == s {
		p.i++
		return true
	}
	return false
}
func (p *parser) expr() (Value, bool) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 8 {
		p.limited = true
		return Value{}, false
	}
	v, ok := p.atom()
	if !ok {
		return Value{}, false
	}
	for p.take("+") {
		r, ok := p.atom()
		if !ok {
			return Value{}, false
		}
		if len(v.Text)+len(r.Text) > maxValue {
			p.limited = true
			return Value{}, false
		}
		v.Text += r.Text
		v.Spans = append(v.Spans, r.Spans...)
		v.Transform = chain(v.Transform, r.Transform, "constant-concat")
		if len(v.Spans) > 128 || v.Transform == "transform-budget" {
			p.limited = true
			return Value{}, false
		}
	}
	return v, true
}
func (p *parser) atom() (Value, bool) {
	if p.i >= len(p.tokens) {
		return Value{}, false
	}
	t := p.tokens[p.i]
	p.i++
	if t.kind == 's' {
		transform := "literal"
		if t.escaped {
			transform = "literal-escape"
		}
		return Value{Text: t.literal, Spans: []Span{{t.start, t.end}}, Transform: transform}, true
	}
	if t.kind == 't' {
		return p.template(t)
	}
	if t.text == "(" {
		v, ok := p.expr()
		return v, ok && p.take(")")
	}
	if t.text == "[" {
		var parts []Value
		for {
			v, ok := p.expr()
			if !ok {
				return Value{}, false
			}
			parts = append(parts, v)
			if len(parts) > 128 {
				p.limited = true
				return Value{}, false
			}
			if p.take("]") {
				break
			}
			if !p.take(",") {
				return Value{}, false
			}
		}
		if !p.take(".") || !p.take("join") || !p.take("(") {
			return Value{}, false
		}
		sep, ok := p.expr()
		if !ok || !p.take(")") {
			return Value{}, false
		}
		v := Value{}
		for i, r := range parts {
			if i > 0 {
				v.Text += sep.Text
			}
			v.Text += r.Text
			v.Spans = append(v.Spans, r.Spans...)
			v.Transform = chain(v.Transform, r.Transform)
			if len(v.Spans) > 128 || v.Transform == "transform-budget" {
				p.limited = true
				return Value{}, false
			}
			if len(v.Text) > maxValue {
				p.limited = true
				return Value{}, false
			}
		}
		v.Spans = append(v.Spans, sep.Spans...)
		v.Transform = chain(v.Transform, sep.Transform, "constant-array-join")
		if len(v.Spans) > 128 || v.Transform == "transform-budget" {
			p.limited = true
			return Value{}, false
		}
		return v, true
	}
	if p.decoders && (t.text == "atob" || t.text == "decodeURIComponent") && p.take("(") {
		v, ok := p.expr()
		if !ok || !p.take(")") {
			return Value{}, false
		}
		var err error
		var decoded string
		if t.text == "atob" {
			decoded, err = decodeBase64(v.Text)
		} else {
			decoded, err = url.PathUnescape(v.Text)
		}
		if err != nil || len(decoded) > maxValue || !utf8.ValidString(decoded) {
			return Value{}, false
		}
		v.Text = decoded
		v.Transform = chain(v.Transform, t.text)
		if v.Transform == "transform-budget" {
			p.limited = true
			return Value{}, false
		}
		return v, true
	}
	if t.kind == 'i' {
		if p.shadowed[t.text] {
			return Value{}, false
		}
		v, ok := p.constants[t.text]
		if ok {
			v.Spans = append(append([]Span(nil), v.Spans...), Span{t.start, t.end})
			v.Transform = chain(v.Transform, "constant-binding")
			if len(v.Spans) > 128 || v.Transform == "transform-budget" {
				p.limited = true
				return Value{}, false
			}
		}
		return v, ok
	}
	return Value{}, false
}
func (p *parser) template(t token) (Value, bool) {
	v := Value{Spans: []Span{{t.start, t.end}}, Transform: "constant-template"}
	for _, part := range t.parts {
		v.Text += part.text
		if part.binding != "" {
			bound, ok := p.constants[part.binding]
			if !ok || p.shadowed[part.binding] {
				return Value{}, false
			}
			v.Text += bound.Text
			v.Spans = append(v.Spans, bound.Spans...)
			v.Transform = chain(v.Transform, bound.Transform)
			if len(v.Spans) > 128 || v.Transform == "transform-budget" {
				p.limited = true
				return Value{}, false
			}
		}
		if len(v.Text) > maxValue {
			p.limited = true
			return Value{}, false
		}
	}
	if len(v.Text) > maxValue {
		p.limited = true
		return Value{}, false
	}
	return v, true
}

// Preserve the bounded sequence of proven operations, without embedding credential text.
func chain(steps ...string) string {
	var out []string
	for _, step := range steps {
		for _, name := range strings.Split(step, " -> ") {
			if name != "" {
				out = append(out, name)
				if len(out) > 128 || name == "transform-budget" {
					return "transform-budget"
				}
			}
		}
	}
	return strings.Join(out, " -> ")
}
func lex(s string) ([]token, bool) {
	var out []token
	regexBudget := 2 * maxInput
	for i := 0; i < len(s); {
		if len(out) >= 100000 {
			return nil, false
		}
		c := s[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			i++
			continue
		}
		if strings.HasPrefix(s[i:], "//") {
			if n := strings.IndexByte(s[i:], '\n'); n >= 0 {
				i += n + 1
				continue
			}
			break
		}
		if strings.HasPrefix(s[i:], "/*") {
			n := strings.Index(s[i+2:], "*/")
			if n < 0 {
				return out, false
			}
			i += n + 4
			continue
		}
		start := i
		if c == '/' {
			end, ok := regexEnd(s, i, &regexBudget)
			if regexBudget < 0 {
				return nil, false
			}
			if !ok && regexStart(out) {
				return out, false
			}
			if ok {
				// Ambiguous slash-delimited regions are opaque too. A bounded lexer
				// cannot establish division-vs-regexp grammar after a control statement.
				out = append(out, token{text: s[i:end], start: i, end: end, kind: 'r'})
				i = end
				continue
			}
		}
		if c == '\'' || c == '"' || c == '`' {
			i++
			var b strings.Builder
			closed := false
			escaped := false
			var parts []templatePart
			for i < len(s) {
				if s[i] == c {
					i++
					closed = true
					break
				}
				// Recognize interpolation in source bytes before cooking literal escapes.
				if c == '`' && strings.HasPrefix(s[i:], "${") {
					end := strings.IndexByte(s[i+2:], '}')
					if end < 0 {
						return out, false
					}
					binding := strings.TrimSpace(s[i+2 : i+2+end])
					if binding == "" {
						binding = "<unsupported interpolation>"
					}
					parts = append(parts, templatePart{b.String(), binding})
					b.Reset()
					i += end + 3
					continue
				}
				if s[i] == '\\' {
					escaped = true
					i++
					if i >= len(s) {
						return out, false
					}
					switch s[i] {
					case '\n':
						i++
					case '\r':
						i++
						if i < len(s) && s[i] == '\n' {
							i++
						}
					case 'b':
						b.WriteByte('\b')
						i++
					case 'f':
						b.WriteByte('\f')
						i++
					case 'v':
						b.WriteByte('\v')
						i++
					case '0':
						i++
						if i < len(s) && s[i] >= '0' && s[i] <= '9' {
							return out, false
						}
						b.WriteByte(0)
					case 'n':
						b.WriteByte('\n')
						i++
					case 'r':
						b.WriteByte('\r')
						i++
					case 't':
						b.WriteByte('\t')
						i++
					case '\\', '\'', '"', '`', '/':
						b.WriteByte(s[i])
						i++
					case '$':
						if c != '`' {
							return out, false
						}
						b.WriteByte('$')
						i++
					case 'x', 'u':
						n := 2
						unicodeEscape := s[i] == 'u'
						if s[i] == 'u' {
							n = 4
						}
						i++
						if unicodeEscape && i < len(s) && s[i] == '{' {
							end := strings.IndexByte(s[i+1:], '}')
							if end < 1 || end > 6 {
								return out, false
							}
							cp, err := strconv.ParseUint(s[i+1:i+1+end], 16, 32)
							if err != nil || cp > utf8.MaxRune || cp >= 0xD800 && cp <= 0xDFFF {
								return out, false
							}
							b.WriteRune(rune(cp))
							i += end + 2
							break
						}
						if i+n > len(s) {
							return out, false
						}
						r, err := strconv.ParseUint(s[i:i+n], 16, 16)
						if err != nil {
							return out, false
						}
						i += n
						cp := rune(r)
						if cp >= 0xD800 && cp <= 0xDBFF && i+6 <= len(s) && s[i:i+2] == `\u` {
							low, err := strconv.ParseUint(s[i+2:i+6], 16, 16)
							if err != nil || low < 0xDC00 || low > 0xDFFF {
								return out, false
							}
							cp = utf16.DecodeRune(cp, rune(low))
							i += 6
						} else if cp >= 0xD800 && cp <= 0xDFFF {
							return out, false
						}
						b.WriteRune(cp)
					default:
						return out, false
					}
				} else {
					b.WriteByte(s[i])
					i++
				}
				if b.Len() > maxValue {
					return out, false
				}
			}
			if !closed {
				return out, false
			}
			kind := byte('s')
			if c == '`' {
				kind = 't'
				parts = append(parts, templatePart{text: b.String()})
			}
			out = append(out, token{text: s[start:i], literal: b.String(), start: start, end: i, kind: kind, escaped: escaped, parts: parts})
			continue
		}
		if ident(c) {
			i++
			for i < len(s) && (ident(s[i]) || s[i] >= '0' && s[i] <= '9') {
				i++
			}
			out = append(out, token{text: s[start:i], start: start, end: i, kind: 'i'})
			continue
		}
		i++
		if s[start:i] == "=" && i < len(s) && s[i] == '>' {
			i++
		}
		if i < len(s) && (s[start:i] == "+" && (s[i] == '=' || s[i] == '+')) {
			i++
		}
		out = append(out, token{text: s[start:i], start: start, end: i})
		if len(out) > 100000 {
			return nil, false
		}
	}
	return out, true
}
func ident(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '$' }

// JavaScript atob uses forgiving base64 and returns Latin-1 code points,
// not the UTF-8 interpretation of the decoded bytes.
func decodeBase64(value string) (string, error) {
	value = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == '\f' {
			return -1
		}
		return r
	}, value)
	if len(value)%4 == 0 {
		for range 2 {
			value = strings.TrimSuffix(value, "=")
		}
	}
	if len(value)%4 == 1 {
		return "", errors.New("invalid base64")
	}
	raw, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	for _, b := range raw {
		out.WriteRune(rune(b))
	}
	return out.String(), nil
}

// Unknown surrounding operators and template tags cannot establish a string value.
func expressionStart(ts []token, i int) bool {
	if i == 0 {
		return true
	}
	switch ts[i-1].text {
	case "=", ";", ",", "(", "[", ":", "{", "}", "return", "throw", "yield", "=>":
		return true
	}
	return false
}

// Parameter bindings are conservatively excluded throughout this bounded pass.
// Resolving their lexical scopes would require a full JavaScript AST.
func arrowParameters(ts []token) (map[string]bool, bool) {
	shadowed := map[string]bool{}
	budget := 100000
	for i, t := range ts {
		if t.text != "=>" || i == 0 {
			continue
		}
		if ts[i-1].kind == 'i' {
			shadowed[ts[i-1].text] = true
		} else if ts[i-1].text == ")" {
			depth := 1
			for j := i - 2; j >= 0; j-- {
				budget--
				if budget < 0 {
					return nil, true
				}
				if ts[j].text == ")" {
					depth++
				}
				if ts[j].text == "(" {
					depth--
					if depth == 0 {
						break
					}
				}
				if ts[j].kind == 'i' {
					shadowed[ts[j].text] = true
				}
			}
		}
	}
	return shadowed, false
}

func regexStart(ts []token) bool {
	if len(ts) == 0 {
		return true
	}
	switch ts[len(ts)-1].text {
	case "=", "(", "[", ",", ":", ";", "{", "!", "?", "return", "throw", "=>":
		return true
	}
	return false
}

// A regular expression is opaque data, never a string expression to evaluate.
func regexEnd(s string, start int, budget *int) (int, bool) {
	class := false
	for i := start + 1; i < len(s); i++ {
		*budget--
		if *budget < 0 {
			return 0, false
		}
		switch s[i] {
		case '\\':
			i++
		case '\n', '\r':
			return 0, false
		case '[':
			class = true
		case ']':
			class = false
		case '/':
			if !class {
				i++
				for i < len(s) && ident(s[i]) {
					i++
				}
				return i, true
			}
		}
	}
	return 0, false
}
