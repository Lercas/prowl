package scan

import (
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

type yamlSource struct {
	text    string
	starts  []int
	columns map[int][]int
}

func newYAMLSource(text string) *yamlSource {
	s := &yamlSource{text: text, starts: []int{0}, columns: map[int][]int{}}
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		i += size
		if r == '\r' && i < len(text) && text[i] == '\n' {
			i++
		}
		if yamlLineBreak(r) {
			s.starts = append(s.starts, i)
		}
	}
	return s
}

func yamlLineBreak(r rune) bool {
	return r == '\r' || r == '\n' || r == '\u0085' || r == '\u2028' || r == '\u2029'
}

func yamlSeparator(r rune) bool { return r == ' ' || r == '\t' || yamlLineBreak(r) }

func yamlSpaceBefore(text string, pos int) bool {
	if pos == 0 {
		return true
	}
	r, _ := utf8.DecodeLastRuneInString(text[:pos])
	return yamlSeparator(r)
}

func yamlLineEnd(text string, start, bound int) (int, int) {
	for i := start; i < bound; {
		r, size := utf8.DecodeRuneInString(text[i:bound])
		if yamlLineBreak(r) {
			next := i + size
			if r == '\r' && next < bound && text[next] == '\n' {
				next++
			}
			return i, next
		}
		i += size
	}
	return bound, bound
}

func (s *yamlSource) offset(n *yaml.Node) (int, bool) {
	if n.Line < 1 || n.Line > len(s.starts) || n.Column < 1 {
		return 0, false
	}
	columns, ok := s.columns[n.Line]
	if !ok {
		end := len(s.text)
		if n.Line < len(s.starts) {
			end = s.starts[n.Line]
		}
		start := s.starts[n.Line-1]
		if strings.HasPrefix(s.text[start:], "\ufeff") {
			start += len("\ufeff") // The pinned parser excludes a leading BOM from columns.
		}
		for i := start; ; {
			columns = append(columns, i)
			if i >= end {
				break
			}
			_, size := utf8.DecodeRuneInString(s.text[i:])
			i += size
		}
		s.columns[n.Line] = columns
	}
	if n.Column > len(columns) {
		return 0, false
	}
	return columns[n.Column-1], true
}

type yamlPhysical struct {
	node       *yaml.Node
	start, end int // Includes properties and quoting for comment exclusion.
	body       int
	group      int
	key        *yaml.Node
	literal    sourceLiteral
	flow       bool
}

func (s *yamlSource) scalar(p *yamlPhysical, bound int) bool {
	n, text := p.node, s.text
	i := p.start
	// Node coordinates point to the first property, not necessarily to the literal delimiter.
	for i < bound && (text[i] == '&' || text[i] == '!') {
		if text[i] == '!' && i+1 < bound && text[i+1] == '<' {
			i += 2
			for i < bound && text[i] != '>' {
				i++
			}
			if i < bound {
				i++
			}
		} else {
			for i < bound {
				r, size := utf8.DecodeRuneInString(text[i:bound])
				if yamlSeparator(r) || strings.ContainsRune(",[]{}", r) {
					break
				}
				i += size
			}
		}
		for i < bound {
			r, size := utf8.DecodeRuneInString(text[i:])
			if !yamlSeparator(r) {
				break
			}
			i += size
		}
	}
	start, end, body := i, i, i
	quoted := n.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle) != 0
	block := n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0
	switch {
	case quoted:
		if i >= bound || text[i] != '\'' && text[i] != '"' {
			return false
		}
		quote := text[i]
		start, body = i+1, i+1
		closed := false
		for i++; i < bound && i-p.start <= 65536; i++ {
			if quote == '"' && text[i] == '\\' {
				i++
				continue
			}
			if text[i] == quote {
				if quote == '\'' && i+1 < bound && text[i+1] == quote {
					i++
					continue
				}
				end, p.end, closed = i, i+1, true
				break
			}
		}
		if !closed {
			return false
		}
	case block:
		if i >= bound || text[i] != '|' && text[i] != '>' {
			return false
		}
		for i < bound {
			r, size := utf8.DecodeRuneInString(text[i:])
			i += size
			if yamlLineBreak(r) {
				if r == '\r' && i < bound && text[i] == '\n' {
					i++
				}
				break
			}
		}
		body = i
		header := s.starts[n.Line-1]
		headerIndent := 0
		for header+headerIndent < len(text) && text[header+headerIndent] == ' ' {
			headerIndent++
		}
		indent := -1
		for line := body; line < bound; {
			right, next := yamlLineEnd(text, line, bound)
			content := line
			for content < right && text[content] == ' ' {
				content++
			}
			if content < right {
				marker := content == line && (text[content:right] == "---" || text[content:right] == "..." || strings.HasPrefix(text[content:right], "--- ") || strings.HasPrefix(text[content:right], "... "))
				if marker || indent < 0 && n.Value == "" && content-line <= headerIndent || indent >= 0 && content-line < indent {
					bound = line
					break
				}
				if indent < 0 {
					indent = content - line
				}
			}
			line = next
		}
		end, p.end = bound, bound
	case len(n.Value) == 0:
		p.end = start
	case strings.HasPrefix(text[i:bound], n.Value) && !strings.ContainsAny(n.Value, "\r\n"):
		end, p.end = i+len(n.Value), i+len(n.Value)
	default:
		for i < bound {
			c := text[i]
			if p.flow && strings.ContainsRune(",[]{}", rune(c)) || c == ':' && i+1 < bound && strings.ContainsRune(" \t\r\n,[]{}", rune(text[i+1])) {
				break
			}
			if (i == 0 || text[i-1] == '\n' || text[i-1] == '\r') && (strings.HasPrefix(text[i:bound], "---") || strings.HasPrefix(text[i:bound], "...")) {
				break
			}
			i++
		}
		end = i
		for end > start && strings.ContainsRune(" \t\r\n", rune(text[end-1])) {
			end--
		}
		p.end = end
	}
	if end < start || end-start > 65536 || len(n.Value) > 4096 {
		return false
	}
	v := sourceLiteral{value: n.Value, start: start, end: end}
	if !s.scalarMap(&v, body, end, quoted, !quoted && !block, n.Style&yaml.SingleQuotedStyle != 0) {
		return false
	}
	p.literal = v
	p.body = body
	return true
}

type yamlSourceUnit struct {
	r          rune
	start, end int
}

// YAML's parser owns folding/chomping semantics. Preserve exact non-whitespace units and map each
// folded whitespace run to its source run; never guess a value from the source representation.
func (s *yamlSource) scalarMap(v *sourceLiteral, start, end int, quoted, plain, single bool) bool {
	text := s.text
	var units []yamlSourceUnit
	for i := start; i < end; {
		left := i
		r, size := utf8.DecodeRuneInString(text[i:])
		i += size
		if plain && r == '#' && (left == start || yamlSpaceBefore(text, left)) {
			i, _ = yamlLineEnd(text, i, end)
			continue
		}
		if quoted && single && r == '\'' && i < end && text[i] == '\'' {
			i++
		} else if quoted && !single && r == '\\' {
			if i >= end {
				return false
			}
			r, size = utf8.DecodeRuneInString(text[i:])
			i += size
			if yamlLineBreak(r) {
				if r == '\r' && i < end && text[i] == '\n' {
					i++
				}
				for i < end && (text[i] == ' ' || text[i] == '\t') {
					i++
				}
				continue
			}
			if r == 'x' || r == 'u' || r == 'U' {
				digits := 2
				switch r {
				case 'u':
					digits = 4
				case 'U':
					digits = 8
				}
				if i+digits > end {
					return false
				}
				value, err := strconv.ParseUint(text[i:i+digits], 16, 32)
				if err != nil || value > utf8.MaxRune || value >= 0xD800 && value <= 0xDFFF {
					return false
				}
				r = rune(value)
				i += digits
			} else {
				decoded, ok := map[rune]rune{'0': 0, 'a': '\a', 'b': '\b', 't': '\t', '\t': '\t', 'n': '\n', 'v': '\v', 'f': '\f', 'r': '\r', 'e': 27, ' ': ' ', '"': '"', '\'': '\'', '\\': '\\', '/': '/', 'N': '\u0085', '_': '\u00a0', 'L': '\u2028', 'P': '\u2029'}[r]
				if !ok {
					return false
				}
				r = decoded
			}
		}
		units = append(units, yamlSourceUnit{r, left, i})
	}
	j := 0
	for i := 0; i < len(v.value); {
		r, size := utf8.DecodeRuneInString(v.value[i:])
		if unicode.IsSpace(r) {
			left := j
			for j < len(units) && unicode.IsSpace(units[j].r) {
				j++
			}
			if j == left {
				return false
			}
			for i < len(v.value) {
				r, size = utf8.DecodeRuneInString(v.value[i:])
				if !unicode.IsSpace(r) {
					break
				}
				for range size {
					v.sourceStarts = append(v.sourceStarts, units[left].start)
					v.sourceEnds = append(v.sourceEnds, units[j-1].end)
				}
				i += size
			}
			continue
		}
		for j < len(units) && unicode.IsSpace(units[j].r) {
			j++
		}
		if j == len(units) || units[j].r != r {
			return false
		}
		for range size {
			v.sourceStarts = append(v.sourceStarts, units[j].start)
			v.sourceEnds = append(v.sourceEnds, units[j].end)
		}
		i += size
		j++
	}
	for j < len(units) && unicode.IsSpace(units[j].r) {
		j++
	}
	return j == len(units)
}

func (s *yamlSource) physical(nodes []*yamlPhysical) bool {
	sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].start < nodes[j].start })
	for i, p := range nodes {
		if p.node.Kind == yaml.AliasNode {
			p.end = p.start + 1 + len(p.node.Value)
			if p.end > len(s.text) || s.text[p.start:p.end] != "*"+p.node.Value {
				return false
			}
			continue
		}
		bound := len(s.text)
		if i+1 < len(nodes) {
			bound = nodes[i+1].start
			if p.node.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 && nodes[i+1].node.Line > p.node.Line {
				bound = s.starts[nodes[i+1].node.Line-1]
			}
		}
		if !s.scalar(p, bound) {
			return false
		}
	}
	return true
}
