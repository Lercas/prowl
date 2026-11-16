package scan

import (
	"context"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/model"
)

func componentEnv(it model.Item) bool {
	if !pathIsFilesystem(it.Source) {
		return false
	}
	base := strings.ToLower(filepath.Base(it.Path))
	return base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env")
}

// dotenv subset: literal single quotes, non-interpolated double quotes, and
// bare values without shell syntax. It never expands variables or executes code.
// Unknown values still shadow the same role in other files; comments remain raw
// detection input, with no authority to supply companion fields.
func envComponents(ctx context.Context, it model.Item) (*literalDocument, map[string]*string) {
	if len(it.Text) > 1<<20 || !utf8.ValidString(it.Text) {
		return nil, nil
	}
	doc := &literalDocument{original: it.Text, lines: newLineIndex(it.Text), unsafeGroups: map[int]bool{}, transform: "env-literal"}
	fields := make(map[string]*string)
	for offset, number := 0, 0; offset < len(it.Text); number++ {
		if ctx.Err() != nil || number >= 10000 {
			return nil, nil
		}
		end := strings.IndexByte(it.Text[offset:], '\n')
		if end < 0 {
			end = len(it.Text)
		} else {
			end += offset
		}
		line := strings.TrimSuffix(it.Text[offset:end], "\r")
		left := strings.TrimLeft(line, " \t")
		start := offset + len(line) - len(left)
		if left == "" || strings.HasPrefix(left, "#") {
			doc.values = append(doc.values, sourceLiteral{value: line, start: offset, end: offset + len(line), raw: true, group: -number - 1})
			offset = end + 1
			continue
		}
		if strings.HasPrefix(left, "export ") {
			left = strings.TrimLeft(left[7:], " \t")
			start = offset + len(line) - len(left)
		}
		eq := strings.IndexByte(left, '=')
		if eq <= 0 {
			return nil, nil
		}
		name := strings.TrimSpace(left[:eq])
		for i, c := range name {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || i > 0 && c >= '0' && c <= '9') {
				return nil, nil
			}
		}
		if _, duplicate := fields[name]; duplicate {
			doc.unsafeGroups[1] = true
		}
		fields[name] = nil
		raw := strings.TrimSpace(left[eq+1:])
		valueStart := start + eq + 1 + len(left[eq+1:]) - len(strings.TrimLeft(left[eq+1:], " \t"))
		known, value := true, raw
		if len(raw) > 0 && (raw[0] == '\'' || raw[0] == '"') {
			quote := raw[0]
			close := strings.IndexByte(raw[1:], quote)
			if close < 0 {
				known = false
			} else {
				close++
				tail := strings.TrimSpace(raw[close+1:])
				if tail != "" && !strings.HasPrefix(tail, "#") {
					known = false
				}
				value = raw[1:close]
				valueStart++
				if quote == '"' && strings.ContainsAny(value, "\\$`") {
					known = false
				}
			}
		} else {
			if comment := strings.Index(raw, " #"); comment >= 0 {
				value = strings.TrimRight(raw[:comment], " \t")
			}
			if strings.ContainsAny(value, "\\$` \t;|&<>()\"'") {
				known = false
			}
		}
		if value == "" {
			known = false
		}
		if known {
			v := sourceLiteral{name: name, value: value, start: valueStart, end: valueStart + len(value), group: 1}
			for i := range len(value) {
				v.sourceStarts = append(v.sourceStarts, valueStart+i)
				v.sourceEnds = append(v.sourceEnds, valueStart+i+1)
			}
			doc.values = append(doc.values, v)
			copyValue := value
			fields[name] = &copyValue
		} else {
			doc.values = append(doc.values, sourceLiteral{value: line, start: offset, end: offset + len(line), raw: true, group: -number - 1})
		}
		offset = end + 1
	}
	doc.prepare()
	return doc, fields
}
