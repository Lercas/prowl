package scan

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/model"
)

var codeIdentifier = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)

// NonLiteralCodeValue rejects identifier expressions in programming languages. Unquoted values in
// .env/YAML/shell and credentials in comments remain eligible; those languages permit bare literals.
func NonLiteralCodeValue(path, text string, start, end int) bool {
	return NewCodeValueFilter(path, text).NonLiteral(start, end)
}

// DetectionOptions preserves bare scalar passwords only in formats that define such literals.
func DetectionOptions(path string) detect.ScanOptions {
	switch strings.ToLower(filepath.Ext(model.SafeLocator(path))) {
	case ".yaml", ".yml":
		return detect.ScanOptions{BarePasswordLiterals: true, YAML: true}
	case ".env", ".ini", ".conf", ".cfg", ".properties", ".sh", ".bash", ".zsh":
		return detect.ScanOptions{BarePasswordLiterals: true}
	}
	return detect.ScanOptions{}
}

// CodeValueFilter indexes strings and comments once per document. Comment markers inside strings
// cannot make later identifiers into credentials, and multiline comments retain literal evidence.
type CodeValueFilter struct {
	text    string
	code    bool
	regions [][2]int
}

func NewCodeValueFilter(path, text string) *CodeValueFilter {
	return newCodeValueFilter(path, text, 0)
}

func newCodeValueFilter(path, text string, nesting int) *CodeValueFilter {
	f := &CodeValueFilter{text: text}
	ext := strings.ToLower(filepath.Ext(model.SafeLocator(path)))
	switch ext {
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".go", ".java", ".cs", ".rs":
	default:
		return f
	}
	f.code = true
	if nesting >= 32 {
		return f // bounded lexical support, not an unbounded programming-language parser
	}
	for i := 0; i < len(text); {
		start := i
		c := text[i]
		switch {
		case ext == ".rs" && c == '\'' && rustLifetime(text, i):
			i++
			continue
		case c == '"' || c == '\'' || c == '`':
			width := 1
			if (ext == ".py" || ext == ".java" || ext == ".cs") && i+2 < len(text) && text[i+1] == c && text[i+2] == c {
				width = 3
			}
			rawHashes := -1
			if ext == ".rs" && c == '"' {
				j := i
				for j > 0 && text[j-1] == '#' {
					j--
				}
				if j > 0 && text[j-1] == 'r' {
					rawHashes = i - j
				}
			}
			verbatim := ext == ".cs" && i > 0 && text[i-1] == '@'
			rawSuffix := ""
			if rawHashes >= 0 {
				rawSuffix = strings.Repeat("#", rawHashes)
			}
			i += width
			for i < len(text) {
				if c == '`' && ext != ".go" && strings.HasPrefix(text[i:], "${") {
					f.regions = append(f.regions, [2]int{start, i})
					exprStart := i + 2
					exprEnd := templateExpressionEnd(text, exprStart)
					child := newCodeValueFilter(path, text[exprStart:exprEnd], nesting+1)
					for _, region := range child.regions {
						f.regions = append(f.regions, [2]int{exprStart + region[0], exprStart + region[1]})
					}
					i = exprEnd
					if i < len(text) {
						i++ // closing interpolation brace
					}
					start = i
					continue
				}
				if text[i] == '\\' && (c != '`' || ext != ".go") && rawHashes < 0 && !verbatim {
					i++
					if i < len(text) {
						i++
					}
					continue
				}
				if verbatim && text[i] == c && i+1 < len(text) && text[i+1] == c {
					i += 2
					continue
				}
				if rawHashes >= 0 {
					if text[i] == c && strings.HasPrefix(text[i+1:], rawSuffix) {
						i += 1 + rawHashes
						break
					}
				} else if text[i] == c && (width == 1 || (i+2 < len(text) && text[i+1] == c && text[i+2] == c)) {
					i += width
					break
				}
				if text[i] == '\n' && width == 1 && c != '`' && rawHashes < 0 && !verbatim {
					break
				}
				i++
			}
		case ext == ".py" && c == '#', ext != ".py" && strings.HasPrefix(text[i:], "//"):
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case ext != ".py" && strings.HasPrefix(text[i:], "/*"):
			i += 2
			depth := 1
			for i < len(text) && depth > 0 {
				if ext == ".rs" && strings.HasPrefix(text[i:], "/*") {
					depth++
					i += 2
				} else if strings.HasPrefix(text[i:], "*/") {
					depth--
					i += 2
				} else {
					i++
				}
			}
		default:
			i++
			continue
		}
		f.regions = append(f.regions, [2]int{start, i})
	}
	return f
}

func rustLifetime(text string, start int) bool {
	if start+1 >= len(text) {
		return false
	}
	r, size := utf8.DecodeRuneInString(text[start+1:])
	end := start + 1 + size
	return (unicode.IsLetter(r) || r == '_') && (end >= len(text) || text[end] != '\'')
}

// templateExpressionEnd skips quoted strings and comments while balancing an interpolation's braces.
func templateExpressionEnd(text string, start int) int {
	depth := 1
	for i := start; i < len(text); {
		switch {
		case strings.HasPrefix(text[i:], "//"):
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case strings.HasPrefix(text[i:], "/*"):
			i += 2
			for i < len(text) && !strings.HasPrefix(text[i:], "*/") {
				i++
			}
			if i < len(text) {
				i += 2
			}
		case strings.ContainsRune("\"'`", rune(text[i])):
			quote := text[i]
			i++
			for i < len(text) {
				if text[i] == '\\' {
					i += min(2, len(text)-i)
				} else if text[i] == quote {
					i++
					break
				} else {
					i++
				}
			}
		case text[i] == '{':
			depth++
			i++
		case text[i] == '}':
			depth--
			if depth == 0 {
				return i
			}
			i++
		default:
			i++
		}
	}
	return len(text)
}

func (f *CodeValueFilter) NonLiteral(start, end int) bool {
	if !f.code || start < 0 || end > len(f.text) || end <= start || !codeIdentifier.MatchString(f.text[start:end]) {
		return false
	}
	i := sort.Search(len(f.regions), func(i int) bool { return f.regions[i][1] > start })
	if i < len(f.regions) && f.regions[i][0] <= start && end <= f.regions[i][1] {
		return false
	}
	return true
}
