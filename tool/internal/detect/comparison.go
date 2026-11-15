package detect

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

const stageComparison = "L1-context-comparison"

// Captures are whole operand values. Escaped quotes cannot prematurely end a
// literal and turn its prefix into an apparent password. No source is executed.
const comparisonLiteral = "(?:\"((?:\\\\[^\\r\\n]|[^\"\\\\\\r\\n]){1,200})\"|'((?:\\\\[^\\r\\n]|[^'\\\\\\r\\n]){1,200})'|`((?:\\\\[^\\r\\n]|[^`\\\\\\r\\n]){1,200})`)"
const comparisonOperator = `[ \t]*(?:===|!==|==|!=)[ \t]*`

var reComparisonRight = regexp.MustCompile("(?i)((?:pass(?:word|wd|phrase)?|pwd|pw|token|secret|api[_\\- ]?key|apikey|key|credential)[A-Za-z0-9_\\-]{0,64})" +
	"[\"'`\\])]{0,3}" + comparisonOperator + comparisonLiteral)
var reComparisonLeft = regexp.MustCompile(comparisonLiteral + comparisonOperator +
	"([A-Za-z_$][A-Za-z0-9_.$]{0,64}(?:\\[[ \\t]*[\"'`][A-Za-z0-9_\\-]{1,64}[\"'`][ \\t]*\\])?)")

func comparisonIdentByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$'
}

// comparisonField reuses the table field vocabulary, then rejects additional
// metadata words: comparing a password's type/status is not authenticating it.
func comparisonField(name string) tableField {
	if i := strings.LastIndexByte(name, '['); i >= 0 {
		name = strings.TrimSpace(strings.TrimSuffix(name[i+1:], "]"))
		if len(name) < 2 || name[0] != name[len(name)-1] {
			return tableField{}
		}
		name = name[1 : len(name)-1]
	} else if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	field := tableFieldFor(name, tableCell{0, len(name)})
	if field.kind == "password" {
		for _, part := range nonSecretNameParts {
			if strings.Contains(field.name, part) {
				return tableField{}
			}
		}
		for _, part := range strings.Split(field.name, "_") {
			for _, meta := range nonSecretNameWords {
				if part == meta {
					return tableField{}
				}
			}
		}
	}
	return field
}

// comparisonValue decodes only the printable escapes already supported by our
// text views. Unknown escapes, controls and interpolation are not guessed.
func comparisonValue(raw string) (string, bool) {
	if !strings.ContainsRune(raw, '\\') {
		return raw, utf8.ValidString(raw)
	}
	var out strings.Builder
	for i := 0; i < len(raw); {
		if raw[i] != '\\' {
			out.WriteByte(raw[i])
			i++
			continue
		}
		value, n := unescapeAt(raw, i)
		if n == 0 {
			return "", false
		}
		out.WriteString(value)
		i += n
	}
	value := out.String()
	return value, utf8.ValidString(value)
}

func (d *Detector) comparisonMatch(text string, ix []int, reverse bool) (Match, bool) {
	nameGroup, first, last := 1, 2, 4
	if reverse {
		nameGroup, first, last = 4, 1, 3
	}
	ns, ne := ix[2*nameGroup], ix[2*nameGroup+1]
	vs, ve, ok := firstGroup(ix, first, last)
	if !ok {
		return Match{}, false
	}
	if reverse {
		// Reject prefixed strings (f/r/b) and a suffix of a longer operand.
		lo := skipBlanksBack(text, vs-2)
		if vs >= 2 && comparisonIdentByte(text[vs-2]) || lo >= 0 && (text[lo] == '+' || text[lo] == '.') {
			return Match{}, false
		}
		if ne < len(text) && comparisonIdentByte(text[ne]) {
			return Match{}, false
		}
		next := skipBlanks(text, ne)
		if next < len(text) && (text[next] == '.' || text[next] == '[' || text[next] == '(' || text[next] == '+') {
			return Match{}, false
		}
	} else {
		ns = nameStart(text, ns)
		if ns > 0 && (text[ns-1] == '\'' || text[ns-1] == '"' || text[ns-1] == '`') {
			// A quoted name is a field only when indexed, not another string literal.
			quote := text[ns-1]
			open := skipBlanksBack(text, ns-2)
			if open < 1 || text[open] != '[' || !(comparisonIdentByte(text[open-1]) || text[open-1] == ']' || text[open-1] == ')') || ne+1 >= len(text) || text[ne] != quote || text[ne+1] != ']' {
				return Match{}, false
			}
		} else if ne < len(text) && (text[ne] == '\'' || text[ne] == '"' || text[ne] == '`' || text[ne] == ']') {
			return Match{}, false
		}
		before := skipBlanksBack(text, ns-1)
		if before >= 0 && text[before] == '+' {
			return Match{}, false
		}
		next := skipBlanks(text, ve+1)
		if next < len(text) && (text[next] == '+' || text[next] == '.' || text[next] == '[' || text[next] == '`') {
			return Match{}, false
		}
	}
	field := comparisonField(text[ns:ne])
	if field.kind == "" {
		return Match{}, false
	}
	value, ok := comparisonValue(text[vs:ve])
	if !ok || strings.ContainsAny(value, " \t\r\n\v\f") || IsExampleOrPlaceholder(value) || IsTemplatePlaceholder(value) {
		return Match{}, false
	}
	typ, category := "generic_password", "generic"
	if field.kind == "password" {
		n := utf8.RuneCountInString(value)
		if !d.genericPwd || (n < 6 && !d.shortPasswordAllowed(field.name, value)) || n > 64 || isBcryptHash(value) || (n >= 6 && isVersionOrNumber(value)) || hasJSOperator(value) || looksLikeUnicodeEscaped(value) {
			return Match{}, false
		}
	} else {
		if !d.genericKey || !d.boundKeyValueOK(field.name, value, field.hexOnly) {
			return Match{}, false
		}
		typ, category = "generic_api_key", d.genericKeyCat
	}
	return Match{Type: typ, Value: value, Start: vs, End: ve, Confidence: .6, Category: category, Stage: stageComparison, ContextName: field.name}, true
}
