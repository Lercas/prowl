package detect

import "strings"

func IsLiteralPasswordPlaceholder(value string) bool {
	return strings.Contains(value, "${") || strings.Contains(value, "{{") || IsCanonicalPasswordPlaceholder(value)
}

// passwordLiteral extends a regex capture cut at a hash's comma or the generic length bound. The
// bounded complete scalar must validate as a KDF encoding; a magic prefix alone is not sufficient.
func passwordLiteral(text string, start, end int) string {
	quote := byte(0)
	if start > 0 && strings.ContainsRune("\"'`", rune(text[start-1])) {
		quote = text[start-1]
	}
	for end < len(text) && end-start < 4096 {
		c := text[end]
		if c == '\n' || c == '\r' || (quote != 0 && c == quote) || (quote == 0 && strings.ContainsRune(" \t;\"'`", rune(c))) {
			break
		}
		end++
	}
	return text[start:end]
}

// literalPasswordEnd recovers the complete bounded scalar once the taxonomy established a password
// assignment. Never mint an identity from a prefix cut at a comma, quote escape or length ceiling.
func literalPasswordEnd(text string, start int) (int, bool) {
	quote := byte(0)
	if start > 0 && strings.ContainsRune("\"'`", rune(text[start-1])) {
		quote = text[start-1]
	}
	end := start
	for end < len(text) && end-start < 4096 {
		c := text[end]
		if c == '\n' || c == '\r' {
			return end, quote == 0
		}
		if quote != 0 {
			if c == quote {
				return end, true
			}
			if c == '\\' && end+1 < len(text) && text[end+1] != '\n' && text[end+1] != '\r' {
				end += 2
				continue
			}
		} else if strings.ContainsRune(" \t;\"'`", rune(c)) {
			return end, true
		}
		end++
	}
	if end-start > 4096 {
		return end, false
	}
	if end == len(text) {
		return end, quote == 0
	}
	return end, quote != 0 && text[end] == quote || quote == 0 && strings.ContainsRune(" \t;\"'`\r\n", rune(text[end]))
}
