package detect

import (
	"html"
	"strings"
	"unicode"
	"unicode/utf8"
)

// textEncodingAt consumes one strict printable escape. It does not interpret '+'
// as a space, execute a language, or recursively decode its own output.
func textEncodingAt(text string, i int) (string, int) {
	if i >= len(text) {
		return "", 0
	}
	if text[i] == '%' {
		if i+3 > len(text) || !isHexByte(text[i+1]) || !isHexByte(text[i+2]) {
			return "", 0
		}
		value := hexVal(text[i+1])<<4 | hexVal(text[i+2])
		// Provider token syntax is ASCII. Reject control bytes and partial UTF-8
		// rather than inventing line boundaries or lossy replacement characters.
		if value < 0x20 || value >= 0x7f {
			return "", 0
		}
		return string(value), 3
	}
	if text[i] != '&' {
		return "", 0
	}
	end := i + 1
	for end < len(text) && end-i < 64 {
		c := text[end]
		if c == ';' {
			break
		}
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '#' && end == i+1) {
			return "", 0
		}
		end++
	}
	if end >= len(text) || end-i >= 64 || text[end] != ';' || end == i+1 {
		return "", 0
	}
	literal := text[i : end+1]
	decoded := html.UnescapeString(literal)
	if decoded == literal || !utf8.ValidString(decoded) || strings.ContainsRune(decoded, utf8.RuneError) {
		return "", 0
	}
	for _, r := range decoded {
		if unicode.IsControl(r) {
			return "", 0
		}
	}
	return decoded, end + 1 - i
}
