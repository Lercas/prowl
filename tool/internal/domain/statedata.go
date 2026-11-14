package domain

import (
	"html"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// stateAssignmentPatterns match known assignments within actual script contents.
var stateAssignmentPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"__NUXT__", regexp.MustCompile(`(?is)window\.__NUXT__\s*=\s*(.*?)\s*$`)},
	{"__INITIAL_STATE__", regexp.MustCompile(`(?is)window\.__INITIAL_STATE__\s*=\s*(.*?);?\s*$`)},
	{"__PRELOADED_STATE__", regexp.MustCompile(`(?is)window\.__PRELOADED_STATE__\s*=\s*(.*?);?\s*$`)},
	{"__APOLLO_STATE__", regexp.MustCompile(`(?is)window\.__APOLLO_STATE__\s*=\s*(.*?);?\s*$`)},
	{"__remixContext", regexp.MustCompile(`(?is)window\.__remixContext\s*=\s*(.*?);?\s*$`)},
	{"__sveltekit", regexp.MustCompile(`(?is)__sveltekit_[\w]+\s*=\s*(.*?);?\s*$`)},
	{"__GATSBY", regexp.MustCompile(`(?is)window\.___gatsby\s*=\s*(.*?);?\s*$`)},
	{"window.env", regexp.MustCompile(`(?is)window\.(?:__ENV__|__RUNTIME_CONFIG__|runtimeConfig|ENV|env|CONFIG|_config|appConfig)\s*=\s*(\{.*?\})\s*;?\s*$`)},
}

// decodeEscapes decodes HTML entities and one layer of common JSON/JS string escapes.
// Newly decoded backslashes are not reparsed. Invalid or unsupported escapes, including
// unpaired UTF-16 surrogates with no UTF-8 representation, remain available as source text.
func decodeEscapes(s string) string {
	return decodeStringEscapes(html.UnescapeString(s))
}

func decodeStringEscapes(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var out strings.Builder
	out.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '\\' || i+1 == len(s) {
			out.WriteByte(s[i])
			i++
			continue
		}
		consumed := 2
		switch s[i+1] {
		case '\\', '/', '\'', '"':
			out.WriteByte(s[i+1])
		case 'b':
			out.WriteByte('\b')
		case 'f':
			out.WriteByte('\f')
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 't':
			out.WriteByte('\t')
		case 'v':
			out.WriteByte('\v')
		case '0':
			if i+2 < len(s) && s[i+2] >= '0' && s[i+2] <= '9' {
				consumed = 1 // Do not guess at legacy octal escapes.
				out.WriteByte('\\')
			} else {
				out.WriteByte(0)
			}
		case '\n': // JavaScript line continuations do not contribute to the string value.
		case '\r':
			if i+2 < len(s) && s[i+2] == '\n' {
				consumed++
			}
		case 'x', 'u':
			r, width, ok := stateEscapeCodePoint(s[i+1:])
			if ok && r >= 0xD800 && r <= 0xDBFF {
				next := i + 1 + width
				ok = false
				if next+1 < len(s) && s[next] == '\\' && s[next+1] == 'u' {
					low, lowWidth, valid := stateEscapeCodePoint(s[next+1:])
					if valid && low >= 0xDC00 && low <= 0xDFFF {
						r = utf16.DecodeRune(r, low)
						width += 1 + lowWidth
						ok = true
					}
				}
			}
			if ok && !utf16.IsSurrogate(r) {
				out.WriteRune(r)
				consumed = 1 + width
			} else {
				out.WriteByte('\\')
				consumed = 1
			}
		default:
			if strings.HasPrefix(s[i+1:], "\u2028") || strings.HasPrefix(s[i+1:], "\u2029") {
				consumed = 1 + len("\u2028")
			} else {
				out.WriteByte('\\')
				consumed = 1
			}
		}
		i += consumed
	}
	return out.String()
}

// stateEscapeCodePoint reads xNN, uNNNN or u{N...} after an escape's backslash.
func stateEscapeCodePoint(s string) (rune, int, bool) {
	width := 4
	if s[0] == 'x' {
		width = 2
	}
	start, end := 1, 1+width
	braced := s[0] == 'u' && len(s) > 1 && s[1] == '{'
	if braced {
		start = 2
		end = len(s)
	}
	if len(s) < end {
		return 0, 0, false
	}
	var value rune
	for i := start; i < end; i++ {
		if braced && s[i] == '}' {
			return value, i + 1, i > start
		}
		var digit rune
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			digit = rune(c - '0')
		case c >= 'a' && c <= 'f':
			digit = rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			digit = rune(c-'A') + 10
		default:
			return 0, 0, false
		}
		if value > (utf8.MaxRune-digit)/16 {
			return 0, 0, false
		}
		value = value*16 + digit
	}
	if braced {
		return 0, 0, false
	}
	return value, end, true
}
