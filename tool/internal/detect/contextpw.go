package detect

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/ahocorasick"
)

// mlPasswordCues are multilingual credential cue roots (lowercased) that flag a nearby token as a
// likely password without an adjacent `=`/`:` anchor.
var mlPasswordCues = []string{
	"password", "passwd", "passphrase", "passwort", "pwd", "kennwort", "mot de passe", "motdepasse", "contraseña", "contrasena", "wachtwoord",
	"salasana", "lösenord", "adgangskode", "geslo", "heslo", "пароль", "geheim",
	"senha", "parola", "mdp", "credential", "zugangsdaten", "パスワード", "密码", "密碼",
}

var passwordCueRE = regexp.MustCompile(`(?i)(?:` + strings.Join(mlPasswordCues, "|") + `)`)
var passwordCueMatcher = ahocorasick.New(mlPasswordCues)
var passwordCueFoldMatcher = newPasswordFoldMatcher()

func lowerFoldRune(r rune) rune {
	r = unicode.ToLower(r)
	best := r
	for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
		if next < best {
			best = next
		}
	}
	return best
}

func newPasswordFoldMatcher() *ahocorasick.Matcher {
	patterns := make([]string, len(mlPasswordCues))
	for i, cue := range mlPasswordCues {
		patterns[i] = strings.Map(lowerFoldRune, cue)
	}
	return ahocorasick.New(patterns)
}

// This is the literal-alternation regex's simple-fold predicate over a ToLower
// view, including fold aliases that ToLower alone does not merge (such as long s).
func containsFoldedPasswordCue(text string) bool {
	next, out := passwordCueFoldMatcher.Transitions(), passwordCueFoldMatcher.Outputs()
	var state int32
	for i := 0; i < len(text); {
		c := text[i]
		if c < utf8.RuneSelf {
			if c >= 'a' && c <= 'z' {
				c -= 'a' - 'A'
			}
			state = next[state<<8|int32(c)]
			if len(out[state]) > 0 {
				return true
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(text[i:])
		var encoded [utf8.UTFMax]byte
		n := utf8.EncodeRune(encoded[:], lowerFoldRune(r))
		for _, b := range encoded[:n] {
			state = next[state<<8|int32(b)]
			if len(out[state]) > 0 {
				return true
			}
		}
		i += size
	}
	return false
}

// These connectives support credential prose without borrowing context across arbitrary text or a
// sentence boundary. Assignments are handled independently by the anchored taxonomy rule.
var passwordConnectives = map[string]bool{
	"is": true, "was": true, "ist": true, "lautet": true, "est": true, "temporaire": true,
	"temporary": true, "new": true, "equals": true, "es": true, "temporal": true, "token": true,
	"é": true, "e": true, "для": true, "доступа": true, "временный": true, "равен": true,
	"это": true, "будет": true, "стенда": true,
}

var contextualAssignment = regexp.MustCompile(`(?:^|[^\pL\pN_])([\pL\pN_]+)=([A-Za-z0-9!@#$%^&*_+.=\-]{8,64})(?:$|[^A-Za-z0-9!@#$%^&*_+.=\-])`)
var reversePassword = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9!@#$%^&*_+.=\-])([A-Za-z0-9!@#$%^&*_+.=\-]{8,64})\s+is\s+the\s+password\b`)

func cueWordBoundary(line string, start, end int) bool {
	word := func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' }
	if start > 0 {
		r, _ := utf8.DecodeLastRuneInString(line[:start])
		if word(r) {
			return false
		}
	}
	if end < len(line) {
		r, _ := utf8.DecodeRuneInString(line[end:])
		if word(r) {
			return false
		}
	}
	return true
}

func isLikelyPasswordToken(t string) bool {
	if len(t) < 8 || len(t) > 64 {
		return false
	}
	var lo, dg bool
	for i := 0; i < len(t); i++ {
		switch c := t[i]; {
		case c >= 'a' && c <= 'z':
			lo = true
		case c >= '0' && c <= '9':
			dg = true
		case c == '/' || c == ':' || c == '\\':
			return false // a path or ref (vault:…, http://…), not a password
		}
	}
	if !lo {
		return false
	}
	// Generated alphabetic passwords are valid credentials too. Require a long, densely
	// mixed-case run to distinguish them from ordinary prose and code identifiers.
	if !dg && !(len(t) >= 12 && partIsRandom(t) && classSwitchRate(t) >= .45 && ShannonEntropy(t) >= 3.5) {
		return false
	}
	if IsExampleOrPlaceholder(t) || isVersionOrNumber(t) || isHexRun(t) || looksLikeIdentifier(t) || looksLikeJSCode(t) {
		return false
	}
	return true
}

func isTokenChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '!' || c == '@' || c == '#' || c == '$' || c == '%' || c == '^' || c == '&' ||
		c == '*' || c == '_' || c == '-' || c == '+' || c == '=' || c == '.'
}

// cueEndsIdentifier accepts a cue that closes a snake_case name written in prose ("the staging
// db_password is …"): the name is the credential, exactly as in an assignment.
func cueEndsIdentifier(line string, start, end int) bool {
	if start == 0 || line[start-1] != '_' {
		return false
	}
	if end < len(line) {
		if r, _ := utf8.DecodeRuneInString(line[end:]); unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			return false
		}
	}
	return true
}

// skipCueSeparators returns the width of spacing and value-introducing punctuation before the next
// word: "password: x", "пароль сервиса — x". An opening bracket counts only directly after the cue
// ("password (x)", "passwd（x）"): later in the clause it is a call (`Password: mask("x")`). A comma
// always ends the clause, as in a signature `password: str, mode: str = "oauth2flow"`.
func skipCueSeparators(s string, afterCue bool) int {
	set := " \t:=\"'`—–："
	if afterCue {
		set += "(（"
	}
	n := 0
	for n < len(s) {
		r, size := utf8.DecodeRuneInString(s[n:])
		if !strings.ContainsRune(set, r) {
			break
		}
		n += size
	}
	return n
}

// maxWeakPasswordGap is how many free prose words may separate a cue from a weak value (lowercase
// letters and digits only). Such a value looks like any word with a digit ("rpm2cpio" in a list of
// commands), so it needs the cue close by; a value with a capital or a symbol may sit further away.
const maxWeakPasswordGap = 2

func isWeakPasswordToken(tok string) bool {
	for i := 0; i < len(tok); i++ {
		if c := tok[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// maxProseWordRunes bounds a connective: longer runs are names or values, not grammar.
const maxProseWordRunes = 12

// isProseWord reports whether tok is an ordinary lowercase word that may stand between a password
// cue and its value ("password for the admin account is …"). Letters only: a digit, a symbol or an
// inner capital makes it a name or a value, which ends the clause.
func isProseWord(tok string) bool {
	n := 0
	for _, r := range tok {
		// A leading capital is a noun or a sentence start ("Konto"); an inner one is a name.
		if !unicode.IsLetter(r) || n > 0 && unicode.IsUpper(r) {
			return false
		}
		n++
	}
	return n > 0 && n <= maxProseWordRunes
}

// contextualPassword finds a password token in any line carrying a credential cue but no adjacent
// assignment. lower is the per-line ASCII-lowercased text (offsets match); uniLower is the Unicode-correct
// lowercase (empty when pure ASCII), used only to detect non-ASCII cues — spans always come from the
// original line. budget is the remaining global match cap; a non-positive budget emits nothing.
func (d *Detector) contextualPassword(text, lower, uniLower string, present []bool, budget int) []Match {
	if budget <= 0 {
		return nil
	}
	if !d.genericPwd { // taxonomy doesn't declare generic_password (e.g. --rules-only): emit no builtin
		return nil
	}
	// A nil presence inventory is reserved for one bounded parser-established
	// scalar. Its own lines must still contain a real cue below.
	if present != nil && !anyPresent(present, d.cueIdx) { // reuse the AC pass: no cue anywhere
		return nil
	}
	var out []Match
	lineStart := 0
	for i := 0; i <= len(text); i++ {
		if i < len(text) && text[i] != '\n' {
			continue
		}
		if len(out) >= budget { // honor the remaining global cap: one match per cue line, stop at budget
			break
		}
		line := text[lineStart:i]
		base := lineStart
		lineStart = i + 1
		if len(line) < 12 {
			continue
		}
		// Presence only: stream the former Unicode lower+simple-fold predicate,
		// or reuse the byte-aligned lowercase view on ASCII lines.
		cueSrc := lower[base:i]
		var hasCue bool
		if uniLower != "" && hasNonASCII(line) {
			hasCue = containsFoldedPasswordCue(line)
		} else {
			hasCue = passwordCueMatcher.Contains(cueSrc)
		}
		if !hasCue {
			continue
		}
		beforeCount := len(out)
		for _, cue := range passwordCueRE.FindAllStringIndex(line, maxScanMatches) {
			j := cue[1]
			switch line[cue[0]:cue[1]] {
			case "パスワード", "密码", "密碼":
				// CJK prose has no word-spacing boundary. Require its value-introducing
				// particle instead, so cryptography terms such as 密码学 are not cues.
				tail := strings.TrimLeft(line[j:], " \t")
				matched := false
				for _, particle := range []string{"は", "是", "为", "為", ":", "：", "="} {
					if strings.HasPrefix(tail, particle) {
						j += len(line[j:]) - len(tail) + len(particle)
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			default:
				if !cueWordBoundary(line, cue[0], cue[1]) && !cueEndsIdentifier(line, cue[0], cue[1]) {
					continue
				}
			}
			if strings.HasPrefix(strings.TrimLeft(line[j:], " \t"), "- ") {
				j += len(line[j:]) - len(strings.TrimLeft(line[j:], " \t")) + 2
			}
			freeWords := 0
			for words := 0; words < 6 && j < len(line) && j-cue[1] < 96; words++ {
				j += skipCueSeparators(line[j:], words == 0)
				k := j
				for k < len(line) && isTokenChar(line[k]) {
					k++
				}
				// Unicode connectives are words too ("für", "сервиса"); byte offsets always refer to
				// the original source. An ASCII run continues only into letters, never out of a value.
				for k < len(line) && line[k] >= utf8.RuneSelf && (k == j || isProseWord(line[j:k])) {
					r, n := utf8.DecodeRuneInString(line[k:])
					if !unicode.IsLetter(r) {
						break
					}
					k += n
					for k < len(line) && (line[k] >= 'a' && line[k] <= 'z' || line[k] >= 'A' && line[k] <= 'Z') {
						k++
					}
				}
				// A full stop that closes the sentence is not part of the value.
				for k > j+1 && line[k-1] == '.' && (k == len(line) || line[k] == ' ') {
					k--
				}
				tok := line[j:k]
				if isLikelyPasswordToken(tok) && (k == len(line) || !strings.ContainsRune("([=", rune(line[k])) && (line[k] != '.' || k+1 == len(line) || line[k+1] == ' ')) &&
					(freeWords <= maxWeakPasswordGap || !isWeakPasswordToken(tok)) {
					out = append(out, Match{Type: "generic_password", Value: tok,
						Start: base + j, End: base + k, Confidence: 0.6,
						Category: "generic", Stage: "L1-context-pw"})
					break
				}
				if !passwordConnectives[strings.ToLower(tok)] {
					if !isProseWord(tok) {
						break
					}
					freeWords++
				}
				j = k
			}
			if len(out) > 0 && out[len(out)-1].Start >= base {
				break
			}
		}
		if len(out) == beforeCount {
			for _, ix := range contextualAssignment.FindAllStringSubmatchIndex(line, maxScanMatches) {
				name := strings.ToLower(line[ix[2]:ix[3]])
				value := line[ix[4]:ix[5]]
				if (strings.Contains(name, "password") || strings.Contains(name, "credential") || strings.Contains(name, "lösenord")) && isLikelyPasswordToken(value) {
					out = append(out, Match{Type: "generic_password", Value: value, Start: base + ix[4], End: base + ix[5], Confidence: 0.6, Category: "generic", Stage: "L1-context-pw"})
					break
				}
			}
		}
		if len(out) == beforeCount {
			if ix := reversePassword.FindStringSubmatchIndex(line); ix != nil && isLikelyPasswordToken(line[ix[2]:ix[3]]) {
				out = append(out, Match{Type: "generic_password", Value: line[ix[2]:ix[3]], Start: base + ix[2], End: base + ix[3], Confidence: 0.6, Category: "generic", Stage: "L1-context-pw"})
			}
		}
		if len(out) == beforeCount && strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "credentials ") {
			fields := strings.Fields(line)
			if len(fields) == 2 && isLikelyPasswordToken(fields[1]) {
				start := strings.LastIndex(line, fields[1])
				out = append(out, Match{Type: "generic_password", Value: fields[1], Start: base + start, End: base + start + len(fields[1]), Confidence: 0.6, Category: "generic", Stage: "L1-context-pw"})
			}
		}
	}
	return out
}
