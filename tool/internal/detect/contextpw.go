package detect

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// mlPasswordCues are multilingual credential cue roots (lowercased) that flag a nearby token as a
// likely password without an adjacent `=`/`:` anchor.
var mlPasswordCues = []string{
	"password", "passphrase", "passwort", "pwd", "kennwort", "mot de passe", "motdepasse", "contraseña", "contrasena", "wachtwoord",
	"salasana", "lösenord", "adgangskode", "geslo", "heslo", "пароль", "geheim",
	"senha", "parola", "mdp", "credential",
}

var passwordCueRE = regexp.MustCompile(`(?i)(?:` + strings.Join(mlPasswordCues, "|") + `)`)

// These connectives support credential prose without borrowing context across arbitrary text or a
// sentence boundary. Assignments are handled independently by the anchored taxonomy rule.
var passwordConnectives = map[string]bool{
	"is": true, "was": true, "ist": true, "lautet": true, "est": true, "temporaire": true,
	"temporary": true, "new": true, "equals": true, "es": true, "temporal": true, "token": true,
	"é": true, "e": true, "для": true, "доступа": true, "временный": true, "равен": true,
	"это": true, "будет": true,
}

var contextualAssignment = regexp.MustCompile(`(?:^|[^\pL\pN_])([\pL\pN_]+)=([A-Za-z0-9!@#$%^&*_+.=\-]{8,24})(?:$|[^A-Za-z0-9!@#$%^&*_+.=\-])`)
var reversePassword = regexp.MustCompile(`(?i)([A-Za-z0-9!@#$%^&*_+.=\-]{8,24})\s+is\s+the\s+password\b`)

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
	if len(t) < 8 || len(t) > 24 {
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
	if !dg || !lo { // require both a digit and a lowercase letter
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
	if !anyPresent(present, d.cueIdx) { // reuse the AC pass: no cue anywhere
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
		// cue presence only: a non-ASCII line needs a Unicode-correct fold (ПАРОЛЬ -> пароль), so
		// lowercase that line independently; pure-ASCII lines reuse the zero-cost ASCII view.
		cueSrc := lower[lineStart:i]
		if uniLower != "" && hasNonASCII(line) {
			cueSrc = strings.ToLower(line)
		}
		if len(line) < 12 || !passwordCueRE.MatchString(cueSrc) {
			lineStart = i + 1
			continue
		}
		lineStart = i + 1
		beforeCount := len(out)
		for _, cue := range passwordCueRE.FindAllStringIndex(line, maxScanMatches) {
			if !cueWordBoundary(line, cue[0], cue[1]) {
				continue
			}
			j := cue[1]
			for words := 0; words < 6 && j < len(line) && j-cue[1] < 96; words++ {
				for j < len(line) && strings.ContainsRune(" \t:=\"'`", rune(line[j])) {
					j++
				}
				k := j
				for k < len(line) && isTokenChar(line[k]) {
					k++
				}
				if k == j {
					// Unicode connectives are words too; byte offsets always refer to the original source.
					for k < len(line) {
						r, n := utf8.DecodeRuneInString(line[k:])
						if !unicode.IsLetter(r) {
							break
						}
						k += n
					}
				}
				tok := line[j:k]
				if isLikelyPasswordToken(tok) && (k == len(line) || !strings.ContainsRune("([.=", rune(line[k]))) {
					out = append(out, Match{Type: "generic_password", Value: tok,
						Start: base + j, End: base + k, Confidence: 0.6,
						Category: "generic", Stage: "L1-context-pw"})
					break
				}
				if !passwordConnectives[strings.ToLower(tok)] {
					break
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
