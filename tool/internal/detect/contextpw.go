package detect

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// mlPasswordCues are multilingual credential cue roots (lowercased) that flag a nearby token as a
// likely password without an adjacent `=`/`:` anchor.
var mlPasswordCues = []string{
	"pass", "pwd", "kennwort", "mot de passe", "motdepasse", "contrase", "wachtwoord",
	"salasana", "lösenord", "adgangskode", "geslo", "heslo", "пароль", "geheim",
	"zugangsdaten", " mdp ", "credential",
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
	if IsExampleOrPlaceholder(t) || isVersionOrNumber(t) || isHexRun(t) {
		return false
	}
	return true
}

func isTokenChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '!' || c == '@' || c == '#' || c == '$' || c == '%' || c == '^' || c == '&' ||
		c == '*' || c == '_' || c == '-' || c == '+' || c == '=' || c == '.'
}

func anyCue(s string) bool {
	for _, kw := range mlPasswordCues {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

// firstPasswordCue maps the first folded cue back to the original line. Folded byte lengths can
// differ (for example, Kelvin sign or dotted I), while candidate spans always use original bytes.
func firstPasswordCue(line, folded string) (start, end int) {
	start, end = -1, -1
	for _, cue := range mlPasswordCues {
		if pos := strings.Index(folded, cue); pos >= 0 && (start < 0 || pos < start) {
			start, end = pos, pos+len(cue)
		}
	}
	if start < 0 || !hasNonASCII(line) {
		return start, end
	}
	foldedStart, foldedEnd := start, end
	start, end = len(line), len(line)
	foldedPos := 0
	for pos, r := range line {
		if foldedPos == foldedStart {
			start = pos
		}
		if foldedPos == foldedEnd {
			end = pos
			break
		}
		foldedPos += utf8.RuneLen(unicode.ToLower(r))
	}
	return start, end
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
		if len(line) < 12 || !anyCue(cueSrc) {
			lineStart = i + 1
			continue
		}
		cueStart, cueEnd := firstPasswordCue(line, cueSrc)
		lineStart = i + 1
		for j := 0; j < len(line); {
			if !isTokenChar(line[j]) {
				j++
				continue
			}
			k := j
			for k < len(line) && isTokenChar(line[k]) {
				k++
			}
			tok := line[j:k]
			valueStart := j
			if eq := strings.IndexByte(tok, '='); eq >= 0 &&
				(anyCue(strings.ToLower(tok[:eq])) || (cueEnd > j && cueStart < j+eq && cueEnd <= j+eq)) {
				// Contextual names such as credential or lösenord are not all covered by the regex.
				// Keep their value, including any later '=' characters, instead of suppressing the leak.
				valueStart = j + eq + 1
				tok = line[valueStart:k]
			}
			if isLikelyPasswordToken(tok) {
				// A token cannot supply its own credential context. Only tokens intersecting the first
				// cue need another line search; this keeps dense single-line inputs linear in size.
				if valueStart < cueEnd && cueStart < k && !anyCue(strings.ToLower(line[:valueStart])) && !anyCue(strings.ToLower(line[k:])) {
					j = k
					continue
				}
				out = append(out, Match{Type: "generic_password", Value: tok,
					Start: base + valueStart, End: base + k, Confidence: 0.6,
					Category: "generic", Stage: "L1-context-pw"})
				break
			}
			j = k
		}
	}
	return out
}
