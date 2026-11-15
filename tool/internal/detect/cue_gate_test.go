package detect

import (
	"strings"
	"testing"
)

func TestPasswordCueGateKeepsUnicodeSimpleFoldCases(t *testing.T) {
	d := newDetector(t)
	for _, text := range []string{"password:\npaſſword is Cedar286", "Kennwort is Cedar286", "PASSWORD is Cedar286"} {
		if namedMatch(d.Scan(text), "generic_password", "Cedar286") == nil {
			t.Fatal("optimized cue gate lost an existing fold variant")
		}
	}
}

func FuzzASCIIPasswordCueGateMatchesRegex(f *testing.F) {
	for _, cue := range mlPasswordCues {
		f.Add("before " + cue + " after")
		f.Add(strings.ToUpper(cue))
	}
	f.Add("ordinary Go identifiers and comments")
	f.Fuzz(func(t *testing.T, text string) {
		if hasNonASCII(text) {
			return
		}
		text = strings.ToLower(text)
		if passwordCueMatcher.Contains(text) != passwordCueRE.MatchString(text) {
			t.Fatal("ASCII cue gate differs from original regex")
		}
	})
}

func FuzzUnicodePasswordCueGateMatchesRegex(f *testing.F) {
	for _, text := range []string{"paſſword is Cedar286", "Kennwort", "İ PASSWORD パスワード 密码", "ПАРОЛЬ", "\xffpass\xfe", "mot de passe"} {
		f.Add(text)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 8192 {
			return
		}
		if containsFoldedPasswordCue(text) != passwordCueRE.MatchString(strings.ToLower(text)) {
			t.Fatal("Unicode simple-fold predicate changed")
		}
	})
}
