package detect

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func TestASCIIGateNeverExtractsOrChangesLongestMode(t *testing.T) {
	short := "v9N7jQ3mX8kP4wZ2"
	full := short + "rT6yU5bA1sD0fG9h"
	re := regexp.MustCompile("(?i)(" + short + "|" + full + ")")
	re.Longest()
	d := New(&taxonomy.Taxonomy{Types: []taxonomy.SecretType{{ID: "owned", Category: "cloud", RE: re, Extract: 1}}})
	ms := d.Scan(strings.ToUpper(full))
	if len(ms) != 1 || ms[0].Value != strings.ToUpper(full) {
		t.Fatal("gate replaced original Longest extraction")
	}
	re = regexp.MustCompile(`(?i:secret)=([A-Z]{4})`)
	d = New(&taxonomy.Taxonomy{Types: []taxonomy.SecretType{{ID: "owned", Category: "cloud", RE: re, Extract: 1}}})
	if ms := d.Scan("secret=abcd"); len(ms) != 0 {
		t.Fatal("case-relaxed gate became a false positive finding")
	}
}

func FuzzASCIIRegexGateCannotRejectOriginalMatch(f *testing.F) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		f.Fatal(err)
	}
	var originals, gates []*regexp.Regexp
	for _, st := range tax.Types {
		if gate := asciiRegexGate(st.RE); gate != nil {
			originals = append(originals, st.RE)
			gates = append(gates, gate)
		}
	}
	for _, re := range namedBuiltins {
		if gate := asciiRegexGate(re); gate != nil {
			originals = append(originals, re)
			gates = append(gates, gate)
		}
	}
	for _, pattern := range []string{`(?i:ſK)`, `(?i)\b[\p{Greek}\p{Cyrillic}]+\b`, `(?i)[^a-z]{2,8}`, `(?i:api)(?-i:[A-Z])`, `(?im)^password\s*[:=].+$`} {
		re := regexp.MustCompile(pattern)
		gate := asciiRegexGate(re)
		if gate == nil {
			f.Fatalf("custom projection failed: %s", pattern)
		}
		originals = append(originals, re)
		gates = append(gates, gate)
	}
	f.Add(`PASSWORD="R7v!K9pX2mQ"`)
	f.Add("api_key: Q7mR3vK8pT2xN6cW4bY9sF5hL1aD0uGz")
	f.Add("ordinaryIdentifiers without a credential")
	f.Add("paſſword: N7vK2qM9\nKEY=Q7mR3vK8pT2xN6cW4bY9sF5hL1aD0uGz")
	f.Add("ПАРОЛЬ: N7vK2qM9\ninvalid\xff\xfe")
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 8192 {
			return
		}
		var scratch []byte
		lower := lowerScratch(&scratch, text)
		for i, original := range originals {
			if original.MatchString(text) && !gates[i].MatchString(lower) {
				t.Fatal("ASCII rejection gate lost a legal original match")
			}
		}
	})
}
