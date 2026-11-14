package linewin

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func TestBuiltinNewlineRepeatsGetSoundBytePlans(t *testing.T) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	contents := map[string]string{
		"deepseek_api_key": `deepseek_-` + "\n_-api_-\n_-key = \"sk-Ab3dE5gH7jK9mN2pQ4rS6tU8vW0xY1zC\";",
		"private_key_pem":  "-----BEGIN RSA PRIVATE KEY-----\nAb3dE5gH7jK9mN2pQ4rS6tU8vW0xY1zC\n-----END",
	}
	for _, st := range tax.Types {
		value, wanted := contents[st.ID]
		if !wanted {
			continue
		}
		t.Run(st.ID, func(t *testing.T) {
			set := New([]*regexp.Regexp{st.RE})
			plan := set.Plan(0)
			if plan == nil || plan.lineSafe {
				t.Fatal("expected the byte proof to handle an unbounded newline construct")
			}
			text := strings.Repeat("var filler=0;", 5000) + value + ";" + strings.Repeat("let tail=1;", 5000)
			if !st.RE.MatchString(text) {
				t.Fatal("fixture must contain a matching credential shape")
			}
			w := set.Prepare(text, "", "", nil)
			if w == nil || w.state[0].full || !w.state[0].byteEdges {
				t.Fatal("byte-only plan fell back despite nearby separators")
			}
			w.Release()
			checkEquivalent(t, set, []*regexp.Regexp{st.RE}, text)
			// A real match beyond the byte budget must survive whole-text fallback.
			long := strings.Replace(value, "\n", strings.Repeat("\n_-", 5000), 1)
			if st.ID == "private_key_pem" {
				long = strings.Replace(value, "\n", strings.Repeat("\nA-", 5000), 1)
			}
			checkEquivalent(t, set, []*regexp.Regexp{st.RE}, strings.Repeat("x;", 5000)+long+strings.Repeat("y;", 5000))
		})
	}
}

func TestWeightedCutsCoverFiniteSyntaxAcrossSeparators(t *testing.T) {
	for _, pattern := range []string{
		`"key"[^"]*"value"`,
		`BEGIN(?:\s*item[=:][a-z]+)*END(?s:.)?`,
		`"service"\s*:\s*"account"[\s\S]{0,800}?PRIVATE_KEY`,
	} {
		re := regexp.MustCompile(pattern)
		set := New([]*regexp.Regexp{re})
		if plan := set.Plan(0); plan == nil || plan.lineSafe || plan.cutBudget <= 0 {
			t.Fatalf("expected finite-skeleton byte proof for %s: %+v", pattern, plan)
		}
		middle := `"key":` + "\nletters\n" + `"value";BEGIN item=first` + "\nitem=second END;" + `"service":"account"` + strings.Repeat("\n", 100) + `PRIVATE_KEY;`
		text := strings.Repeat(`"padding":0;`, 5000) + middle + strings.Repeat(`"tail":1;`, 5000)
		checkEquivalent(t, set, []*regexp.Regexp{re}, text)
	}
}

func TestUnprovableUnboundedAlphabetRemainsWholeText(t *testing.T) {
	for _, pattern := range []string{`(?s)BEGIN.*END`, `name[\s_-]*key=[^\n]+`} {
		if plan := Analyze(regexp.MustCompile(pattern)); plan != nil {
			t.Fatalf("no finite line/byte proof exists for %s", pattern)
		}
	}
}

func TestDenseSeparatorProofHasLinearWorkBudget(t *testing.T) {
	re := regexp.MustCompile(`"key"[^"]*"value"`)
	set := New([]*regexp.Regexp{re})
	text := strings.Repeat(`"key"x"value";`, 3000)
	w := set.Prepare(text, "", "", nil)
	defer w.Release()
	if w == nil || !w.state[0].full || w.state[0].byteWork > 2*len(text)+maxByteWindow {
		t.Fatal("dense separator search did not stop at its linear work budget")
	}
	checkEquivalent(t, set, []*regexp.Regexp{re}, text)
}

func FuzzWeightedByteWindowParity(f *testing.F) {
	f.Add(`"key":x"value";`)
	f.Add("deepseek_\n_key=sk-Ab3dE5gH7jK9mN2pQ4rS6tU8vW0xY1zC;\xff")
	patterns := []string{`"key"[^"]*"value"`, `BEGIN(?:\s*item[=:][a-z]+)*END(?s:.)?`,
		`deepseek[\s_-]*key=(sk-[a-z0-9]{8,32})(?:[^a-z0-9]|$)`}
	res := make([]*regexp.Regexp, len(patterns))
	for i, pattern := range patterns {
		res[i] = regexp.MustCompile(pattern)
	}
	set := New(res)
	f.Fuzz(func(t *testing.T, middle string) {
		if len(middle) > 2048 {
			t.Skip()
		}
		text := strings.Repeat(`"x";`, 128) + middle + strings.Repeat(`"y";`, 128)
		checkEquivalent(t, set, res, text)
	})
}
