package linewin

import (
	"math/rand"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestAnalyze(t *testing.T) {
	cases := []struct {
		rx   string
		lits []Lit // nil == must fall back to whole-text
		gaps int
		edge bool
	}{
		{rx: `\bAC[a-f0-9]{32}\b`, lits: []Lit{{S: "AC"}}},
		{rx: `\b(hf_[A-Za-z0-9]{34,})\b`, lits: []Lit{{S: "hf_"}}},
		{rx: `(?i)token\s*[=:]\s*(\w+)`, lits: []Lit{{S: "token", Fold: true}}, gaps: 2},
		{rx: `sk-[a-z]{8}(?:[^a-z]|$)`, lits: []Lit{{S: "sk-"}}, gaps: 1, edge: true},
		{rx: `^key=\w+`, lits: []Lit{{S: "key="}}, edge: true},
		{rx: `(?m)^key=\w+$`, lits: []Lit{{S: "key="}}},
		{rx: `new[_\-]?relic`, lits: []Lit{{S: "new-relic"}, {S: "new_relic"}, {S: "newrelic"}}},
		{rx: `(?:^|[\s"'])(?:pass|pw)=\S+`, lits: []Lit{{S: "pass="}, {S: "pw="}}, gaps: 1, edge: true},
		{rx: `(?i)пароль=\S+`, lits: []Lit{{S: "пар", Fold: true}}}, // cut at 'о': U+1C82 folds to it
		{rx: `(?s)ab.cd`, lits: []Lit{{S: "ab"}}, gaps: 1},
		// not provable: whole-text
		{rx: `[0-9]{8,10}:[A-Za-z0-9_-]{35}`},      // no literal
		{rx: `"key"[^"]*"value"`},                  // unbounded class that can cross lines
		{rx: `a\w{3}`},                             // literal too short
		{rx: `-----BEGIN KEY-----\n[A-Za-z]+`},     // required literal spans a line break
		{rx: `(?:foo|[a-z]{3})bar\d+[A-Z]{2}=\S*`}, // alternation with a literal-free branch; "bar" still required
	}
	for _, c := range cases {
		p := Analyze(regexp.MustCompile(c.rx))
		if c.rx == `(?:foo|[a-z]{3})bar\d+[A-Z]{2}=\S*` {
			if p == nil || !reflect.DeepEqual(p.Lits, []Lit{{S: "bar"}}) {
				t.Errorf("%s: plan = %+v, want literal bar", c.rx, p)
			}
			continue
		}
		if c.lits == nil {
			if p != nil {
				t.Errorf("%s: got plan %+v, want whole-text", c.rx, p)
			}
			continue
		}
		if p == nil {
			t.Errorf("%s: no plan, want lits %v", c.rx, c.lits)
			continue
		}
		if !reflect.DeepEqual(p.Lits, c.lits) || p.Gaps != c.gaps || p.EdgeCheck != c.edge {
			t.Errorf("%s: got lits=%v gaps=%d edge=%v, want lits=%v gaps=%d edge=%v",
				c.rx, p.Lits, p.Gaps, p.EdgeCheck, c.lits, c.gaps, c.edge)
		}
	}
}

// equivalencePatterns mix the shapes real rules use with ones chosen to stress the proof: text
// anchors, multi-line whitespace gaps, newline-capable classes, case folding, non-ASCII literals.
var equivalencePatterns = []string{
	`(?i)(?:password|passwd|(?:^|[\s_."'\-])(?:pass|pw))["']?\s*[=:]\s*["']?([^"'\s,;]{4,64})`,
	`\b(sk-[A-Za-z0-9]{8})(?:[^A-Za-z0-9_\-]|$)`,
	`\bAC[a-f0-9]{8}\b`,
	`(?m)^key=(\w+)$`,
	`^key=\w+`,
	`key=\w+$`,
	`(?i)token\s{0,3}:\s*\w{4,}`,
	`foo[^x]bar`,
	`(?s)ab.cd`,
	`ab\ncd`,
	`(?i)пароль\s*=\s*\S+`,
	`(?i)contraseña[=:]\w+`,
	`(?i)secret_?key\W{0,2}\w{4,}`,
	`(?:api|app)[_-]?key\s*=\s*"?(\w{4,})"?`,
	`(key)+=\w+`,
	`(?i)k[e3]y=\w+`,
	`\A\s*key`,
	`bar\s*\z`,
	`(?i)(?:^|\s)-p(\S{4,})`,
	`Ñandú=\w+`,
}

var fragments = []string{
	"password", "PASSWORD", "Passwd", "pass", "pw", "PW", "-p", "-P", "sk-abcdEFGH", "sk-12345678", "ACdeadbeef",
	"acdeadbeef", "key=value1", "key", "KEY", "k3y=zz", "=", ":", "\"", "'", ",", ";", "_", ".", "-", "x",
	"foo", "bar", "ab", "cd", "token", "Token", "secret_key", "SECRETKEY", "api_key", "app-key", "apikey",
	"hunter2abc", "S3cr3t!", "value", "\n", "\n", "\n\n", "\n \n", " ", "  ", "\t", "\r\n", "\f", "\v",
	"пароль", "ПАРОЛЬ", "Пароль", "парᲂль", "contraseña", "CONTRASEÑA", "Ñandú", "ñandú", "\u017f", "\u212a",
	"pa\u017f\u017f", "to\u212aen", "\u0130", "\xff", "é", "// comment", "#",
}

func randomText(r *rand.Rand) string {
	var b strings.Builder
	for n := r.Intn(40); n > 0; n-- {
		b.WriteString(fragments[r.Intn(len(fragments))])
	}
	return b.String()
}

func checkEquivalent(t *testing.T, set *Set, res []*regexp.Regexp, text string) {
	t.Helper()
	w := set.Prepare(text, "", "", nil)
	defer w.Release()
	for i, re := range res {
		for _, n := range []int{-1, 1, 2} {
			want := re.FindAllStringSubmatchIndex(text, n)
			got := w.FindAll(i, re, text, n)
			if len(want) == 0 && len(got) == 0 {
				continue
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("regex %q n=%d on %q:\n windowed %v\n whole    %v", re, n, text, got, want)
			}
		}
		if got, want := w.Match(i, re, text), re.MatchString(text); got != want {
			t.Fatalf("regex %q Match on %q: windowed %v, whole %v", re, text, got, want)
		}
	}
}

func compileAll(t testing.TB) (*Set, []*regexp.Regexp) {
	res := make([]*regexp.Regexp, len(equivalencePatterns))
	for i, p := range equivalencePatterns {
		res[i] = regexp.MustCompile(p)
	}
	return New(res), res
}

func TestWindowedEqualsWholeTextRandom(t *testing.T) {
	set, res := compileAll(t)
	planned := 0
	for i := range res {
		if set.Plan(i) != nil {
			planned++
		}
	}
	if planned < len(res)-2 {
		t.Fatalf("only %d of %d patterns are windowed; the test would not exercise the proof", planned, len(res))
	}
	r := rand.New(rand.NewSource(1))
	iters := 200000
	if testing.Short() {
		iters = 20000
	}
	for i := 0; i < iters; i++ {
		checkEquivalent(t, set, res, randomText(r))
	}
}

func TestWindowedEqualsWholeTextCases(t *testing.T) {
	set, res := compileAll(t)
	for _, text := range []string{
		"", "\n", "password=hunter2abc", "password\n\n\n=\n\n\nhunter2abc\n",
		"x\npassword =\n   hunter2abc\ny\n", "pass=abcd\npw: efgh\n", "a\nb\nc\nkey=v1\nd\ne\nkey=v2",
		"key=first\nkey=second\n", "\n\nkey=v", "sk-abcdEFGH", "sk-abcdEFGH\nsk-12345678\n",
		"ПАРОЛЬ = S3cr3t!\n", "x\u017f\npassword=hunter2abc\n", "CONTRASEÑA=abc\ncontraseña:def\n",
		"\u0130\nпароль=abc\nПАРОЛЬ=def\n", "\xff\nПАРОЛЬ=abc\n", "foo\nbar", "ab\ncd\nab\ncd", "bar \n\n",
		strings.Repeat("filler line\n", 50) + "token :\n\n abcd\n" + strings.Repeat("more\n", 50),
		strings.Repeat("pw=abcd ", 200),
	} {
		checkEquivalent(t, set, res, text)
	}
}

func FuzzWindowedEqualsWholeText(f *testing.F) {
	f.Add("password =\n hunter2abc\nkey=v1\n")
	f.Add("ПАРОЛЬ=abc\r\nsk-abcdEFGH\n")
	set, res := compileAll(f)
	f.Fuzz(func(t *testing.T, text string) {
		checkEquivalent(t, set, res, text)
	})
}
