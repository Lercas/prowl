package linewin

import (
	"math/rand"
	"reflect"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestMatchByteProof(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		max     int // zero means no usable finite-width proof
	}{
		{`KEY[A-Z]{8}`, 11}, {`(?i)key`, 12}, {`KEY(?:[a-z]{2}|[a-z]{4})`, 7},
		{`KEY(?:[a-z]{2}){1,3}`, 9}, {`KEY.{1,3}`, 15}, {`KEY\b$`, 3},
		{`KEY[A-Z]+`, 0}, {`KEY[A-Z]*`, 0}, {`KEY` + strings.Repeat(`[A-Z]{1,1000}`, 6), 0},
	} {
		tree, err := syntax.Parse(tc.pattern, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := matchBytes(tree)
		if got != tc.max {
			t.Errorf("%s: bound=%d want=%d", tc.pattern, got, tc.max)
		}
	}
}

func TestMinifiedByteWindowsStayBounded(t *testing.T) {
	for _, tc := range []struct{ pattern, value string }{
		{`\bAC[a-f0-9]{32}\b`, "AC0123456789abcdef0123456789abcdef"},
		{`\bhf_[A-Za-z0-9]{34,}\b`, "hf_0123456789abcdef0123456789abcdef0123"},
		{`(?i)token\s*[=:]\s*[A-Za-z0-9]+`, "TOKEN = A1b2C3d4"},
		{`(?i)prefix[ſK][a-z]+`, "PREFIXStoken"},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			re := regexp.MustCompile(tc.pattern)
			set := New([]*regexp.Regexp{re})
			text := strings.Repeat("let filler=0;", 10000) + tc.value + ";" + strings.Repeat("var tail=0;", 10000)
			w := set.Prepare(text, "", "", nil)
			defer w.Release()
			if w == nil || w.state[0].full || !w.state[0].byteEdges || len(w.wins[0]) != 1 {
				t.Fatalf("minified input fell back to whole-text: %+v", w)
			}
			region := w.wins[0][0]
			if region[1]-region[0] > maxByteWindow {
				t.Fatal("isolated byte window exceeded its budget")
			}
			checkEquivalent(t, set, []*regexp.Regexp{re}, text)
		})
	}
}

func TestUnboundedAndOversizedMatchesRetainWholeTextFallback(t *testing.T) {
	for _, tc := range []struct{ pattern, text string }{
		{`KEY[A-Z]+`, strings.Repeat("A", 20000) + "KEY" + strings.Repeat("Z", 20000)},
		{`KEY` + strings.Repeat(`[A-Z]{1,1000}`, 6) + `END`, strings.Repeat("A", 20000) + "KEY" + strings.Repeat("Z", 5500) + "END;"},
		{`KEY.*END`, strings.Repeat("x", 20000) + "KEY" + strings.Repeat("z", 10000) + "END"},
	} {
		re := regexp.MustCompile(tc.pattern)
		set := New([]*regexp.Regexp{re})
		w := set.Prepare(tc.text, "", "", nil)
		if w != nil && !w.state[0].full {
			t.Fatal("unproven byte boundary must retain the whole-line fallback")
		}
		w.Release()
		checkEquivalent(t, set, []*regexp.Regexp{re}, tc.text)
	}
}

func TestArtificialByteEdgesCannotChangeAssertionsOrGreediness(t *testing.T) {
	for _, tc := range []struct {
		pattern, text string
		lo, hi        int
	}{
		{`\bKEY[A-Z]+`, "xKEYABC", 1, 7},
		{`KEY[A-Z]+`, "KEYABCZZ", 0, 6},
		{`^KEY[A-Z]+`, "xKEYABC", 1, 7},
		{`KEY[A-Z]+$`, "KEYABCxx", 0, 6},
	} {
		re := regexp.MustCompile(tc.pattern)
		set := New([]*regexp.Regexp{re})
		w := &Windows{set: set, state: []winState{{byteEdges: true}}, wins: [][][2]int{{{tc.lo, tc.hi}}}}
		if got, want := w.FindAll(0, re, tc.text, -1), re.FindAllStringSubmatchIndex(tc.text, -1); !reflect.DeepEqual(got, want) {
			t.Fatalf("artificial edge changed match: %s got=%v want=%v", tc.pattern, got, want)
		}
		if got, want := w.Match(0, re, tc.text), re.MatchString(tc.text); got != want {
			t.Fatalf("artificial edge changed predicate: %s", tc.pattern)
		}
	}
}

func TestByteWindowsPreserveUnicodeAndMalformedBytes(t *testing.T) {
	re := regexp.MustCompile(`(?i)пароль=([\pL]{4,8})`)
	set := New([]*regexp.Regexp{re})
	for _, text := range []string{
		strings.Repeat("é🌍", 5000) + ";ПАРОЛЬ=секрет;" + strings.Repeat("秘密", 5000),
		strings.Repeat("\x80", 12000) + ";пароль=секрет;" + strings.Repeat("\xff", 12000),
	} {
		checkEquivalent(t, set, []*regexp.Regexp{re}, text)
	}
	text := "a🌍é秘密z"
	for pos := range len(text) + 1 {
		start := runeBoundaryBefore(text, pos)
		if start > pos || pos-start >= utf8.UTFMax || !utf8.ValidString(text[:start]) {
			t.Fatalf("invalid UTF-8 boundary: pos=%d start=%d", pos, start)
		}
	}
}

func TestByteWindowsMergeWithLongLineFallback(t *testing.T) {
	re := regexp.MustCompile(`KEY[A-Z]+`)
	set := New([]*regexp.Regexp{re})
	text := strings.Repeat("a;", 4000) + "KEYABC;KEYDEF;KEY" + strings.Repeat("Z", 12000)
	checkEquivalent(t, set, []*regexp.Regexp{re}, text)
}

func TestFiniteByteWindowsAlignContextAndSupportLongest(t *testing.T) {
	re := regexp.MustCompile(`KEY([A-Z]{4}|[A-Z]{8})`)
	re.Longest()
	set := New([]*regexp.Regexp{re})
	for _, filler := range []string{"🌍", "\x80"} {
		for padding := range 4 {
			text := strings.Repeat(filler, 5000) + strings.Repeat("a", padding) + "KEYABCDEFGH" + strings.Repeat(filler, 5000)
			w := set.Prepare(text, "", "", nil)
			if w == nil || w.state[0].full || !w.state[0].byteEdges {
				t.Fatal("finite-width pattern did not exercise a byte window")
			}
			if utf8.ValidString(text) {
				for _, region := range w.wins[0] {
					if !utf8.ValidString(text[region[0]:region[1]]) {
						t.Fatal("context boundary split a valid UTF-8 rune")
					}
				}
			}
			w.Release()
			checkEquivalent(t, set, []*regexp.Regexp{re}, text)
		}
	}
}

func TestMinifiedWindowParityRandom(t *testing.T) {
	set, res := compileAll(t)
	rng := rand.New(rand.NewSource(1500))
	iterations := 1000
	if testing.Short() {
		iterations = 100
	}
	for range iterations {
		text := strings.Repeat("var filler=0;", 200+rng.Intn(100)) + randomText(rng) + ";" + strings.Repeat("let tail=1;", 200+rng.Intn(100))
		checkEquivalent(t, set, res, text)
	}
}

func FuzzMinifiedWindowParity(f *testing.F) {
	f.Add("KEY=abcd;password=secret123;hf_0123456789abcdef0123456789abcdef0123;")
	f.Add("\xff ПАРОЛЬ=секрет\n token :\nabc")
	patterns := []string{`\bAC[a-f0-9]{8}\b`, `(?i)token\s*[:=]\s*([a-z0-9]{4,32})`,
		`\bKEY[A-Z]+`, `(?m)^key=(\w+)$`, `(?i)пароль=([\pL]{4,8})`}
	res := make([]*regexp.Regexp, len(patterns))
	for i, pattern := range patterns {
		res[i] = regexp.MustCompile(pattern)
	}
	set := New(res)
	f.Fuzz(func(t *testing.T, middle string) {
		if len(middle) > 2048 {
			t.Skip()
		}
		text := strings.Repeat("x=0;", 128) + middle + ";" + strings.Repeat("y=1;", 128)
		checkEquivalent(t, set, res, text)
	})
}
