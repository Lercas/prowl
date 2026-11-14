package linewin

import (
	"math/rand"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestStructuralProofBranches(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		planned bool
	}{
		{`[0-9]{8,10}:[A-Za-z0-9_-]{35}`, true},
		{`[0-9a-f]{8}-[0-9a-f]{4}`, true},
		{`(?:[0-9]{8}:|[a-f]{8}\.)[a-z]+`, true},
		{`([0-9]{8}:){1,3}`, true},
		{`([0-9]{8}:)?[a-z]+`, false},
		{`([0-9]{8}:)*[a-z]+`, false},
		{`[0-9]{8}:|[a-z]+`, false},
		{`[0-9]{7}:[a-z]+`, false},
		{`(?i)[a-z]{8}:[a-z]+`, false}, // Unicode fold partners are not ASCII bytes
		{`[a-zé]{8}:[a-z]+`, false},
	} {
		p := Analyze(regexp.MustCompile(tc.pattern))
		if (p != nil) != tc.planned {
			t.Errorf("%s: plan=%+v, want planned=%v", tc.pattern, p, tc.planned)
		}
	}
}

func TestStructuralTriggerParity(t *testing.T) {
	patterns := []string{
		`\b([0-9]{8,10}:[A-Za-z0-9_-]{35})(?:[^A-Za-z0-9_-]|$)`,
		`\b([MNO][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})(?:[^A-Za-z0-9_-]|$)`,
		`\b[a-z]{8}:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
		`\b[a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8}\b`,
		`(?:[0-9]{8}:|[a-f]{8}\.)([a-z]+)`,
		`[0-9]{100}:[a-z]+`, // capped guard still proves a mandatory suffix
	}
	values := []string{
		"123456789:" + strings.Repeat("A", 35),
		"M" + strings.Repeat("a", 23) + ".abc123." + strings.Repeat("b", 30),
		"abcdefgh:01234567-89ab-cdef-0123-456789abcdef",
		strings.Repeat("a", 32) + "-01234567-89abcdef",
		"12345678:abc abcdefab.xyz",
		strings.Repeat("1", 100) + ":value",
	}
	res := make([]*regexp.Regexp, len(patterns))
	for i, pattern := range patterns {
		res[i] = regexp.MustCompile(pattern)
	}
	set := New(res)
	for i := range res {
		if set.Plan(i) == nil || len(set.Plan(i).triggers) == 0 {
			t.Fatalf("missing structural plan for %s", patterns[i])
		}
	}
	filler := strings.Repeat("x.y:z-/=; ", 2000)
	text := filler + "\xff " + strings.Join(values, " ; ") + " ; " + filler + strings.Join(values, "\n")
	checkEquivalent(t, set, res, text)
	rng := rand.New(rand.NewSource(92841))
	for trial := 0; trial < 2000; trial++ {
		var b strings.Builder
		for j := 0; j < 15; j++ {
			value := values[rng.Intn(len(values))]
			if rng.Intn(3) == 0 {
				value = value[rng.Intn(len(value)):]
			}
			b.WriteString(value)
			b.WriteString([]string{" ", "\xff", "é", "_", "\n", ":", ""}[rng.Intn(7)])
		}
		checkEquivalent(t, set, res, b.String())
	}
	// Ordinary punctuation must not create windows, including short class runs.
	w := set.Prepare(filler+"1234567:abc", "", "", nil)
	defer w.Release()
	for i := range res {
		if w == nil || w.state[i].full || len(w.wins[i]) != 0 {
			t.Fatalf("unguarded punctuation built regions for %s", patterns[i])
		}
	}
	// Long minified input must retain exact submatch offsets and output limits.
	w = set.Prepare(text, "", "", nil)
	defer w.Release()
	for i, re := range res {
		if w == nil || w.state[i].full || len(w.wins[i]) == 0 {
			t.Fatalf("isolated tokens did not produce windows: %s", patterns[i])
		}
		for _, n := range []int{-1, 0, 1, 2, 5} {
			if got, want := w.FindAll(i, re, text, n), re.FindAllStringSubmatchIndex(text, n); !reflect.DeepEqual(got, want) {
				t.Fatalf("%s n=%d: got %v want %v", patterns[i], n, got, want)
			}
		}
	}
}

func FuzzStructuralTriggerParity(f *testing.F) {
	res := []*regexp.Regexp{
		regexp.MustCompile(`\b([0-9]{8,10}:[A-Za-z0-9_-]{35})(?:[^A-Za-z0-9_-]|$)`),
		regexp.MustCompile(`(?:[0-9]{8}:|[a-f]{8}\.)([a-z]+)`),
		regexp.MustCompile(`([a-f0-9]{8}-){1,3}[a-f0-9]{8}`),
	}
	set := New(res)
	f.Add("12345678:" + strings.Repeat("A", 35))
	f.Add("abcdefab.xyz 12345678:abc\xff01234567-89abcdef")
	f.Fuzz(func(t *testing.T, text string) {
		checkEquivalent(t, set, res, text)
	})
}

func BenchmarkStructuralAnchors(b *testing.B) {
	res := []*regexp.Regexp{
		regexp.MustCompile(`\b([0-9]{8,10}:[A-Za-z0-9_-]{35})\b`),
		regexp.MustCompile(`\b[MNO][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}\b`),
		regexp.MustCompile(`\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`),
	}
	text := strings.Repeat("const x={a:1,b:2}; x.y=x.z-1; ", 32768) + " 12345678:" + strings.Repeat("A", 35)
	set := New(res)
	for _, mode := range []string{"whole", "windowed"} {
		b.Run(mode, func(b *testing.B) {
			b.SetBytes(int64(len(text)))
			b.ReportAllocs()
			for b.Loop() {
				var w *Windows
				if mode == "windowed" {
					w = set.Prepare(text, "", "", nil)
				}
				for i, re := range res {
					if hits := w.FindAll(i, re, text, -1); (i == 0 && len(hits) != 1) || (i != 0 && len(hits) != 0) {
						b.Fatal("unexpected matches")
					}
				}
				w.Release()
			}
		})
	}
}
