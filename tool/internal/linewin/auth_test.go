package linewin

import (
	"math/rand"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func basicAuthRegex(t testing.TB) *regexp.Regexp {
	t.Helper()
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range tax.Types {
		if st.ID == "basic_auth_header" {
			return st.RE
		}
	}
	t.Fatal("missing basic_auth_header")
	return nil
}

func TestBasicAuthSelectiveAnchors(t *testing.T) {
	re := basicAuthRegex(t)
	set := New([]*regexp.Regexp{re})
	p := set.Plan(0)
	if p == nil || len(p.Lits) != 2 {
		t.Fatalf("expected both auth branches: %+v", p)
	}
	anchors := map[string]bool{}
	for _, l := range p.Lits {
		anchors[l.S] = true
	}
	if !anchors["authorization:"] || !anchors["@"] || anchors["//"] {
		t.Fatalf("incorrect auth anchors: %v", anchors)
	}
	// Ordinary source comments should not invoke this regex at all.
	comments := strings.Repeat("// comment with http://example.invalid/path\n", 5000)
	w := set.Prepare(comments, "", "", nil)
	if w == nil || w.state[0].full || len(w.wins[0]) != 0 {
		t.Fatal("comments generated auth windows")
	}
	w.Release()
	for _, value := range []string{
		"https://u:p@example.invalid/path",
		"https://пользователь:пароль@example.invalid/",
		"https://\xff:\xfe@example.invalid/",
		"Authorization: Basic YWRtaW46aHVudGVyMmFiYw==",
		"aUtHoRiZaTiOn:\n\nBasic\nYWRtaW46aHVudGVyMmFiYw==",
	} {
		text := comments + "\n" + value + "\n" + comments
		if !re.MatchString(value) {
			t.Fatal("fixture must exercise an auth match")
		}
		w := set.Prepare(text, "", "", nil)
		if w == nil || w.state[0].full || len(w.wins[0]) == 0 {
			t.Fatal("isolated auth match must stay windowed")
		}
		for _, n := range []int{-1, 0, 1, 2} {
			if got, want := w.FindAll(0, re, text, n), re.FindAllStringSubmatchIndex(text, n); !reflect.DeepEqual(got, want) {
				t.Fatalf("offsets or captures changed, limit=%d", n)
			}
		}
		w.Release()
	}
	// The new anchor must not impose a maximum credential length.
	long := "//" + strings.Repeat("u", 10000) + ":" + strings.Repeat("p", 10000) + "@"
	checkEquivalent(t, set, []*regexp.Regexp{re}, long)
	checkEquivalent(t, set, []*regexp.Regexp{re}, comments+" "+long+" "+comments)
	checkEquivalent(t, set, []*regexp.Regexp{re}, strings.Repeat("@", 50000))
}

func TestAtSignAnchorsPreserveBranchesAndEmptyMatches(t *testing.T) {
	patterns := []string{`@`, `@?`, `(?:foo|@)`, `@|`, `[^@]+@`, `//[^:@\s/]+:[^@\s/]+@`, `(?m)^@+$`, `@.*\z`, `@{1,3}`, `(?:a@|b@)?`}
	res := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		res[i] = regexp.MustCompile(p)
	}
	set := New(res)
	rng := rand.New(rand.NewSource(7391))
	parts := []string{"@", "//", ":", "foo", "b", "é", "\n", " ", "\xff", "Authorization: Basic YWRtaW46aHVudGVyMmFiYw=="}
	for trial := 0; trial < 3000; trial++ {
		var text strings.Builder
		for j := rng.Intn(50); j > 0; j-- {
			text.WriteString(parts[rng.Intn(len(parts))])
		}
		checkEquivalent(t, set, res, text.String())
	}
}

func FuzzBasicAuthWindows(f *testing.F) {
	re := basicAuthRegex(f)
	res := []*regexp.Regexp{re}
	set := New(res)
	f.Add("https://u:p@host Authorization: Basic YWRtaW46aHVudGVyMmFiYw==")
	f.Add("//é:密碼@\xff @ // http://host\n")
	f.Fuzz(func(t *testing.T, text string) {
		checkEquivalent(t, set, res, text)
	})
}

func BenchmarkBasicAuthComments(b *testing.B) {
	re := basicAuthRegex(b)
	set := New([]*regexp.Regexp{re})
	text := strings.Repeat("// comment with http://example.invalid/path\n", 24000) + "https://u:p@host"
	for _, mode := range []string{"whole", "windowed"} {
		b.Run(mode, func(b *testing.B) {
			b.SetBytes(int64(len(text)))
			b.ReportAllocs()
			for b.Loop() {
				var w *Windows
				if mode == "windowed" {
					w = set.Prepare(text, "", "", nil)
				}
				if len(w.FindAll(0, re, text, -1)) != 1 {
					b.Fatal("unexpected auth matches")
				}
				w.Release()
			}
		})
	}
}
