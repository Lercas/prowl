package linewin

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestGatedWindowsPreserveExtractionAndUnicodeFallback(t *testing.T) {
	re := regexp.MustCompile(`(?i)(password)[ \t]*:[ \t]*([A-Z0-9]{8,16})`)
	gate := regexp.MustCompile(`pa[sſ][sſ]word[ \t]*:[ \t]*[a-z0-9ſK]{8,16}`)
	set := New([]*regexp.Regexp{re})
	for _, text := range []string{"note 🚀\nPASSWORD: AB9CD123\n", "paſſword: AB9CD123", "password: short\nPASSWORD: AB9CD123", "ordinary no matches\npassword = nothing"} {
		lower := strings.ToLower(text)
		w := set.Prepare(text, "", "", []bool{true})
		for _, n := range []int{-1, 1, 2} {
			want := w.FindAll(0, re, text, n)
			if got := w.FindAllGated(0, re, gate, text, lower, n); !reflect.DeepEqual(got, want) {
				t.Fatal("ASCII gate changed captures/limits or Unicode fallback")
			}
			if got := w.FindAllGated(0, re, gate, text, strings.Repeat("x", len(text)), n); !reflect.DeepEqual(got, want) {
				t.Fatal("misaligned or incorrect lowercase view caused rejection")
			}
		}
		w.Release()
	}
}
