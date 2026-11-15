package ahocorasick

import (
	"strings"
	"testing"
)

func TestContainsMatchesPatternPresence(t *testing.T) {
	patterns := []string{"he", "hers", "she", "his", "密码", ""}
	m := New(patterns)
	for _, text := range []string{"", "ordinary", "ushers", "HERS", "他的密码", "he\x00his"} {
		flags := make([]bool, len(patterns))
		m.MatchInto(text, flags)
		want := false
		for _, flag := range flags {
			want = want || flag
		}
		if m.Contains(text) != want {
			t.Fatal("early exit changed pattern presence")
		}
	}
}

func FuzzContainsLowerMatchesStandardLibrary(f *testing.F) {
	f.Add("İKΣſ PASSWORD \xff", "i\x00k\x00password\x00�")
	f.Fuzz(func(t *testing.T, text, raw string) {
		if len(text) > 8192 || len(raw) > 128 {
			return
		}
		patterns := strings.Split(strings.ToLower(raw), "\x00")
		m := New(patterns)
		flags := make([]bool, len(patterns))
		m.MatchInto(strings.ToLower(text), flags)
		want := false
		for _, v := range flags {
			want = want || v
		}
		if m.ContainsLower(text) != want {
			t.Fatal("early-exit lower predicate changed")
		}
	})
}
