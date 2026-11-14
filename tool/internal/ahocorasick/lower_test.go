package ahocorasick

import (
	"reflect"
	"strings"
	"testing"
)

func checkLowerOracle(t *testing.T, text string, patterns []string) {
	t.Helper()
	for i := range patterns {
		patterns[i] = strings.ToLower(patterns[i])
	}
	m := New(patterns)
	got, want := make([]bool, len(patterns)), make([]bool, len(patterns))
	m.MatchLowerInto(text, got)
	m.MatchInto(strings.ToLower(text), want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("streaming lowercase differs: text=%q patterns=%q got=%v want=%v", text, patterns, got, want)
	}
}

func TestLowercaseMatchesStandardLibrary(t *testing.T) {
	for _, text := range []string{"", "AKIA password ToKeN", "ПАРОЛЬ=秘密", "İKΣſ", "I\xffKEY\xc0\x80", "🌍🔑"} {
		checkLowerOracle(t, text, []string{"AKIA", "PASSWORD", "token", "пароль", "秘密", "i", "k", "σ", "ſ", "s", "�", "🌍", ""})
	}
	m := New([]string{"token", "secret", "пароль"})
	present := make([]bool, 3)
	if n := testing.AllocsPerRun(100, func() { m.MatchLowerInto("TOKEN ПАРОЛЬ \xff secret", present) }); n != 0 {
		t.Fatalf("streaming lowercase allocated: %v", n)
	}
}

func FuzzLowercaseMatchesStandardLibrary(f *testing.F) {
	f.Add("İKΣſ TOKEN", "i\x00k\x00σ\x00token")
	f.Add("I\xffKEY", "�\x00key")
	f.Fuzz(func(t *testing.T, text, rawPatterns string) {
		if len(text) > 4096 || len(rawPatterns) > 128 {
			t.Skip()
		}
		patterns := strings.Split(rawPatterns, "\x00")
		if len(patterns) > 8 {
			t.Skip()
		}
		checkLowerOracle(t, text, patterns)
	})
}
