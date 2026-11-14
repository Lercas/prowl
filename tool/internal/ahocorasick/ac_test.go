package ahocorasick

import (
	"math/rand"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func checkMatches(t *testing.T, patterns []string, text string) {
	t.Helper()
	m := New(patterns)
	if m.PatternCount() != len(patterns) {
		t.Fatal("pattern IDs changed")
	}
	got, want := make([]bool, len(patterns)), make([]bool, len(patterns))
	m.MatchInto(text, got)
	for id, pattern := range patterns {
		want[id] = pattern != "" && strings.Contains(text, pattern)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("patterns %q in %q: got %v, want %v", patterns, text, got, want)
	}
	// The detector uses the exposed tables directly in its fused byte scan.
	direct := make([]bool, len(patterns))
	var state int32
	for i := range len(text) {
		state = m.Transitions()[state<<8|int32(text[i])]
		for _, id := range m.Outputs()[state] {
			direct[id] = true
		}
	}
	if !reflect.DeepEqual(direct, want) {
		t.Fatal("direct table contract differs from MatchInto")
	}
}

func TestSuffixesOverlapsDuplicatesAndBinaryPatterns(t *testing.T) {
	patterns := []string{"he", "she", "his", "hers", "he", "", "a", "aa", "aaa", "\x00\xff", "пароль", "🔑"}
	for _, text := range []string{"", "ushers", "hishers", "aaaa", "\xff\x00\xff", "пароль=🔑", "SHE"} {
		checkMatches(t, patterns, text)
	}
	checkMatches(t, nil, "no patterns")
}

func TestRandomizedPatternsMatchSubstringOracle(t *testing.T) {
	rng := rand.New(rand.NewSource(1500))
	for range 100 {
		patterns := make([]string, rng.Intn(20))
		for i := range patterns {
			b := make([]byte, rng.Intn(8))
			for j := range b {
				b[j] = byte(rng.Intn(6))
			}
			patterns[i] = string(b)
		}
		text := make([]byte, 200)
		for i := range text {
			text[i] = byte(rng.Intn(6))
		}
		checkMatches(t, patterns, string(text))
	}
}

func TestConcurrentReadsAndCallerOwnedAccumulation(t *testing.T) {
	m := New([]string{"aws", "password", "token"})
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			present := make([]bool, m.PatternCount())
			for _, text := range []string{"aws", "password", "token", ""} {
				m.MatchInto(text, present)
			}
			if !reflect.DeepEqual(present, []bool{true, true, true}) {
				t.Error("MatchInto cleared caller-owned accumulated flags")
			}
		})
	}
	workers.Wait()
}
