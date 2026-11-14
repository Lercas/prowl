package rules

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func wordTestEngine(t *testing.T) *Engine {
	t.Helper()
	e := &Engine{}
	for _, outer := range []string{"and", "or"} {
		for _, inner := range []string{"and", "or"} {
			for _, negative := range []bool{false, true} {
				for _, words := range [][]string{{"CONTEXT", "пароль"}, {"absent", "KEY"}, {"İ", "K", "Σ", "ſ"}, {"�"}, {""}} {
					tpl := &Template{ID: fmt.Sprintf("word-%d", len(e.templates)), MatchersCondition: outer,
						Matchers: []Matcher{{Type: "word", Words: words, Condition: inner, Negative: negative},
							{Type: "regex", Regex: []string{`TOKEN_[A-Z0-9]+`}}},
						Extractors: []Extractor{{Regex: []string{`TOKEN_[A-Z0-9]+`}}}}
					if err := tpl.compile(); err != nil {
						t.Fatal(err)
					}
					e.templates = append(e.templates, tpl)
				}
			}
		}
	}
	return e
}

// Reference evaluation deliberately bypasses both keyword and regex-window indices.
func referenceWordHits(e *Engine, text string, limit int) ([]Hit, bool) {
	if limit <= 0 {
		return nil, false
	}
	var hits []Hit
	truncated := false
	in := evaluation{text: text, lower: strings.ToLower(text)}
	for _, tpl := range e.templates {
		local, limited := tpl.matchN(in, limit-len(hits))
		hits = append(hits, local...)
		truncated = truncated || limited
		if len(hits) >= limit {
			return hits, true
		}
	}
	return hits, truncated
}

func TestWordIndexMatchesStandaloneEvaluation(t *testing.T) {
	e := wordTestEngine(t)
	for _, text := range []string{"", "CONTEXT ПАРОЛЬ TOKEN_ABC", "KEY TOKEN_ABC TOKEN_DEF", "İKΣſ TOKEN_ABC", "\xff TOKEN_ABC", "TOKEN_ABC", "plain text"} {
		for _, limit := range []int{0, 1, 3, 100} {
			want, wantLimited := referenceWordHits(e, text, limit)
			got, gotLimited := e.MatchN(text, limit)
			if !reflect.DeepEqual(got, want) || gotLimited != wantLimited {
				t.Fatalf("indexed words differ: text=%q limit=%d hits=%d/%d limited=%v/%v", text, limit, len(got), len(want), gotLimited, wantLimited)
			}
		}
	}
	// Rebuilding after filtering must assign word IDs against the new index.
	e.Filter(FilterOpts{IDs: []string{e.templates[0].ID, e.templates[len(e.templates)-1].ID}})
	text := "CONTEXT ПАРОЛЬ TOKEN_ABC"
	want, _ := referenceWordHits(e, text, 100)
	if got := e.Match(text); !reflect.DeepEqual(got, want) {
		t.Fatal("filtered engine reused stale word IDs")
	}
}

func TestWordIndexConcurrentScansDoNotSharePresenceFlags(t *testing.T) {
	e := wordTestEngine(t)
	texts := []string{"CONTEXT ПАРОЛЬ TOKEN_ABC", "TOKEN_DEF", "\xff TOKEN_123", "KEY TOKEN_456"}
	wants := make([][]Hit, len(texts))
	for i, text := range texts {
		wants[i], _ = referenceWordHits(e, text, 100)
	}
	var workers sync.WaitGroup
	for i, text := range texts {
		want := wants[i]
		workers.Go(func() {
			for range 50 {
				if got := e.Match(text); !reflect.DeepEqual(got, want) {
					t.Error("another scan changed word presence")
					return
				}
			}
		})
	}
	workers.Wait()
}
