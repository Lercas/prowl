//go:build !race

package rules

import (
	"strings"
	"testing"
)

// Race instrumentation randomly discards sync.Pool entries; allocation budgets
// are measured only in ordinary builds, while behavior is also tested under race.
func TestWordIndexMissDoesNotAllocateLowercaseCopy(t *testing.T) {
	tpl := &Template{ID: "absent", Matchers: []Matcher{{Type: "word", Words: []string{"MISSING_ANCHOR"}}}}
	if err := tpl.compile(); err != nil {
		t.Fatal(err)
	}
	e := &Engine{templates: []*Template{tpl}}
	text := strings.Repeat("PUBLIC PAYLOAD;", 4096)
	e.Match(text)
	allocations := testing.AllocsPerRun(100, func() {
		if hits := e.Match(text); len(hits) != 0 {
			t.Fatal("missing anchor produced a hit")
		}
	})
	if allocations != 0 {
		t.Fatalf("warmed word-index miss allocated: %v", allocations)
	}
}
