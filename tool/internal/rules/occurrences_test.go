package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOccurrenceModePreservesSpansAndKeepsBudgetHonest(t *testing.T) {
	dir := t.TempDir()
	rule := `id: owned
info:
  name: owned
  severity: high
matchers:
  - type: regex
    regex: ['OWNED_[A-Za-z0-9]{12}']
extractors:
  - type: regex
    group: 0
    regex: ['OWNED_[A-Za-z0-9]{12}', 'OWNED_[A-Za-z0-9]{12}']
`
	if err := os.WriteFile(filepath.Join(dir, "owned.yaml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	text := "OWNED_Z7mV8qR3pL9s OWNED_Z7mV8qR3pL9s"
	defaultHits, limited := engine.MatchN(text, 10)
	if limited || len(defaultHits) != 1 {
		t.Fatal("default value-deduplication contract changed")
	}
	hits, limited := engine.MatchOccurrencesN(text, 10)
	if limited || len(hits) != 2 || hits[0].Start == hits[1].Start || hits[0].Value != hits[1].Value {
		t.Fatal("distinct occurrences or duplicate extractor handling failed")
	}
	hits, limited = engine.MatchOccurrencesN(text, 1)
	if !limited || len(hits) != 1 {
		t.Fatal("occurrence mode lost bounded extraction status")
	}
	hits, limited = engine.MatchOccurrencesN(text, 0)
	if limited || len(hits) != 0 {
		t.Fatal("zero occurrence budget was not honored")
	}
}
