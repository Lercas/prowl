package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBoundedExtractionRemainsIncompleteAfterDeduplication(t *testing.T) {
	dir := t.TempDir()
	body := "id: owned-first\ninfo:\n  name: Owned first\n  severity: high\nmatchers:\n  - type: regex\n    regex:\n      - FIRST_[A-Za-z0-9]{12}\n---\nid: owned-late\ninfo:\n  name: Owned late\n  severity: high\nmatchers:\n  - type: regex\n    regex:\n      - LATE_[A-Za-z0-9]{12}\n"
	if err := os.WriteFile(filepath.Join(dir, "owned.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Repeat("FIRST_G7hJ9kL2mN5p ", 8) + "LATE_A6bC9dE2fG7h"
	hits, limited := eng.MatchN(text, 3)
	if !limited || len(hits) != 2 || hits[0].RuleID != "owned-first" || hits[1].RuleID != "owned-late" {
		t.Fatal("raw extraction limit was lost or prevented a later template from using the remaining budget")
	}
	full, limited := eng.MatchN(text, 100)
	if limited || len(full) != len(hits) {
		t.Fatal("normal duplicate extraction was changed or marked incomplete")
	}
	occurrences, limited := eng.MatchOccurrencesN(text, 3)
	if !limited || len(occurrences) != 3 || occurrences[0].RuleID != "owned-first" {
		t.Fatal("bounded occurrence extraction lost the released raw-count contract")
	}
	all, limited := eng.MatchOccurrencesN(text, 100)
	if limited || len(all) != 9 || all[8].RuleID != "owned-late" {
		t.Fatal("full occurrence extraction lost repeated credentials or the later rule")
	}
}

func TestBoundedExtractionRemainsIncompleteAfterEntropyFiltering(t *testing.T) {
	dir := t.TempDir()
	body := "id: owned-entropy\ninfo:\n  name: Owned entropy\n  severity: high\nmatchers:\n  - type: regex\n    regex:\n      - '[A-Za-z0-9]{12}'\n  - type: entropy\n    min: 3\n"
	if err := os.WriteFile(filepath.Join(dir, "owned.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Repeat("AAAAAAAAAAAA ", 8) + "G7hJ9kL2mN5pQ"
	hits, limited := eng.MatchN(text, 3)
	if !limited || len(hits) != 0 {
		t.Fatal("entropy-filtered bounded extraction was reported as complete")
	}
	full, limited := eng.MatchN(text, 100)
	if limited || len(full) != 1 {
		t.Fatal("unbounded fixture did not reveal the secret omitted by bounded extraction")
	}
}
