package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadDeduplicatesRuleIDs: two templates sharing an id load as one (so the match isn't
// double-reported), and the duplicate is surfaced in the returned error.
func TestLoadDeduplicatesRuleIDs(t *testing.T) {
	dir := t.TempDir()
	tpl := func(name string) {
		body := `
id: dup-rule
info:
  name: dup
  severity: high
  tags: generic
matchers:
  - type: word
    words: ["AKIA"]
`
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tpl("a-first.yaml")  // lexically first -> kept
	tpl("b-second.yaml") // duplicate -> ignored

	e, err := Load(dir)
	if err == nil {
		t.Error("Load should surface the duplicate rule id as an error")
	} else if !strings.Contains(err.Error(), "duplicate rule id") {
		t.Errorf("error should mention the duplicate id, got: %v", err)
	}
	if e.Len() != 1 {
		t.Fatalf("duplicate rule id should load exactly one template (no double-report), got %d", e.Len())
	}
	// And the one kept template still works (only one hit, not two).
	if hits := e.Match(`k = "AKIA1234"`); len(hits) != 1 {
		t.Fatalf("expected exactly one hit from the de-duplicated rule, got %d: %+v", len(hits), hits)
	}
}

// TestEntropyOnlyTemplateRespectsFloor: an entropy-only template (sole matcher `type: entropy,
// min: X`) enforces the floor — plain prose below it yields no finding, high-entropy text yields one.
func TestEntropyOnlyTemplateRespectsFloor(t *testing.T) {
	const y = `
id: entropy-only
info:
  name: high entropy blob
  severity: high
  tags: generic
matchers:
  - type: entropy
    min: 4.5
`
	tpl, err := ParseTemplate([]byte(y), "entropy-only.yaml")
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{templates: []*Template{tpl}}

	// Plain English prose has Shannon entropy well under 4.5 -> no finding (the floor is enforced).
	prose := "The quick brown fox jumps over the lazy dog. This is an ordinary sentence with words."
	if hits := e.Match(prose); len(hits) != 0 {
		t.Fatalf("entropy-only template fired on low-entropy prose (entropy %.2f < 4.5): %+v", shannon(prose), hits)
	}

	// A long random-looking base64-ish blob has entropy above 4.5 -> exactly one whole-text finding.
	highEnt := "Zm9vYmFyMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVm" +
		"Z2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5Kw=="
	if shannon(highEnt) < 4.5 {
		t.Fatalf("test fixture entropy too low (%.2f); pick a higher-entropy string", shannon(highEnt))
	}
	hits := e.Match(highEnt)
	if len(hits) != 1 {
		t.Fatalf("entropy-only template should fire once on high-entropy text, got %+v", hits)
	}
	if hits[0].Value != highEnt {
		t.Errorf("entropy-only hit should span the whole text; got %q", hits[0].Value)
	}
}

// TestEntropyFloorOnExtractedValue: with a regex extractor plus an entropy floor, the floor still
// filters low-entropy captures.
func TestEntropyFloorOnExtractedValue(t *testing.T) {
	const y = `
id: tok-entropy
info:
  name: token with entropy floor
  severity: high
  tags: generic
matchers:
  - type: regex
    regex:
      - 'tok_[A-Za-z0-9]+'
  - type: entropy
    min: 4.0
`
	tpl, err := ParseTemplate([]byte(y), "tok.yaml")
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{templates: []*Template{tpl}}

	// Low-entropy match (all same char class, repetitive) -> filtered by the floor.
	if hits := e.Match("tok_aaaaaaaaaaaaaaaa"); len(hits) != 0 {
		t.Errorf("low-entropy token should be filtered by min:4.0 floor, got %+v", hits)
	}
	// High-entropy token -> reported.
	high := "tok_" + "aB3xQ9zP7mK2wL5vN8tR"
	if hits := e.Match(high); len(hits) != 1 || !strings.HasPrefix(hits[0].Value, "tok_") {
		t.Errorf("high-entropy token should be reported, got %+v", hits)
	}
}

// TestEngineMatchBounded: a dense file matching a permissive template many times must not make Match
// build an unbounded []Hit. Match is capped at MaxEngineMatches, and MatchN reports truncation and
// honors a smaller passed-in budget.
func TestEngineMatchBounded(t *testing.T) {
	dir := t.TempDir()
	// anchor-less generic regex -> always runs, fires once per distinct 40-char token
	body := "id: generic-blob\ninfo:\n  name: generic blob\n  severity: high\nmatchers:\n  - type: regex\n    regex:\n      - '[A-Za-z0-9]{40}'\n"
	if err := os.WriteFile(filepath.Join(dir, "g.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for i := 0; b.Len() < 8*1024*1024; i++ {
		b.WriteString("secret_key_")
		// distinct token: a 40-char run that differs per line so the per-value dedup can't collapse it
		var t [40]byte
		x := i
		for j := 0; j < 40; j++ {
			t[j] = byte('A' + x%26)
			x = x/26 + j
		}
		b.Write(t[:])
		b.WriteByte('\n')
	}
	text := b.String()

	// Match is bounded by the package default cap.
	if hits := eng.Match(text); len(hits) > MaxEngineMatches {
		t.Fatalf("Match not bounded: %d hits > %d", len(hits), MaxEngineMatches)
	}
	// MatchN honors a smaller passed-in budget and reports truncation.
	hits, trunc := eng.MatchN(text, 100)
	if len(hits) > 100 {
		t.Fatalf("MatchN exceeded its budget: %d > 100", len(hits))
	}
	if !trunc {
		t.Fatalf("MatchN should report truncation on a dense input far exceeding the budget")
	}
	// A zero/negative budget yields nothing.
	if hits, _ := eng.MatchN(text, 0); len(hits) != 0 {
		t.Fatalf("MatchN(_,0) should yield no hits, got %d", len(hits))
	}
}

func TestTemplateMatch(t *testing.T) {
	e, err := Load("../../rules/cloud/aws-access-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if e.Len() != 1 {
		t.Fatalf("want 1 template, got %d", e.Len())
	}
	// matches a real-shaped key (AND: word AKIA + regex + entropy)
	hits := e.Match(`aws_key = "AKIA1B2C3D4E5F6G7H8I"`)
	if len(hits) != 1 || hits[0].RuleID != "aws-access-key-id" || hits[0].Severity != "high" {
		t.Fatalf("expected 1 high hit, got %+v", hits)
	}
	if hits[0].Value != "AKIA1B2C3D4E5F6G7H8I" {
		t.Errorf("bad extracted value: %q", hits[0].Value)
	}
	// no AKIA word -> pre-filter skips, no hit
	if h := e.Match("just some random text without keys"); len(h) != 0 {
		t.Errorf("unexpected hits: %+v", h)
	}
}

func TestFilterByTagSeverity(t *testing.T) {
	e, _ := Load("../../rules/cloud/aws-access-key.yaml")
	if e.Filter(FilterOpts{Tags: []string{"gcp"}}).Len() != 0 {
		t.Error("tag filter should exclude aws rule for gcp tag")
	}
	e2, _ := Load("../../rules/cloud/aws-access-key.yaml")
	if e2.Filter(FilterOpts{Severities: []string{"high"}}).Len() != 1 {
		t.Error("severity filter should keep the high rule")
	}
}
