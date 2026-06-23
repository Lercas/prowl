package taxonomy

import (
	"os"
	"path/filepath"
	"testing"
)

const gitleaksTOML = `title = "test"
[[rules]]
id = "aws-access-key"
description = "AWS Access Key"
regex = '''AKIA[0-9A-Z]{16}'''
keywords = ["AKIA"]
[[rules]]
id = "github-pat"
description = "GitHub PAT"
regex = '''ghp_[0-9A-Za-z]{36}'''
keywords = ["ghp_"]
entropy = 3.5
  [[rules.allowlists]]
  regexes = ['''EXAMPLE''']
  stopwords = ["sample"]
[allowlist]
paths = ['''test\.js$''']
stopwords = ["dummy"]
`

const trufflehogYAML = `detectors:
- name: GroqCloud
  keywords: [gsk_]
  regex:
    apikey: 'gsk_[A-Za-z0-9]{52}'
- name: TwoPattern
  keywords: [tp]
  regex:
    a: 'tpa_[0-9]{10}'
    b: 'tpb_[0-9]{10}'
`

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadGitleaks(t *testing.T) {
	tax, al, err := LoadGitleaks(write(t, "g.toml", gitleaksTOML))
	if err != nil {
		t.Fatal(err)
	}
	if len(tax.Types) != 2 {
		t.Fatalf("want 2 rules, got %d", len(tax.Types))
	}
	aws := tax.Types[0]
	if aws.ID != "aws_access_key" || aws.Source != "gitleaks" || aws.Category != "cloud" {
		t.Errorf("aws rule wrong: %+v", aws)
	}
	if aws.RE == nil || !aws.RE.MatchString("AKIA1234567890ABCDEF") {
		t.Error("aws regex did not compile/match")
	}
	if len(aws.Keywords) != 1 || aws.Keywords[0] != "akia" {
		t.Errorf("keywords not lowercased/attached: %v", aws.Keywords)
	}
	if tax.Types[1].Entropy != 3.5 {
		t.Errorf("entropy not parsed: %v", tax.Types[1].Entropy)
	}
	// allowlist merged from rule-level + global
	if !contains(al.Regexes, "EXAMPLE") || !contains(al.StopWords, "sample") ||
		!contains(al.StopWords, "dummy") || !contains(al.Paths, `test\.js$`) {
		t.Errorf("allowlist not merged: %+v", al)
	}
}

func TestLoadTrufflehog(t *testing.T) {
	tax, err := LoadTrufflehog(write(t, "th.yaml", trufflehogYAML))
	if err != nil {
		t.Fatal(err)
	}
	// GroqCloud (1 regex) + TwoPattern (2 regexes) = 3 rules
	if len(tax.Types) != 3 {
		t.Fatalf("want 3 rules, got %d", len(tax.Types))
	}
	var ids []string
	for _, s := range tax.Types {
		ids = append(ids, s.ID)
		if s.Source != "trufflehog" {
			t.Errorf("source not set: %+v", s)
		}
	}
	if !contains(ids, "groqcloud") || !contains(ids, "twopattern_a") || !contains(ids, "twopattern_b") {
		t.Errorf("ids wrong (multi-regex split): %v", ids)
	}
}

func TestLoadGitleaksSecretGroup(t *testing.T) {
	const toml = `title = "t"
[[rules]]
id = "grouped"
description = "Grouped Secret"
regex = '''(prefix)_(?:x)_([A-Za-z0-9]{40})'''
secretGroup = 2
keywords = ["prefix"]
`
	tax, _, err := LoadGitleaks(write(t, "grp.toml", toml))
	if err != nil {
		t.Fatal(err)
	}
	if len(tax.Types) != 1 {
		t.Fatalf("want 1 rule, got %d", len(tax.Types))
	}
	if got := tax.Types[0].Extract; got != 2 {
		t.Errorf("secretGroup not threaded into Extract: got %d, want 2", got)
	}
}

func TestLoadAnyAutodetect(t *testing.T) {
	if tax, _, _ := LoadAny(write(t, "x.toml", gitleaksTOML)); len(tax.Types) != 2 {
		t.Error("toml not routed to gitleaks loader")
	}
	if tax, _, _ := LoadAny(write(t, "x.yaml", trufflehogYAML)); len(tax.Types) != 3 {
		t.Error("yaml with detectors: not routed to trufflehog loader")
	}
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// --- regex-bomb guard (saferegex) + file-size cap ---

// TestGitleaksRegexBombSkipped proves a committed .gitleaks.toml with a giant-bound regex SKIPS that
// rule (saferegex refuses it) instead of OOMing, while a real AWS rule alongside it still compiles
// and fires — the no-over-correction proof in one test.
func TestGitleaksRegexBombSkipped(t *testing.T) {
	const toml = `title = "bomb"
[[rules]]
id = "good-aws"
description = "AWS Access Key"
regex = '''AKIA[0-9A-Z]{16}'''
[[rules]]
id = "bomb"
description = "Regex Bomb"
regex = '''a{1000000000}'''
`
	tax, _, err := LoadGitleaks(write(t, "bomb.toml", toml))
	if err != nil {
		t.Fatalf("LoadGitleaks should not error on a bomb rule (it's skipped): %v", err)
	}
	// The good AWS rule survived and matches; the bomb was skipped.
	var ids []string
	for _, st := range tax.Types {
		ids = append(ids, st.ID)
	}
	if len(tax.Types) != 1 || tax.Types[0].ID != "good_aws" {
		t.Fatalf("expected only the good AWS rule, got types=%v skipped=%v", ids, tax.Skipped)
	}
	if !tax.Types[0].RE.MatchString("AKIAIOSFODNN7EXAMPLE") {
		t.Error("real AWS detector should still fire")
	}
	if !contains(tax.Skipped, "bomb") {
		t.Errorf("bomb rule should be in Skipped, got %v", tax.Skipped)
	}
}

// TestTaxonomyRegexBombSkipped proves the Prowl-native taxonomy loader (Load) skips a giant-bound
// detection regex instead of OOMing.
func TestTaxonomyRegexBombSkipped(t *testing.T) {
	const y = `version: 1
types:
  - id: good_github
    detection:
      regex: 'ghp_[0-9A-Za-z]{36}'
  - id: bomb
    detection:
      regex: 'a{999999999}'
`
	tax, err := Load(write(t, "tax.yaml", y))
	if err != nil {
		t.Fatalf("Load should not error on a bomb type (it's skipped): %v", err)
	}
	if len(tax.Types) != 1 || tax.Types[0].ID != "good_github" {
		t.Fatalf("expected only good_github, got %d types skipped=%v", len(tax.Types), tax.Skipped)
	}
	if !tax.Types[0].RE.MatchString("ghp_16C7e42F292c6912E7710c838347Ae178B4a") {
		t.Error("real GitHub detector should still fire")
	}
}

// TestTaxonomyFileSizeCapRefused proves an oversized taxonomy/gitleaks file is refused (not slurped).
func TestTaxonomyFileSizeCapRefused(t *testing.T) {
	big := "# " + repeatStr("a", MaxFileSize+16) + "\nversion: 1\n"
	if _, err := Load(write(t, "huge.yaml", big)); err == nil {
		t.Fatal("expected Load to refuse an oversized taxonomy file, got nil")
	}
	if _, _, err := LoadGitleaks(write(t, "huge.toml", "# "+repeatStr("a", MaxFileSize+16))); err == nil {
		t.Fatal("expected LoadGitleaks to refuse an oversized .toml, got nil")
	}
}

func repeatStr(s string, n int) string {
	b := make([]byte, 0, n)
	for i := 0; i < n; i++ {
		b = append(b, s[0])
	}
	return string(b)
}
