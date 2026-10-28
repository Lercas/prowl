package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestIncompleteScanCannotWriteBaseline(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "baseline.json")
	c := model.NewCoverage()
	c.Note("max_size", "large.txt", true)
	flags := commonFlags{coverage: c, writeBaseline: p, format: "json", output: filepath.Join(dir, "report.json")}
	if reportFindings(flags, nil, 0) != 2 {
		t.Fatal("incomplete baseline accepted")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("baseline was created")
	}
}
func TestFailOnVerifiedCannotBeSuppressedByDisplayFilters(t *testing.T) {
	live := true
	f := model.Finding{Type: "stripe_secret", Severity: "high", Confidence: .1, Verified: &live, Fingerprint: "fp"}
	c := commonFlags{coverage: model.NewCoverage(), format: "json", output: filepath.Join(t.TempDir(), "report.json"), failOnVerified: true, disable: "stripe_secret", minConfidence: .99}
	if reportFindings(c, []model.Finding{f}, 0) != 1 {
		t.Fatal("live CI gate bypassed")
	}
}
func TestVerifiedOnlyIsExactlyLive(t *testing.T) {
	live, dead := true, false
	fs := []model.Finding{{Verified: &live}, {Verified: &dead}, {Severity: "critical"}, {Rationale: "verification inconclusive: timeout"}}
	got := keepVerified(fs)
	if len(got) != 1 || got[0].Verified == nil || !*got[0].Verified {
		t.Fatal("LIVE-only filter includes unresolved candidates")
	}
}
func TestMCPRequestIdentity(t *testing.T) {
	for _, raw := range []string{"{}", "[]", "true", "1.5", "null"} {
		if _, ok := mcpIDKey([]byte(raw)); ok {
			t.Fatal("invalid ID accepted")
		}
	}
	a, ok := mcpIDKey([]byte(`"a"`))
	b, okB := mcpIDKey([]byte(`"\u0061"`))
	if !ok || !okB || a != b {
		t.Fatal("equivalent string IDs differ")
	}
}

func TestServeRejectsUnsupportedStagesAndCorruptRulesBeforeListening(t *testing.T) {
	t.Setenv("PROWL_HOME", t.TempDir())
	for _, flag := range []string{"--ml", "--verify", "--verified-only", "--verify-all", "--semantic", "--reconstruct", "--show-secrets"} {
		if code := cmdServe([]string{flag}); code != 2 {
			t.Fatalf("worker ignored unsupported stage %s", flag)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("not: [valid"), 0600); err != nil {
		t.Fatal(err)
	}
	if code := cmdServe([]string{"--rules-dir", dir}); code != 2 {
		t.Fatal("worker started after dropping a rule load failure")
	}
}
