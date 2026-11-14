package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestReportRefusesFailedSuppressionPolicyWithoutReplacingArtifact(t *testing.T) {
	for _, kind := range []string{"explicit-missing", "explicit-malformed", "auto-baseline", "auto-ignore", "ignore-long-line", "wrong-type", "broken-link"} {
		t.Run(kind, func(t *testing.T) {
			t.Chdir(t.TempDir())
			c := commonFlags{format: "json", output: "report.json"}
			if err := os.WriteFile(c.output, []byte("previous owned artifact"), 0o600); err != nil {
				t.Fatal(err)
			}
			path, raw := ".prowl-baseline.json", "broken-json"
			switch kind {
			case "explicit-missing":
				c.baseline = "missing.json"
				path = ""
			case "explicit-malformed":
				path, c.baseline = "explicit.json", "explicit.json"
			case "auto-ignore":
				path, raw = ".gitleaksignore", "broken-fingerprint"
			case "ignore-long-line":
				path, raw = ".gitleaksignore", "a.env:owned:1\n"+strings.Repeat("x", 1024*1024+1)
			case "wrong-type":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				path = ""
			case "broken-link":
				if err := os.Symlink("missing.json", path); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
				path = ""
			}
			if path != "" {
				if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if code := reportFindings(c, []model.Finding{{Path: "a.env", Type: "owned", Line: 1}}, 0); code != 2 {
				t.Fatalf("invalid selected policy returned %d", code)
			}
			after, err := os.ReadFile(c.output)
			if err != nil || string(after) != "previous owned artifact" {
				t.Fatal("failed policy load replaced report")
			}
		})
	}
}

func TestReportChecksBothPoliciesBeforeSuppression(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile(".prowl-baseline.json", []byte(`["accepted"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".gitleaksignore", []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings := []model.Finding{{Fingerprint: "accepted"}, {Fingerprint: "novel"}}
	if code := reportFindings(commonFlags{format: "json", output: filepath.Join(".", "report.json")}, findings, 0); code != 2 {
		t.Fatalf("failed ignore ignored: %d", code)
	}
	if findings[0].Fingerprint != "accepted" || findings[1].Fingerprint != "novel" {
		t.Fatal("first policy mutated findings before second policy was validated")
	}
}

func TestReportWithoutOptionalPoliciesStillSucceeds(t *testing.T) {
	t.Chdir(t.TempDir())
	if code := reportFindings(commonFlags{format: "json", output: "report.json"}, nil, 0); code != 0 {
		t.Fatalf("genuinely absent automatic policies returned %d", code)
	}
}
