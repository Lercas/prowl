package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateFileUsesLoadingContract(t *testing.T) {
	for _, body := range []string{
		"performance:\n  ml_threshold: .nan\n",
		"detectors: [\n",
		"version: 1\n---\nversion: 2\n",
		"detectors:\n  custom: [{id: owned, regex: '.*'}]\nunknown: true\n",
	} {
		problems, err := ValidateFile(writeCfg(t, body))
		if err != nil || len(problems) == 0 {
			t.Fatalf("policy error did not become validation problems: %v %v", problems, err)
		}
		if strings.Contains(body, "unknown:") && len(problems) != 2 {
			t.Fatalf("fatal load lost unknown-key validation: %v", problems)
		}
	}
	for _, body := range []string{"version: 1\n", "version: 1\n---\n# empty\n", ""} {
		if problems, err := ValidateFile(writeCfg(t, body)); err != nil || len(problems) != 0 {
			t.Fatalf("valid configuration rejected: %v %v", problems, err)
		}
	}
}

func TestValidateFileRejectsOversizedAndNonregularInputs(t *testing.T) {
	dir := t.TempDir()
	large := filepath.Join(dir, "large.yaml")
	if err := os.WriteFile(large, []byte("#"+strings.Repeat(" ", MaxConfigSize)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{large, dir, filepath.Join(dir, "missing")} {
		if problems, err := ValidateFile(path); err == nil || len(problems) != 0 {
			t.Fatalf("unreadable configuration became valid/problems: %v %v", problems, err)
		}
	}
	boundary := writeCfg(t, "#"+strings.Repeat(" ", MaxConfigSize-1))
	if problems, err := ValidateFile(boundary); err != nil || len(problems) != 0 {
		t.Fatalf("exact byte cap rejected: %v %v", problems, err)
	}
}
