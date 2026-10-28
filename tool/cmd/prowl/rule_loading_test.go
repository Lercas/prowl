package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/rules"
)

func brokenRuleSet(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTemplate(t, dir, "owned-valid")
	bad := `id: broken
info: {name: Broken, severity: high}
matchers:
  - type: regex
    regex: ['[']
`
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRuleLoadFailuresCannotCreateCleanReportsOrBaselines(t *testing.T) {
	t.Setenv("PROWL_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	input := "prod.env"
	if err := os.WriteFile(input, []byte("owned-valid_abcdefgh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"partial", "tampered", "missing", "external", "taxonomy", "custom"} {
		t.Run(mode, func(t *testing.T) {
			args := []string{input, "--rules-only", "--format", "json", "--output", mode + ".json", "--write-baseline", mode + "-baseline.json", "--silence"}
			switch mode {
			case "partial":
				args = append(args, "--rules-dir", brokenRuleSet(t))
			case "tampered":
				dir := t.TempDir()
				writeTemplate(t, dir, "owned-valid")
				if _, err := rules.GenerateManifest(dir); err != nil {
					t.Fatal(err)
				}
				// A valid replacement used to disable the detector without a setup error.
				path := filepath.Join(dir, "owned-valid.yaml")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(raw), "owned-valid_", "replacement_")), 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--rules-dir", dir)
			case "missing":
				args = append(args, "--rules-dir", filepath.Join(t.TempDir(), "missing"))
			case "external":
				args = append(args, "--rules", filepath.Join(t.TempDir(), "missing.toml"))
			case "taxonomy":
				path := filepath.Join(t.TempDir(), "taxonomy.yaml")
				if err := os.WriteFile(path, []byte("version: 1\ntypes:\n  - id: broken\n    detection: {regex: '['}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				// --rules-only deliberately ignores --taxonomy, so test the selected taxonomy directly.
				args = []string{input, "--taxonomy", path, "--output", mode + ".json", "--write-baseline", mode + "-baseline.json", "--silence"}
			case "custom":
				path := filepath.Join(t.TempDir(), "config.yaml")
				if err := os.WriteFile(path, []byte("version: 1\ndetectors:\n  custom:\n    - id: broken\n      regex: '['\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--config", path)
			}
			if code := cmdScan(args); code != 2 {
				t.Errorf("%s rule failure returned %d", mode, code)
			}
			for _, file := range []string{mode + ".json", mode + "-baseline.json"} {
				if _, err := os.Stat(file); !os.IsNotExist(err) {
					t.Errorf("%s produced %s", mode, file)
				}
			}
		})
	}
}

func TestRuleLoadFailurePrecedesBucketAcquisition(t *testing.T) {
	fakeBucketCLI(t, "0")
	marker := filepath.Join(t.TempDir(), "started")
	t.Setenv("PROWL_BUCKET_STARTED", marker)
	if code := cmdBucket([]string{"s3://owned/prefix", "--rules-dir", brokenRuleSet(t), "--silence"}); code != 2 {
		t.Errorf("broken rules returned %d", code)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Error("acquired source with an incomplete rule set")
	}
}

func TestRuleQueriesRejectPartialLibraries(t *testing.T) {
	dir := brokenRuleSet(t)
	for _, args := range [][]string{{"list", dir}, {"stats", dir}, {"show", "owned-valid", "--rules", dir}, {"test", "owned-valid_abcdefgh", "--rules", dir}, {"search", "owned-valid", "--rules", dir}} {
		if code := cmdRules(args); code != 2 {
			t.Errorf("partial query %v returned %d", args, code)
		}
	}
}
