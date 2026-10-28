package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func requireRuleLoadRefusal(t *testing.T, dir string) {
	t.Helper()
	if eng, err := Load(dir); err == nil || eng.Len() != 0 {
		t.Fatalf("invalid library reached the engine: count=%d err=%v", eng.Len(), err)
	}
	hasError := false
	for _, issue := range ValidateDir(dir) {
		hasError = hasError || issue.Level == "error"
	}
	if !hasError {
		t.Fatal("validation silently accepted invalid library integrity")
	}
}

func TestRuntimeAndValidationEnforceRuleLibraryIntegrity(t *testing.T) {
	for _, kind := range []string{"tampered", "unlisted", "missing", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			writeRuleFile(t, dir, "owned.yaml", awsTemplate)
			if _, err := GenerateManifest(dir); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "tampered":
				writeRuleFile(t, dir, "owned.yaml", strings.Replace(awsTemplate, "AKIA[0-9A-Z]{16}", "NEVER_MATCH_ZZZ", 1))
			case "unlisted":
				writeRuleFile(t, dir, "extra.yaml", strings.Replace(awsTemplate, "id: aws-key", "id: extra", 1))
			case "missing":
				writeRuleFile(t, dir, IntegrityManifestName, strings.Repeat("0", 64)+"  missing.yaml\n")
			case "malformed":
				writeRuleFile(t, dir, IntegrityManifestName, "not a manifest\n")
			}
			requireRuleLoadRefusal(t, dir)
		})
	}
}

func TestRuleManifestRejectsDuplicateAndUnsafePaths(t *testing.T) {
	for _, rel := range []string{"owned.yaml", "../outside.yaml", "/absolute.yaml", "a/../owned.yaml"} {
		t.Run(filepath.Base(rel), func(t *testing.T) {
			dir := t.TempDir()
			p := writeRuleFile(t, dir, "owned.yaml", awsTemplate)
			sum, err := hashFileBytes(p)
			if err != nil {
				t.Fatal(err)
			}
			line := sum + "  " + rel + "\n"
			if rel == "owned.yaml" {
				line = strings.Repeat("0", 64) + "  owned.yaml\n" + line
			}
			writeRuleFile(t, dir, IntegrityManifestName, line)
			if err := CheckIntegrity(dir, IntegrityPolicy{}); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
}

func TestRuleManifestPreservesFileNameBytes(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, " leading  spaces.yaml", awsTemplate)
	if n, err := GenerateManifest(dir); err != nil || n != 1 {
		t.Fatalf("generate: n=%d err=%v", n, err)
	}
	if err := CheckIntegrity(dir, IntegrityPolicy{}); err != nil {
		t.Fatalf("generated manifest changed filename bytes: %v", err)
	}
}

func TestRuleSnapshotChecksAndCompilesCapturedBytes(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "owned.yaml", awsTemplate)
	if _, err := GenerateManifest(dir); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readLibrarySnapshot(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	writeRuleFile(t, dir, "owned.yaml", strings.Replace(awsTemplate, "AKIA[0-9A-Z]{16}", "NEVER_MATCH_ZZZ", 1))
	if err := checkLibrarySnapshot(dir, IntegrityPolicy{}, snapshot); err != nil {
		t.Fatalf("unchanged captured bytes failed integrity: %v", err)
	}
	tpl, err := ParseTemplate(snapshot.files[0].raw, snapshot.files[0].path)
	if err != nil || len(tpl.Match("AKIANAFGYOEYPXU1DSYP", "akianafgyoeypxu1dsyp")) != 1 {
		t.Fatalf("captured matching rule changed after validation: template=%v err=%v", tpl, err)
	}
	requireRuleLoadRefusal(t, dir)
}

func TestRuleManifestSpecialPathsAndBounds(t *testing.T) {
	for _, kind := range []string{"escaping-link", "broken-link", "directory", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			writeRuleFile(t, dir, "owned.yaml", awsTemplate)
			manifest := filepath.Join(dir, IntegrityManifestName)
			switch kind {
			case "escaping-link", "broken-link":
				target := filepath.Join(t.TempDir(), "outside")
				if kind == "escaping-link" {
					writeRuleFile(t, filepath.Dir(target), filepath.Base(target), "")
				}
				if err := os.Symlink(target, manifest); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			case "directory":
				if err := os.Mkdir(manifest, 0o700); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				writeRuleFile(t, dir, IntegrityManifestName, "#"+strings.Repeat("x", MaxIntegrityManifestSize))
			}
			requireRuleLoadRefusal(t, dir)
		})
	}
}

func TestRuleLibraryBudgets(t *testing.T) {
	t.Run("actual-bytes", func(t *testing.T) {
		dir := t.TempDir()
		body := "#" + strings.Repeat("x", MaxTemplateSize-1)
		for i := 0; i < MaxLibraryBytes/MaxTemplateSize; i++ {
			writeRuleFile(t, dir, fmt.Sprintf("%04d.yaml", i), body)
		}
		if _, err := readLibrarySnapshot(dir, false); err != nil {
			t.Fatalf("exact byte budget rejected: %v", err)
		}
		writeRuleFile(t, dir, "overflow.yaml", "#")
		requireRuleLoadRefusal(t, dir)
	})
	t.Run("file-count", func(t *testing.T) {
		dir := t.TempDir()
		for i := 0; i < MaxLibraryFiles; i++ {
			writeRuleFile(t, dir, fmt.Sprintf("%05d.yaml", i), "")
		}
		if _, err := readLibrarySnapshot(dir, false); err != nil {
			t.Fatalf("exact file budget rejected: %v", err)
		}
		writeRuleFile(t, dir, "overflow.yaml", "")
		requireRuleLoadRefusal(t, dir)
	})
}
