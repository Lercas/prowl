package rules

import (
	"maps"
	"os"
	"path/filepath"
	"testing"
)

func TestUpdateCheckUsesActualInstalledFiles(t *testing.T) {
	for _, change := range []string{"modified", "missing", "extra", "schema", "version", "integrity", "missing-integrity"} {
		t.Run(change, func(t *testing.T) {
			source, target := t.TempDir(), t.TempDir()
			writeRuleFile(t, source, "owned.yaml", minimalRule("owned"))
			writeRuleFile(t, source, "SCHEMA.md", "original schema\n")
			if _, err := Update(UpdateOpts{Source: source, Target: target}); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "modified":
				writeRuleFile(t, target, "owned.yaml", "id: [broken\n")
			case "missing":
				if err := os.Rename(filepath.Join(target, "owned.yaml"), filepath.Join(t.TempDir(), "saved.yaml")); err != nil {
					t.Fatal(err)
				}
			case "extra":
				writeRuleFile(t, target, "extra.yaml", minimalRule("extra"))
			case "schema":
				writeRuleFile(t, target, "SCHEMA.md", "changed schema\n")
			case "version":
				writeRuleFile(t, source, "VERSION", "v-new\n")
			case "integrity":
				writeRuleFile(t, target, IntegrityManifestName, "broken checksum\n")
			case "missing-integrity":
				if err := os.Rename(filepath.Join(target, IntegrityManifestName), filepath.Join(t.TempDir(), "saved.sha256")); err != nil {
					t.Fatal(err)
				}
			}
			before := inventoryContents(t, target)
			res, err := Update(UpdateOpts{Source: source, Target: target, Check: true})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = res.Close() })
			if res.NoChange {
				t.Fatal("check reported current library despite physical or metadata drift")
			}
			if after := inventoryContents(t, target); !maps.Equal(before, after) {
				t.Fatal("check mutated installed files or metadata")
			}
			if change == "modified" && (len(res.Changed) != 1 || res.Changed[0] != "owned.yaml") ||
				change == "missing" && (len(res.Added) != 1 || res.Added[0] != "owned.yaml") ||
				change == "extra" && (len(res.Removed) != 1 || res.Removed[0] != "extra.yaml") ||
				change == "schema" && (len(res.Changed) != 1 || res.Changed[0] != "SCHEMA.md") {
				t.Fatal("check diff does not describe the actual managed files")
			}
			if _, err := Update(UpdateOpts{Source: source, Target: target}); err != nil {
				t.Fatal(err)
			}
			stable, err := Update(UpdateOpts{Source: source, Target: target, Check: true, Now: "different timestamp"})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stable.Close() }()
			if !stable.NoChange {
				t.Fatal("repaired target did not become current")
			}
		})
	}
}

func TestEmptyLibraryCheckDistinguishesAbsentIntegrityFromAnEmptyManifest(t *testing.T) {
	source, target := t.TempDir(), t.TempDir()
	if _, err := Update(UpdateOpts{Source: source, Target: target}); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(target, IntegrityManifestName), filepath.Join(t.TempDir(), "saved.sha256")); err != nil {
		t.Fatal(err)
	}
	res, err := Update(UpdateOpts{Source: source, Target: target, Check: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Close() }()
	if res.NoChange || !res.MetadataChanged || res.Manifest.Count != 0 {
		t.Fatal("absent integrity manifest was treated as a present empty one")
	}
}

func inventoryContents(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		out[path] = string(raw)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestUpdateWritesIntegrityForItsValidatedSnapshot(t *testing.T) {
	source, target := t.TempDir(), t.TempDir()
	body := minimalRule("owned")
	writeRuleFile(t, source, "nested/owned.yaml", body)
	if _, err := Update(UpdateOpts{Source: source, Target: target, Validate: func(dir string) error {
		if err := ValidateForUpdate(dir); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(source, "nested/owned.yaml"), []byte(minimalRule("replacement")), 0o600)
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, IntegrityManifestName)); err != nil {
		t.Fatalf("installed snapshot has no integrity manifest: %v", err)
	}
	if err := CheckIntegrity(target, IntegrityPolicy{}); err != nil {
		t.Fatal(err)
	}
}
