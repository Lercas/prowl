package rules

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateInstallsTheSourceBytesCapturedForValidation(t *testing.T) {
	source, target := t.TempDir(), t.TempDir()
	original := minimalRule("owned")
	writeRuleFile(t, source, "owned.yaml", original)
	_, err := Update(UpdateOpts{Source: source, Target: target, Validate: func(dir string) error {
		if err := ValidateForUpdate(dir); err != nil {
			return err
		}
		// Model an independent editor changing the public source after the validator read it.
		return os.WriteFile(filepath.Join(source, "owned.yaml"), []byte(minimalRule("replacement")), 0o600)
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(target, "owned.yaml"))
	if err != nil || string(raw) != original {
		t.Fatalf("installed bytes differ from those captured for validation: err=%v", err)
	}
}

func TestUpdateCheckOwnsAnIndependentValidationCopy(t *testing.T) {
	source := t.TempDir()
	target := filepath.Join(t.TempDir(), "not-created")
	body := minimalRule("owned")
	writeRuleFile(t, source, "owned.yaml", body)
	res, err := Update(UpdateOpts{Source: source, Target: target, Check: true, Validate: func(dir string) error {
		if err := ValidateForUpdate(dir); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(source, "owned.yaml"), []byte(minimalRule("replacement")), 0o600)
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = res.Close() })
	if res.StagedDir == source || res.StagedDir == "" {
		t.Fatal("check returned the public source instead of an owned snapshot")
	}
	raw, err := os.ReadFile(filepath.Join(res.StagedDir, "owned.yaml"))
	if err != nil || string(raw) != body {
		t.Fatalf("check snapshot is absent or changed: %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("check created its target")
	}
	if err := res.Close(); err != nil {
		t.Fatal(err)
	}
	if err := res.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(res.StagedDir); !os.IsNotExist(err) {
		t.Fatal("owned check snapshot was not cleaned")
	}
	if _, err := os.Stat(filepath.Join(source, "owned.yaml")); err != nil {
		t.Fatal("closing the snapshot changed the public source")
	}
}

func TestUpdatePreflightsEveryDestinationBeforeWriting(t *testing.T) {
	for _, parentLink := range []bool{false, true} {
		t.Run(map[bool]string{false: "leaf", true: "parent"}[parentLink], func(t *testing.T) {
			source, target, outside := t.TempDir(), t.TempDir(), t.TempDir()
			writeRuleFile(t, source, "a.yaml", minimalRule("first"))
			writeRuleFile(t, source, "z/owned.yaml", minimalRule("last"))
			if err := os.WriteFile(filepath.Join(outside, "owned.yaml"), []byte("outside sentinel"), 0o600); err != nil {
				t.Fatal(err)
			}
			var err error
			if parentLink {
				err = os.Symlink(outside, filepath.Join(target, "z"))
			} else {
				if err = os.Mkdir(filepath.Join(target, "z"), 0o700); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(filepath.Join(outside, "owned.yaml"), filepath.Join(target, "z/owned.yaml"))
			}
			if err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if _, err := Update(UpdateOpts{Source: source, Target: target}); err == nil {
				t.Fatal("linked destination accepted")
			}
			if _, err := os.Stat(filepath.Join(target, "a.yaml")); !os.IsNotExist(err) {
				t.Fatal("prefix of the library installed before destination refusal")
			}
			raw, err := os.ReadFile(filepath.Join(outside, "owned.yaml"))
			if err != nil || string(raw) != "outside sentinel" {
				t.Fatal("destination refusal modified the outside sentinel")
			}
		})
	}
}

func TestUpdateRefusesOversizedSchemaBeforeValidationOrMutation(t *testing.T) {
	source := t.TempDir()
	target := filepath.Join(t.TempDir(), "not-created")
	writeRuleFile(t, source, "owned.yaml", minimalRule("owned"))
	if err := os.WriteFile(filepath.Join(source, "SCHEMA.md"), []byte(strings.Repeat("x", MaxUpdateSchemaSize+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	validated := false
	_, err := Update(UpdateOpts{Source: source, Target: target, Validate: func(string) error {
		validated = true
		return nil
	}})
	if err == nil || validated {
		t.Fatal("oversized source reached validation or installation")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("oversized source created the target")
	}
}

func TestUpdateCancellationBeforeCaptureLeavesTargetAbsent(t *testing.T) {
	source := t.TempDir()
	target := filepath.Join(t.TempDir(), "not-created")
	writeRuleFile(t, source, "owned.yaml", minimalRule("owned"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Update(UpdateOpts{Source: source, Target: target, Ctx: ctx}); err == nil {
		t.Fatal("cancelled update succeeded")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("cancelled update created the target")
	}
}

func TestUpdateRejectsChangesToItsValidationSnapshot(t *testing.T) {
	source := t.TempDir()
	target := filepath.Join(t.TempDir(), "not-created")
	writeRuleFile(t, source, "owned.yaml", minimalRule("owned"))
	_, err := Update(UpdateOpts{Source: source, Target: target, Validate: func(dir string) error {
		if err := ValidateForUpdate(dir); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, "owned.yaml"), []byte("id: [broken\n"), 0o600)
	}})
	if err == nil {
		t.Fatal("a modified validation snapshot was installed without validation")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("refused validation snapshot mutated the target")
	}
}

func TestUpdateKeepsTheSelectedTargetDirectory(t *testing.T) {
	source, parent := t.TempDir(), t.TempDir()
	selected, moved := filepath.Join(parent, "selected"), filepath.Join(parent, "moved")
	if err := os.Mkdir(selected, 0o700); err != nil {
		t.Fatal(err)
	}
	body := minimalRule("owned")
	writeRuleFile(t, source, "owned.yaml", body)
	_, err := Update(UpdateOpts{Source: source, Target: selected, Validate: func(dir string) error {
		if err := ValidateForUpdate(dir); err != nil {
			return err
		}
		if err := os.Rename(selected, moved); err != nil {
			return err
		}
		return os.Mkdir(selected, 0o700)
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(selected, "owned.yaml")); !os.IsNotExist(err) {
		t.Fatal("installation followed a replacement of the target pathname")
	}
	raw, err := os.ReadFile(filepath.Join(moved, "owned.yaml"))
	if err != nil || string(raw) != body {
		t.Fatalf("installation left the selected target directory: err=%v", err)
	}
}

func TestUpdatePreservesHardlinksToPreviousTemplates(t *testing.T) {
	source, target := t.TempDir(), t.TempDir()
	outside := filepath.Join(t.TempDir(), "owned-sentinel")
	writeRuleFile(t, source, "owned.yaml", minimalRule("owned"))
	if err := os.WriteFile(outside, []byte("preserve outside sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(target, "owned.yaml")); err != nil {
		t.Skipf("hardlinks unavailable: %v", err)
	}
	if _, err := Update(UpdateOpts{Source: source, Target: target}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(outside)
	if err != nil || string(raw) != "preserve outside sentinel" {
		t.Fatalf("template installation changed another hardlink: err=%v", err)
	}
}
