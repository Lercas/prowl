package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/verify"
)

func TestInstalledQualificationNeverBlessesChangedFiles(t *testing.T) {
	for _, kind := range []string{"rules", "verifiers"} {
		for _, reblessed := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: "/changed", true: "/changed-checksum"}[reblessed], func(t *testing.T) {
				source, target := t.TempDir(), t.TempDir()
				opts := rules.UpdateOpts{Source: source, Target: target}
				if kind == "rules" {
					writeTemplate(t, source, "owned")
				} else {
					if err := os.WriteFile(filepath.Join(source, "owned.yaml"), []byte("id: owned\nmatch: [owned]\nrequests:\n  - url: https://owned.invalid/identity\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					opts.Validate = func(dir string) error { _, err := verify.Load(0, dir); return err }
				}
				res, err := rules.Update(opts)
				if err != nil {
					t.Fatal(err)
				}
				if err := validateInstalledLibrary(kind, target, res.Manifest); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(target, "owned.yaml")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(raw, []byte("\n# unvalidated change\n")...), 0o600); err != nil {
					t.Fatal(err)
				}
				if reblessed {
					if _, err := rules.GenerateManifest(target); err != nil {
						t.Fatal(err)
					}
				}
				before, err := os.ReadFile(filepath.Join(target, rules.IntegrityManifestName))
				if err != nil {
					t.Fatal(err)
				}
				if err := validateInstalledLibrary(kind, target, res.Manifest); err == nil {
					t.Fatal("installed qualification accepted changed or reblessed bytes")
				}
				after, err := os.ReadFile(filepath.Join(target, rules.IntegrityManifestName))
				if err != nil || string(after) != string(before) {
					t.Fatal("qualification rewrote the installed checksum")
				}
			})
		}
	}
}
