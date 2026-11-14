package localfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/verify"
)

func TestManifestGenerationCannotOverwriteLinkedFiles(t *testing.T) {
	for _, library := range []struct {
		name, body string
		generate   func(string) (int, error)
	}{
		{"rules", "id: owned\ninfo: {name: Owned, severity: high}\nmatchers:\n  - type: regex\n    regex: ['OWNED_[A-Z]{8}']\n", rules.GenerateManifest},
		{"verifiers", "id: owned\nmatch: [owned]\nrequests:\n  - url: https://owned.invalid/identity\n", verify.GenerateManifest},
	} {
		t.Run(library.name, func(t *testing.T) {
			for _, kind := range []string{"symlink", "broken-symlink", "hardlink"} {
				t.Run(kind, func(t *testing.T) {
					dir, outside := t.TempDir(), filepath.Join(t.TempDir(), "owned-sentinel")
					if err := os.WriteFile(filepath.Join(dir, "owned.yaml"), []byte(library.body), 0o600); err != nil {
						t.Fatal(err)
					}
					if kind != "broken-symlink" {
						if err := os.WriteFile(outside, []byte("preserve owned sentinel"), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					manifest := filepath.Join(dir, "MANIFEST.sha256")
					link := os.Symlink
					if kind == "hardlink" {
						link = os.Link
					}
					if err := link(outside, manifest); err != nil {
						t.Skipf("links unavailable: %v", err)
					}
					_, err := library.generate(dir)
					if kind != "hardlink" && err == nil {
						t.Error("manifest generation followed a destination symlink")
					}
					if kind == "hardlink" && err != nil {
						t.Errorf("atomic replacement of a regular file failed: %v", err)
					}
					raw, readErr := os.ReadFile(outside)
					if kind == "broken-symlink" {
						if !os.IsNotExist(readErr) {
							t.Fatal("generation created the target of a broken manifest link")
						}
					} else if readErr != nil || string(raw) != "preserve owned sentinel" {
						t.Fatalf("generation modified a file outside the library: err=%v", readErr)
					}
				})
			}
		})
	}
}

func TestGeneratedManifestsRoundTripEscapedFileNames(t *testing.T) {
	for _, name := range []string{"line\nbreak.yaml", "carriage\rreturn.yaml", "back\\slash.yaml"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			body := "id: owned\ninfo: {name: Owned, severity: high}\nmatchers:\n  - type: regex\n    regex: ['OWNED_[A-Z]{8}']\n"
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				t.Skipf("filename unavailable: %v", err)
			}
			if _, err := rules.GenerateManifest(dir); err != nil {
				t.Fatal(err)
			}
			if _, err := rules.Load(dir); err != nil {
				t.Fatalf("generated manifest could not load its own filename: %v", err)
			}
		})
	}
}
