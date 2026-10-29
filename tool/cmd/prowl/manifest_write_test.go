package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUpdateCannotReportSuccessWithoutIntegrityManifest(t *testing.T) {
	for _, kind := range []string{"rules", "verifiers"} {
		t.Run(kind, func(t *testing.T) {
			source, target := t.TempDir(), t.TempDir()
			if kind == "rules" {
				writeTemplate(t, source, "owned")
			} else {
				if err := os.WriteFile(filepath.Join(source, "owned.yaml"), []byte("id: owned\nmatch: [owned]\nrequests:\n  - url: https://owned.invalid/identity\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			blocked := filepath.Join(target, "MANIFEST.sha256")
			if err := os.Mkdir(blocked, 0o700); err != nil {
				t.Fatal(err)
			}
			// A non-managed sentinel prevents syncDir's empty-directory pruning from hiding the error.
			if err := os.WriteFile(filepath.Join(blocked, "preserve.txt"), []byte("owned sentinel"), 0o600); err != nil {
				t.Fatal(err)
			}
			if code := updateInto(kind, source, target, "owned-test", false, true); code != 2 {
				t.Fatalf("failed integrity manifest generation reported update success: code=%d", code)
			}
		})
	}
}
