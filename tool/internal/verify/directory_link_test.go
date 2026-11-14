package verify

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoryLinkPreservesInventoryAndIntegrity(t *testing.T) {
	target := t.TempDir()
	writeFile(t, target, "nested/owned.yaml", headerVerifier)
	alias := filepath.Join(t.TempDir(), "library")
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if set, err := Load(0, alias); err != nil || set.Count() != 1 {
		t.Fatalf("unsigned linked directory failed: count=%d err=%v", set.Count(), err)
	}
	if n, err := GenerateManifest(alias); err != nil || n != 1 {
		t.Fatalf("linked directory manifest had incomplete inventory: count=%d err=%v", n, err)
	}
	if set, err := Load(0, alias); err != nil || set.Count() != 1 {
		t.Fatalf("signed linked directory failed: count=%d err=%v", set.Count(), err)
	}
	path := filepath.Join(target, "nested", "owned.yaml")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\n# changed after manifest\n"); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if set, err := Load(0, alias); err == nil || set.Count() != 0 {
		t.Fatalf("linked directory bypassed integrity check: count=%d err=%v", set.Count(), err)
	}
}
