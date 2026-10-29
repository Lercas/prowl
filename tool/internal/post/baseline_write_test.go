package post

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBaselineWritePreservesDestinationLinks(t *testing.T) {
	dir := t.TempDir()
	outside, path := filepath.Join(dir, "outside"), filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(outside, []byte("owned sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := WriteBaseline(path, nil); err == nil {
		t.Fatal("baseline write replaced a pre-existing symlink")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("baseline refusal changed the link")
	}
}
