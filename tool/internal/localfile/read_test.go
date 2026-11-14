package localfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadRegularLimitAndType(t *testing.T) {
	dir := t.TempDir()
	for _, size := range []int{0, 8, 9} {
		p := filepath.Join(dir, "policy")
		if err := os.WriteFile(p, make([]byte, size), 0o600); err != nil {
			t.Fatal(err)
		}
		b, err := ReadRegular(p, 8)
		if size > 8 {
			if err == nil {
				t.Fatal("oversized policy accepted")
			}
		} else if err != nil || len(b) != size {
			t.Fatalf("boundary read %d: bytes=%d err=%v", size, len(b), err)
		}
	}
	if _, err := ReadRegular(dir, 8); err == nil {
		t.Fatal("directory accepted as a policy file")
	}
}

func TestDiscoveryBrokenLinkIsSelected(t *testing.T) {
	dir := t.TempDir()
	first, second := filepath.Join(dir, "first"), filepath.Join(dir, "second")
	if err := os.Symlink(filepath.Join(dir, "missing"), first); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.WriteFile(second, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	selected, err := FirstExisting(filepath.Join(dir, "absent"), first, second)
	if err != nil || selected != first {
		t.Fatalf("broken policy silently bypassed: path=%s err=%v", selected, err)
	}
	if _, err := ReadRegular(selected, 8); err == nil {
		t.Fatal("broken policy failed to surface read error")
	}
}

func TestDirectoryDiscoveryPrecedenceAndLinks(t *testing.T) {
	dir := t.TempDir()
	fallback := filepath.Join(dir, "fallback")
	if err := os.Mkdir(fallback, 0o700); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(dir, "first")
	if got, err := FirstDirectory(first, fallback); err != nil || got != fallback {
		t.Fatalf("missing first directory prevented fallback: path=%s err=%v", got, err)
	}
	if err := os.Symlink(fallback, first); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if got, err := FirstDirectory(first, fallback); err != nil || got != first {
		t.Fatalf("valid link was not selected: path=%s err=%v", got, err)
	}
	broken := filepath.Join(dir, "broken")
	if err := os.Symlink(filepath.Join(dir, "missing"), broken); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{broken, filepath.Join(broken, "library"), filepath.Join(broken, "nested", "library")} {
		if got, err := FirstDirectory(path, fallback); err == nil || got != "" {
			t.Errorf("dangling path triggered fallback: path=%s selected=%s err=%v", path, got, err)
		}
	}
}
