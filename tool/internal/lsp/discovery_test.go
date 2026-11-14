package lsp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildRefusesBrokenInstalledLibrary(t *testing.T) {
	t.Chdir(t.TempDir())
	home := t.TempDir()
	t.Setenv("PROWL_HOME", home)
	if err := os.Symlink(filepath.Join(home, "missing"), filepath.Join(home, "rules")); err != nil {
		t.Fatal(err)
	}
	if eng, err := build(); err == nil || eng != nil {
		t.Fatalf("editor silently ignored broken installed library: engine=%v err=%v", eng, err)
	}
}
