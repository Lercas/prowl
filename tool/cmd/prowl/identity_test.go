package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIdentityCreationIsExclusiveAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.key")
	if cmdIdentity([]string{"init", "-o", path}) != 0 {
		t.Fatal("could not create identity")
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	key, err := loadIdentityKey(path)
	if err != nil || len(key) != 32 {
		t.Fatalf("cannot load generated key: %v", err)
	}
	if cmdIdentity([]string{"init", "-o", path}) != 2 {
		t.Fatal("existing key was overwritten")
	}
	second, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("existing identity changed")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadIdentityKey(path); err == nil {
			t.Fatal("world-readable key accepted")
		}
	}
}

func TestIdentityLoaderRejectsUnsafeOrInvalidInputs(t *testing.T) {
	t.Setenv("PROWL_HOME", t.TempDir())
	if key, err := loadIdentityKey(""); err != nil || key != nil {
		t.Fatal("missing optional key should preserve keyless mode")
	}
	valid := filepath.Join(t.TempDir(), "private.key")
	if err := os.WriteFile(valid, []byte(strings.Repeat("ab", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link.key")
	if err := os.Symlink(valid, link); err == nil {
		if _, err := loadIdentityKey(link); err == nil {
			t.Fatal("key symlink accepted")
		}
	}
	for _, content := range []string{"not hex", strings.Repeat("ab", 31), strings.Repeat("ab", 33), strings.Repeat("ab", 200)} {
		path := filepath.Join(t.TempDir(), "invalid.key")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadIdentityKey(path); err == nil || strings.Contains(err.Error(), content) {
			t.Fatal("invalid key accepted or echoed")
		}
	}
	if _, err := loadIdentityKey(t.TempDir()); err == nil {
		t.Fatal("directory accepted as identity key")
	}
}

func TestInvalidIdentityPreflightPreservesReportAndNamedInput(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PROWL_HOME", t.TempDir())
	for _, path := range []string{"report.json", "config.json"} {
		if err := os.WriteFile(path, []byte("owned sentinel"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if code := runCLI([]string{"scan", "--stdin-name=config.json", "--output=report.json", "--identity-key-file=missing-private-key"}); code != 2 {
		t.Fatal("invalid identity preflight did not fail")
	}
	for _, path := range []string{"report.json", "config.json"} {
		raw, err := os.ReadFile(path)
		if err != nil || string(raw) != "owned sentinel" {
			t.Fatal("identity preflight touched source or report")
		}
	}
}

func TestIdentityInvalidArgumentsHaveNoSideEffects(t *testing.T) {
	for _, args := range [][]string{{"init", "-o"}, {"init", "--output="}, {"init", "-o", "--unexpected"}} {
		if cmdIdentity(args) != 2 {
			t.Fatal("missing output path accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "identity.key")
	if cmdIdentity([]string{"init", "-o", path, "--unexpected"}) != 2 {
		t.Fatal("unknown flag accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("key created before argument validation")
	}
}
