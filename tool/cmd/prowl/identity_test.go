package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
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
