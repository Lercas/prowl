//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestIdentityFIFOIsRejectedWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.key")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := loadIdentityKey(path); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted as an identity key")
		}
	case <-time.After(time.Second):
		t.Fatal("identity loader blocked on a FIFO")
	}
}

func TestOptionalIdentityRefusesDanglingParent(t *testing.T) {
	parent := t.TempDir()
	link := filepath.Join(parent, "home")
	if err := os.Symlink(filepath.Join(parent, "missing"), link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROWL_HOME", link)
	if _, err := loadIdentityKey(""); err == nil {
		t.Fatal("dangling identity home became keyless fallback")
	}
}
