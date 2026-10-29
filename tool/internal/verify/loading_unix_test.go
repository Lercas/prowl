//go:build !windows

package verify

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestVerifierFIFOsRefusedBeforeWaiting(t *testing.T) {
	for _, mode := range []string{"loose", "entry", "manifest"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "pipe.yaml")
			if mode == "manifest" {
				path = filepath.Join(dir, ManifestName)
			}
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			target := dir
			if mode == "loose" {
				target = path
			}
			done := make(chan error, 1)
			go func() { _, err := Load(0, target); done <- err }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("FIFO accepted as verifier policy")
				}
			case <-time.After(3 * time.Second):
				if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					f.Close()
				}
				t.Fatal("verifier loader waited for a FIFO writer")
			}
		})
	}
}

func TestVerifierUnreadableDirectoryIsNotIgnored(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	dir := t.TempDir()
	writeFile(t, dir, "good.yaml", headerVerifier)
	blocked := filepath.Join(dir, "blocked")
	writeFile(t, blocked, "hidden.yaml", headerVerifier)
	if err := os.Chmod(blocked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o700) })
	if _, err := Load(0, dir); err == nil {
		t.Fatal("unreadable selected subtree silently ignored")
	}
}
