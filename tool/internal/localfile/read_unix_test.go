//go:build !windows

package localfile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestFIFORejectedWithoutWriter(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadRegular(p, 8); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted as a policy file")
		}
	case <-time.After(3 * time.Second):
		// Unblock a regressed open so the test does not leave a goroutine waiting on its fixture.
		f, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			f.Close()
		}
		t.Fatal("policy open waited for a FIFO writer")
	}
}

func TestDiscoveryAccessErrorIsNotAbsence(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if path, err := FirstExisting(filepath.Join(dir, "config")); err == nil || path != "" {
		t.Fatalf("access failure treated as absent: path=%s err=%v", path, err)
	}
}
