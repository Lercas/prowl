//go:build !windows

package targetlist

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadRefusesFIFOWithoutWaiting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := Read(path); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(3 * time.Second):
		f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = f.Close()
			<-done
		}
		t.Fatal("inventory reader waited for a FIFO writer")
	}
}
