//go:build unix

package mlmodel

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestLoadFileRefusesFIFOBeforeBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "model.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := LoadFile(path); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted as a model file")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("model FIFO blocked waiting for a writer")
	}
}
