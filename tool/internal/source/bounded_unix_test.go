//go:build unix

package source

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestBoundedFileOpenDoesNotBlockOnFIFOReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "changed.txt")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readSourceFile(func() (*os.File, error) {
			return os.OpenFile(path, os.O_RDONLY|sourceOpenFlags, 0)
		}, 1024)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("replaced file was accepted as a regular input")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("opening a FIFO replacement blocked the source reader")
	}
}
