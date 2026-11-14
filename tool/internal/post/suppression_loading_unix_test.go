//go:build !windows

package post

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSuppressionLoadersRefuseFIFOWithoutWriter(t *testing.T) {
	for name, load := range map[string]func(string) error{
		"baseline": func(p string) error { _, err := LoadBaseline(p); return err },
		"ignore":   func(p string) error { _, err := LoadGitleaksIgnore(p); return err },
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy")
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- load(path) }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("FIFO accepted")
				}
			case <-time.After(3 * time.Second):
				// Release an old blocking loader so the owned fixture leaves no goroutine behind.
				f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
				if err == nil {
					_ = f.Close()
					<-done
				}
				t.Fatal("policy reader waited for a FIFO writer")
			}
		})
	}
}
