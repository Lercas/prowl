//go:build !windows

package rules

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestMetadataFIFOsNeverWaitForWriter(t *testing.T) {
	for _, name := range []string{ManifestName, "VERSION"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, name)
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				if name == ManifestName {
					_, err := ReadManifest(dir)
					done <- err
				} else {
					_, err := readVersionFile(dir)
					done <- err
				}
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("FIFO metadata accepted")
				}
			case <-time.After(3 * time.Second):
				if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					_ = f.Close()
				}
				t.Fatal("metadata loader waited for a FIFO writer")
			}
		})
	}
}

func TestUpdateSourceFIFOsNeverWaitOrMutate(t *testing.T) {
	for _, name := range []string{"owned.yaml", "SCHEMA.md", "VERSION", IntegrityManifestName} {
		t.Run(name, func(t *testing.T) {
			source := t.TempDir()
			target := filepath.Join(t.TempDir(), "not-created")
			if name != "owned.yaml" {
				writeRuleFile(t, source, "owned.yaml", minimalRule("owned"))
			}
			path := filepath.Join(source, name)
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				_, err := Update(UpdateOpts{Source: source, Target: target})
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("FIFO source accepted")
				}
			case <-time.After(3 * time.Second):
				if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					_ = f.Close()
				}
				t.Fatal("update waited for a FIFO writer")
			}
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatal("FIFO source mutated target")
			}
		})
	}
}
