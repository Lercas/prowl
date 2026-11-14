package source

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestCommandOutputCapDrainsConcurrentWriters(t *testing.T) {
	out := &commandOutput{}
	payload := []byte(strings.Repeat("x", maxCommandOutput))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if n, err := out.Write(payload); n != len(payload) || err != nil {
				t.Errorf("bounded writer stopped draining: n=%d err=%v", n, err)
			}
		}()
	}
	wg.Wait()
	text := out.String()
	if !strings.HasSuffix(text, "[command output truncated]") || len(text) > maxCommandOutput+64 {
		t.Fatalf("diagnostic output is not bounded: %d bytes", len(text))
	}
}

func TestOwnedCommandBoundsDiagnosticOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell command is POSIX-only")
	}
	path := filepath.Join(t.TempDir(), "command")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nhead -c 1048576 /dev/zero\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := runOwnedCommand(exec.CommandContext(context.Background(), path))
	if err == nil || len(out) > maxCommandOutput+64 || !strings.Contains(out, "[command output truncated]") {
		t.Fatalf("external command output limit: bytes=%d err=%v", len(out), err)
	}
}
