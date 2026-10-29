//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReportRefusesFIFOWithoutWaitingForAReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- writeReportFile(path, nil, "json") }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("report writer accepted a FIFO")
		}
	case <-time.After(3 * time.Second):
		// Release a test-owned blocked writer while keeping the reader open until it terminates.
		reader, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("test-owned FIFO writer did not terminate")
		}
		t.Fatal("report writer waited for a FIFO reader")
	}
}
