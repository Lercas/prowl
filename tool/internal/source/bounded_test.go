package source

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestReadSourceBytesBoundsActualInput(t *testing.T) {
	input := strings.NewReader(strings.Repeat("x", 1024))
	if _, err := readSourceBytes(input, 8); !errors.Is(err, errSourceTooLarge) {
		t.Fatalf("oversized unknown-length source accepted: %v", err)
	}
	if input.Len() != 1024-9 {
		t.Fatalf("reader consumed %d bytes, want at most limit plus one", 1024-input.Len())
	}
	if data, err := readSourceBytes(strings.NewReader("12345678"), 8); err != nil || string(data) != "12345678" {
		t.Fatalf("exactly-at-limit content changed: data=%q err=%v", data, err)
	}
}

func TestStdinDecodesUTF16(t *testing.T) {
	input := io.NopCloser(bytes.NewReader(utf16BOM(encSecret, true)))
	items := archiveItems(stdinFrom(context.Background(), input, 1024))
	if len(items) != 1 || items[0].Error != nil || items[0].Path != "<stdin>" || items[0].Text != encSecret {
		t.Fatalf("stdin bypassed source encoding handling: %+v", items)
	}
}

func TestStdinCancellationClosesBlockedInput(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	items := stdinFrom(ctx, r, 1024)
	cancel()
	done := make(chan struct{})
	go func() {
		for range items {
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stdin producer did not stop after cancellation")
	}
}
