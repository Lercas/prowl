package source

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNamedStdinDecodesUTF16(t *testing.T) {
	const label = "production.json"
	input := io.NopCloser(bytes.NewReader(utf16BOM(encSecret, true)))
	items := archiveItems(stdinNamedFrom(t.Context(), input, 1024, label))
	if len(items) != 1 || items[0].Error != nil || items[0].Path != label || items[0].Text != encSecret {
		t.Fatalf("named stdin lost encoding normalization: %+v", items)
	}
}

func TestNamedStdinUsesOnlyReaderAndPreservesLabel(t *testing.T) {
	label := filepath.Join(t.TempDir(), "existing.json")
	if err := os.WriteFile(label, []byte("file content must not be read"), 0600); err != nil {
		t.Fatal(err)
	}
	const input = `{"password":"Kx7;mPq2"}`
	items := archiveItems(stdinNamedFrom(t.Context(), io.NopCloser(strings.NewReader(input)), 1024, label))
	if len(items) != 1 || items[0].Error != nil || items[0].Path != label || items[0].Text != input {
		t.Fatalf("logical label changed input: %+v", items)
	}
	raw, err := os.ReadFile(label)
	if err != nil || string(raw) != "file content must not be read" {
		t.Fatal("logical label file was changed")
	}
	missing := filepath.Join(t.TempDir(), "missing", "config.yaml")
	items = archiveItems(stdinNamedFrom(t.Context(), io.NopCloser(strings.NewReader("password: Kx7#mPq2")), 1024, missing))
	if len(items) != 1 || items[0].Path != missing || items[0].Error != nil {
		t.Fatal("missing logical path was treated as a real input")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("logical label created a file")
	}
}

func TestNamedStdinBoundsAndCancellation(t *testing.T) {
	const label = "prod/config.json"
	items := archiveItems(stdinNamedFrom(t.Context(), io.NopCloser(strings.NewReader("too much input")), 4, label))
	if len(items) != 1 || items[0].Error == nil || items[0].Path != label {
		t.Fatal("named stdin lost size diagnostic or label")
	}
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithCancel(t.Context())
	stream := stdinNamedFrom(ctx, r, 1024, label)
	cancel()
	done := make(chan struct{})
	go func() {
		for range stream {
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("named stdin did not interrupt blocked input")
	}
}
