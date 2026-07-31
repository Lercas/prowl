package ocr

import (
	"context"
	"os/exec"
	"testing"
)

func TestRenderPDFPageRejectsInvalidInput(t *testing.T) {
	if _, err := exec.LookPath("pdftocairo"); err != nil {
		t.Skip("pdftocairo is not installed")
	}
	if _, err := renderPDFPage(context.Background(), []byte("not a PDF"), 1, 256, 1<<20); err == nil {
		t.Fatal("invalid PDF should fail")
	}
}

func TestCapWriterBoundsMemory(t *testing.T) {
	writer := newCapWriter(4)
	if n, err := writer.Write([]byte("123456")); err != nil || n != 6 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if got := writer.buf.String(); got != "1234" || !writer.exceeded {
		t.Fatalf("got=%q exceeded=%v", got, writer.exceeded)
	}
}
