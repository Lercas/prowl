package checkedio

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

type injectedWriter struct {
	mode  string
	calls int
}

func (w *injectedWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls > 1 {
		return 0, errors.New("unexpected retry")
	}
	switch w.mode {
	case "zero":
		return 0, nil
	case "short":
		return len(p) / 2, nil
	case "negative":
		return -1, nil
	case "oversized":
		return len(p) + 1, nil
	default:
		return 0, io.ErrClosedPipe
	}
}

func TestBufferedOutputRejectsBadCountsWithoutRetry(t *testing.T) {
	for _, mode := range []string{"zero", "short", "negative", "oversized", "error"} {
		for _, size := range []int{8, 128} {
			raw := &injectedWriter{mode: mode}
			buffered := bufio.NewWriterSize(NewWriter(raw), 16)
			_, writeErr := buffered.Write([]byte(strings.Repeat("x", size)))
			flushErr := buffered.Flush()
			if writeErr == nil && flushErr == nil {
				t.Fatalf("%s count was accepted at size %d", mode, size)
			}
			if raw.calls != 1 {
				t.Fatalf("%s output was retried after partial failure: %d calls", mode, raw.calls)
			}
		}
	}
}

func TestHealthyBufferedOutputUnchanged(t *testing.T) {
	var output strings.Builder
	w := bufio.NewWriterSize(NewWriter(&output), 16)
	text := strings.Repeat("healthy ", 20)
	if n, err := w.Write([]byte(text)); n != len(text) || err != nil {
		t.Fatal("healthy full write failed")
	}
	if err := w.Flush(); err != nil || output.String() != text {
		t.Fatal("buffered healthy output changed")
	}
}
