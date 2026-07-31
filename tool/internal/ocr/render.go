package ocr

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
)

// renderPDFPage uses Poppler without temporary files: PDF bytes enter stdin and one PNG leaves stdout.
func renderPDFPage(ctx context.Context, pdf []byte, page, scaleTo int, maxImage int64) ([]byte, error) {
	binary, err := exec.LookPath("pdftocairo")
	if err != nil {
		return nil, errors.New("PDF OCR needs Poppler's pdftocairo in PATH")
	}
	if page <= 0 || scaleTo <= 0 || maxImage <= 0 {
		return nil, errors.New("invalid PDF OCR render limits")
	}
	cmd := exec.CommandContext(
		ctx,
		binary,
		"-png", "-singlefile",
		"-f", strconv.Itoa(page),
		"-l", strconv.Itoa(page),
		"-scale-to", strconv.Itoa(scaleTo),
		"-", "-",
	)
	cmd.Stdin = bytes.NewReader(pdf)
	stdout := newCapWriter(maxImage)
	stderr := newCapWriter(4 << 10)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("pdftocairo failed for page %d", page)
	}
	if stdout.exceeded {
		return nil, fmt.Errorf("rendered PDF page exceeds the %d-byte image limit", maxImage)
	}
	image := stdout.buf.Bytes()
	if mediaType, ok := imageMediaType(image); !ok || mediaType != "image/png" {
		return nil, fmt.Errorf("pdftocairo returned no PNG for page %d", page)
	}
	return bytes.Clone(image), nil
}

type capWriter struct {
	buf      bytes.Buffer
	limit    int64
	exceeded bool
}

func newCapWriter(limit int64) *capWriter {
	return &capWriter{limit: limit}
}

func (w *capWriter) Write(p []byte) (int, error) {
	original := len(p)
	remaining := w.limit - int64(w.buf.Len())
	if remaining <= 0 {
		w.exceeded = true
		return original, nil
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
		w.exceeded = true
	}
	_, _ = w.buf.Write(p)
	return original, nil
}
