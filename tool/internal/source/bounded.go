package source

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/Lercas/prowl/tool/internal/model"
)

var errSourceTooLarge = errors.New("input exceeds max-size")

func closeInputOnCancel(ctx context.Context, input io.Closer) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = input.Close()
		case <-done:
		}
	}()
	return func() { close(done) }
}

// readSourceBytes bounds actual bytes rather than trusting an earlier stat or a declared size.
func readSourceBytes(r io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("invalid source size limit")
	}
	data, err := io.ReadAll(io.LimitReader(r, maxBytes))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) == maxBytes {
		var extra [1]byte
		if n, err := io.ReadFull(r, extra[:]); n > 0 {
			return nil, errSourceTooLarge
		} else if err != io.EOF {
			return nil, err
		}
	}
	return data, nil
}

func readSourceFile(open func() (*os.File, error), maxBytes int64) ([]byte, error) {
	f, err := open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("source is not a regular file")
	}
	if info.Size() > maxBytes {
		return nil, errSourceTooLarge
	}
	return readSourceBytes(f, maxBytes)
}

func emitSourceError(ctx context.Context, ch chan<- model.Item, path string, err error) bool {
	code := "source_error"
	if errors.Is(err, errSourceTooLarge) {
		code = "max_size"
	}
	model.Note(ctx, code, path, true)
	return send(ctx, ch, model.Item{Source: sourceForPath(path), Path: path, Error: err})
}
