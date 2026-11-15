package source

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/resilience"
)

// MobileBytes uses the same mobile intake without creating a file. Bytes are borrowed read-only
// until the returned stream closes; archive entries are never written to disk.
func MobileBytes(ctx context.Context, name string, data []byte, opts MobileOptions) (<-chan model.Item, error) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = maxMobileEntryBytes
	}
	var err error
	ctx, err = mobileContext(ctx, name, true, opts)
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	ch := make(chan model.Item, 128)
	display := ctx.Value(mobileOriginKey{}).(mobileOrigin).display
	go func() {
		defer close(ch)
		resilience.Guard(func() { emitMobileReader(ctx, ch, zr, display, opts) }, func(any) { emitSourceError(ctx, ch, display, errors.New("mobile payload processing failed")) })
	}()
	return ch, nil
}
