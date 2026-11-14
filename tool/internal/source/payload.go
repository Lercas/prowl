package source

import (
	"context"
	"errors"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/resilience"
)

// Payload applies the shared archive/document/mail intake to borrowed read-only bytes.
// The caller must not modify data until the returned stream closes.
func Payload(ctx context.Context, name string, data []byte, maxBytes int64) <-chan model.Item {
	if maxBytes <= 0 {
		maxBytes = 10 << 20
	}
	model.CoverageFrom(ctx).RegisterScope("payload", name, struct{ MaxBytes int64 }{maxBytes})
	ch := make(chan model.Item, 64)
	go func() {
		defer close(ch)
		if int64(len(data)) > maxBytes {
			emitSourceError(ctx, ch, name, errors.New("payload exceeds size limit"))
			return
		}
		resilience.Guard(func() { emitPayload(ctx, ch, name, data, maxBytes, nil, nil) }, func(any) { emitSourceError(ctx, ch, name, errors.New("payload processing failed")) })
	}()
	return ch
}
