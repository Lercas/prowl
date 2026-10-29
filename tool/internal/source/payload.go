package source

import (
	"context"

	"github.com/Lercas/prowl/tool/internal/model"
)

// Payload applies the actual archive/document/mail intake to an in-memory payload.
func Payload(ctx context.Context, name string, data []byte, maxBytes int64) <-chan model.Item {
	ch := make(chan model.Item, 64)
	go func() { defer close(ch); emitPayload(ctx, ch, name, data, maxBytes, nil, nil) }()
	return ch
}
