package scan

import (
	"context"
	"sync"

	"github.com/Lercas/prowl/tool/internal/reconstruct"
)

// One original item owns this lazy snapshot, including its reconstructed child scans.
// A shared Pipeline never retains a previous item's plaintext or mutable binding state.
type publicBindings struct {
	once   sync.Once
	text   string
	parsed *reconstruct.ObjectBindings
}

func (b *publicBindings) forCandidate(ctx context.Context, c verificationCandidate, origin *reconstructionOrigin) map[string]string {
	if b == nil {
		return nil
	}
	b.once.Do(func() { b.parsed = reconstruct.ParseObjectBindings(ctx, b.text) })
	start, end := c.start, c.end
	if origin != nil {
		start, end = origin.value.Expression.Start, origin.value.Expression.End
	}
	return b.parsed.ForSpan(start, end, c.value)
}
