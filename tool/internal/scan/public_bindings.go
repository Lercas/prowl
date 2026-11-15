package scan

import (
	"context"
	"sync"

	"github.com/Lercas/prowl/tool/internal/publicaudit"
	"github.com/Lercas/prowl/tool/internal/reconstruct"
)

// One original item owns this lazy snapshot, including its reconstructed child scans.
// A shared Pipeline never retains a previous item's plaintext or mutable binding state.
type publicBindings struct {
	once   sync.Once
	text   string
	path   string
	parsed *reconstruct.ObjectBindings
	xml    *firebaseXMLBindings
}

func (b *publicBindings) forCandidate(ctx context.Context, c verificationCandidate, origin *reconstructionOrigin) map[string]string {
	if b == nil {
		return nil
	}
	kind := firebaseXMLKind(b.path)
	if kind != "" && !publicaudit.GoogleType(c.typ) {
		return nil
	}
	b.once.Do(func() {
		if kind != "" {
			b.xml = parseFirebaseXML(ctx, b.text, kind)
		} else {
			b.parsed = reconstruct.ParseObjectBindings(ctx, b.text)
		}
	})
	start, end := c.start, c.end
	if origin != nil {
		start, end = origin.value.Expression.Start, origin.value.Expression.End
	}
	if kind != "" {
		if fields := b.xml.forSpan(start, end, c.value); fields != nil {
			return fields
		}
		return map[string]string{"firebaseConfig": "XML binding unavailable"}
	}
	return b.parsed.ForSpan(start, end, c.value)
}
