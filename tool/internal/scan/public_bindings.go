package scan

import (
	"context"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Lercas/prowl/tool/internal/model"

	"github.com/Lercas/prowl/tool/internal/publicaudit"
	"github.com/Lercas/prowl/tool/internal/reconstruct"
)

// One original item owns this lazy snapshot, including its reconstructed child scans.
// A shared Pipeline never retains a previous item's plaintext or mutable binding state.
type publicBindings struct {
	once    sync.Once
	text    string
	path    string
	parsed  *reconstruct.ObjectBindings
	xml     *firebaseXMLBindings
	algolia *algoliaXMLBindings
}

func publicXMLKind(path string) string {
	if strings.EqualFold(filepath.Ext(model.SafeLocator(path)), ".plist") {
		return "plist"
	}
	return firebaseXMLKind(path)
}

func (b *publicBindings) parse(ctx context.Context) {
	b.once.Do(func() {
		kind := publicXMLKind(b.path)
		if kind == "" {
			b.parsed = reconstruct.ParseObjectBindings(ctx, b.text)
			return
		}
		root := parsePublicXMLRoot(ctx, b.text, kind)
		if root == nil {
			return
		}
		if firebaseXMLKind(b.path) != "" {
			if kind == "plist" {
				b.xml = firebasePlistBindings(root)
			} else {
				b.xml = firebaseResourceBindings(root)
			}
		}
		b.algolia = parseAlgoliaXML(root, kind, b.text)
	})
}

func (b *publicBindings) forCandidate(ctx context.Context, c verificationCandidate, origin *reconstructionOrigin) map[string]string {
	if b == nil {
		return nil
	}
	b.parse(ctx)
	start, end := c.start, c.end
	if origin != nil {
		start, end = origin.value.Expression.Start, origin.value.Expression.End
	}
	if publicXMLKind(b.path) != "" {
		if c.typ == "algolia-api-key" {
			return b.algolia.forSpan(start, end, c.value)
		}
		if publicaudit.GoogleType(c.typ) && firebaseXMLKind(b.path) != "" {
			if fields := b.xml.forSpan(start, end, c.value); fields != nil {
				return fields
			}
			return map[string]string{"firebaseConfig": "XML binding unavailable"}
		}
		return nil
	}
	return b.parsed.ForSpan(start, end, c.value)
}
