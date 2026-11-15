package detect

import (
	"context"
	"strings"
	"testing"
)

type cancelPaddingContext struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *cancelPaddingContext) Err() error {
	c.checks++
	if c.checks == 2 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestBase64CancellationInterruptsLongPadding(t *testing.T) {
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &cancelPaddingContext{Context: parent, cancel: cancel}
	d := newDetector(t)
	text := "QUJD" + strings.Repeat("=", maxBase64Blob+4096)
	ordinary, children, limited := d.base64OccurrencesWithJWT(ctx, text, ScanOptions{})
	if parent.Err() != context.Canceled || len(ordinary)+len(children) != 0 || limited {
		t.Fatal("padding was classified as oversized instead of observing cancellation")
	}
}
