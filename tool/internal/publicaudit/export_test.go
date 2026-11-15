package publicaudit

import (
	"net/http"
	"time"
)

// NewWithOwnedTransport exists only in test binaries; production has no endpoint override.
func NewWithOwnedTransport(transport http.RoundTripper) *Auditor {
	a := New(time.Second)
	a.client.Transport = transport
	return a
}
