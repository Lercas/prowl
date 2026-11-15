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

func NewWithOwnedCollections(transport http.RoundTripper, collections []string) (*Auditor, error) {
	a, err := NewWithCollections(time.Second, collections)
	if err == nil {
		a.client.Transport = transport
	}
	return a, err
}
