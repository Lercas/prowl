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

func NewWithOwnedTargets(transport http.RoundTripper, collections, tables []string) (*Auditor, error) {
	a, err := NewWithTargets(time.Second, collections, tables)
	if err == nil {
		a.client.Transport = transport
	}
	return a, err
}

func NewWithOwnedGoogleRestrictions(transport http.RoundTripper, token string) (*Auditor, error) {
	a, err := NewWithGoogleRestrictions(time.Second, nil, nil, token)
	if err == nil {
		a.client.Transport = transport
	}
	return a, err
}
