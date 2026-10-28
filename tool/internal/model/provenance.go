package model

import (
	"context"
	"encoding/hex"
	"net/url"
	"strings"
)

type provenanceKey struct{}

func WithProvenance(ctx context.Context, p map[string]any) context.Context {
	merged := map[string]any{}
	if parent, ok := ctx.Value(provenanceKey{}).(map[string]any); ok {
		for k, v := range parent {
			merged[k] = v
		}
	}
	for k, v := range p {
		merged[k] = v
	}
	return context.WithValue(ctx, provenanceKey{}, merged)
}

// Only immutable content/revision identifiers can justify shared-metadata links.
func ValidImmutableMetadata(key, value string) bool {
	if key == "digest" || key == "layer_digest" {
		value = strings.TrimPrefix(value, "sha256:")
		if len(value) != 64 {
			return false
		}
	} else if len(value) != 40 && len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
func AttachProvenance(ctx context.Context, it *Item) {
	p, _ := ctx.Value(provenanceKey{}).(map[string]any)
	if len(p) == 0 {
		return
	}
	meta := map[string]any{}
	for k, v := range it.Meta {
		meta[k] = v
	}
	for k, v := range p {
		meta[k] = v
	}
	it.Meta = meta
}

// SafeLocator removes URL credentials, query strings and fragments from reports.
func SafeLocator(raw string) string {
	lower := strings.ToLower(raw)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(raw, "//") {
		return raw
	}
	// A virtual delimiter inside query/fragment data is not a member boundary.
	if end := strings.IndexAny(raw, "?#"); end >= 0 {
		raw = raw[:end]
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid URL>"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	safe := u.String()
	return safe
}

type Occurrence struct {
	ID           string            `json:"id,omitempty"`
	Source       string            `json:"source"`
	Path         string            `json:"path"`
	Line         int               `json:"line"`
	Col          int               `json:"col"`
	Evidence     []Evidence        `json:"evidence,omitempty"`
	Provenance   map[string]string `json:"provenance,omitempty"`
	Verification *Verification     `json:"verification,omitempty"`
}

func (f Finding) Occurrence() Occurrence {
	return Occurrence{f.OccurrenceID, f.Source, f.Path, f.Line, f.Col, f.Evidence, f.Provenance, f.Verification}
}
