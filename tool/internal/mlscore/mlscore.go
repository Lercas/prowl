// Package mlscore is a thin client for the local ML inference sidecar (src/serve.py). It lets the
// scanner ask the L1+L2 cascade "is this candidate actually a secret?" for a batch of hits, so a
// data-file blob or a placeholder that an entropy rule flagged can be dropped. The sidecar runs
// at the explicitly selected endpoint. A local endpoint keeps inference on the same machine;
// the request carries raw candidate values and their context.
package mlscore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Lercas/prowl/tool/internal/jsonstrict"
	"github.com/Lercas/prowl/tool/internal/safehttp"
)

// Record is one candidate to score: the raw value plus the context the model was trained on.
type Record struct {
	Value   string  `json:"value"`
	Context Context `json:"context"`
}

// Context mirrors the python feature extractor's context dict (name/line/path/source).
type Context struct {
	Name   string `json:"name,omitempty"`
	Line   string `json:"line,omitempty"`
	Path   string `json:"path,omitempty"`
	Source string `json:"source,omitempty"`
}

// Result is the cascade's verdict for one record.
type Result struct {
	Score    float64 `json:"score"`
	IsSecret bool    `json:"is_secret"`
	Type     string  `json:"type"`
	Stage    string  `json:"stage"`
}

// ValidScore reports whether a value is a finite probability. The comparisons reject NaN and
// infinities too; a missing/invalid score must never become evidence that a candidate is noise.
func ValidScore(value float64) bool { return value >= 0 && value <= 1 }

// A scan sends at most 200 candidates per sidecar batch. Allow ample optional metadata while
// bounding decoded response bytes, including chunked and transparently decompressed responses.
const maxScoreResponseBytes = 1 << 20

// sidecarFailure preserves transport classification without printing endpoint credentials or
// provider-controlled diagnostics that may echo the raw candidate values sent for inference.
type sidecarFailure struct {
	operation string
	cause     error
}

func (e *sidecarFailure) Error() string { return "ml sidecar " + e.operation + " failed" }
func (e *sidecarFailure) Unwrap() error { return e.cause }

// Client posts batches to the sidecar's /score endpoint.
type Client struct {
	url       string
	threshold float64
	http      *http.Client
	initError error
}

// New returns a client for the sidecar at url (e.g. http://127.0.0.1:8799). threshold is the score
// below which a non-checksum candidate is treated as not-a-secret by the caller.
//
// The HTTP client is built by internal/safehttp (same as verify/forge/domain): its CheckRedirect
// refuses any cross-origin redirect, so a malicious or misconfigured sidecar that 302s elsewhere
// can never re-POST the raw candidate values and context to another host; its dialer also blocks
// private/loopback targets unless safehttp.AllowPrivate is set. A real local sidecar is loopback,
// so production deployments that point --ml-url at 127.0.0.1 must run with PROWL_ALLOW_PRIVATE_IPS=1
// (the same toggle --verify against an internal endpoint needs).
func New(url string, threshold float64) *Client {
	c, err := NewWithPolicy(url, threshold, false)
	if err != nil {
		return &Client{initError: err, threshold: threshold}
	}
	return c
}
func NewWithPolicy(url string, threshold float64, allowRemote bool) (*Client, error) {
	client, err := safehttp.InferenceClient(url, allowRemote, 30*time.Second)
	if err != nil {
		return nil, err
	}
	return &Client{url: url, threshold: threshold, http: client}, nil
}

// Threshold is the drop cutoff the caller applies to scores.
func (c *Client) Threshold() float64 { return c.threshold }

func (c *Client) Local() bool { return false }

// Health reports whether the sidecar answers /health, with a short timeout (used as a startup probe
// so a misconfigured --ml-url fails fast and loudly instead of silently scoring nothing).
func (c *Client) Health(ctx context.Context) (err error) {
	if c.initError != nil {
		return c.initError
	}
	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, c.url+"/health", nil)
	if err != nil {
		return &sidecarFailure{"health request construction", err}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return &sidecarFailure{"health request", err}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			err = errors.Join(err, &sidecarFailure{"health response close", closeErr})
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ml sidecar /health returned %d", resp.StatusCode)
	}
	return nil
}

// Score returns one Result per input record (same order). An error means the caller should fail
// open (keep every finding) — the ML stage is a precision aid, never a gate that can drop findings
// just because the sidecar is unreachable.
func (c *Client) Score(ctx context.Context, recs []Record) (results []Result, err error) {
	if c.initError != nil {
		return nil, c.initError
	}
	if len(recs) == 0 {
		return nil, nil
	}
	body, err := json.Marshal(map[string]any{"records": recs})
	if err != nil {
		return nil, &sidecarFailure{"score request encoding", err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/score", bytes.NewReader(body))
	if err != nil {
		return nil, &sidecarFailure{"score request construction", err}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &sidecarFailure{"score request", err}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			results = nil
			err = errors.Join(err, &sidecarFailure{"score response close", closeErr})
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ml sidecar /score returned %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxScoreResponseBytes+1))
	if err != nil {
		return nil, &sidecarFailure{"score response read", err}
	}
	if len(raw) > maxScoreResponseBytes {
		return nil, fmt.Errorf("ml sidecar response exceeds the %d-byte limit", maxScoreResponseBytes)
	}
	var out struct {
		Results []struct {
			Score    *float64 `json:"score"`
			IsSecret bool     `json:"is_secret"`
			Type     string   `json:"type"`
			Stage    string   `json:"stage"`
		} `json:"results"`
	}
	if err := jsonstrict.UnmarshalContext(ctx, raw, &out); err != nil {
		return nil, err
	}
	if len(out.Results) != len(recs) {
		return nil, fmt.Errorf("ml sidecar returned %d results for %d records", len(out.Results), len(recs))
	}
	results = make([]Result, len(out.Results))
	for i, result := range out.Results {
		if result.Score == nil || !ValidScore(*result.Score) {
			return nil, errors.New("ml sidecar result requires a numeric score in 0..1")
		}
		results[i] = Result{Score: *result.Score, IsSecret: result.IsSecret, Type: result.Type, Stage: result.Stage}
	}
	return results, nil
}
