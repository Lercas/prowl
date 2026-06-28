// Package mlscore is a thin client for the local ML inference sidecar (src/serve.py). It lets the
// scanner ask the L1+L2 cascade "is this candidate actually a secret?" for a batch of hits, so a
// data-file blob or a placeholder that an entropy rule flagged can be dropped. The sidecar runs on
// localhost — candidate values never leave the machine (same trust boundary as the regex layer).
package mlscore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

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

// Client posts batches to the sidecar's /score endpoint.
type Client struct {
	url       string
	threshold float64
	http      *http.Client
}

// New returns a client for the sidecar at url (e.g. http://127.0.0.1:8799). threshold is the score
// below which a non-checksum candidate is treated as not-a-secret by the caller.
//
// The HTTP client is built by internal/safehttp (same as verify/forge/domain): its CheckRedirect
// refuses any cross-origin redirect, so a malicious or misconfigured sidecar that 302s elsewhere
// can never re-POST the (masked) feature payload to another host; its dialer also blocks
// private/loopback targets unless safehttp.AllowPrivate is set. A real local sidecar is loopback,
// so production deployments that point --ml-url at 127.0.0.1 must run with PROWL_ALLOW_PRIVATE_IPS=1
// (the same toggle --verify against an internal endpoint needs).
func New(url string, threshold float64) *Client {
	return &Client{
		url:       url,
		threshold: threshold,
		http:      safehttp.Client(30 * time.Second),
	}
}

// Threshold is the drop cutoff the caller applies to scores.
func (c *Client) Threshold() float64 { return c.threshold }

func (c *Client) Local() bool { return false }

// Health reports whether the sidecar answers /health, with a short timeout (used as a startup probe
// so a misconfigured --ml-url fails fast and loudly instead of silently scoring nothing).
func (c *Client) Health(ctx context.Context) error {
	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, c.url+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ml sidecar /health returned %d", resp.StatusCode)
	}
	return nil
}

// Score returns one Result per input record (same order). An error means the caller should fail
// open (keep every finding) — the ML stage is a precision aid, never a gate that can drop findings
// just because the sidecar is unreachable.
func (c *Client) Score(ctx context.Context, recs []Record) ([]Result, error) {
	if len(recs) == 0 {
		return nil, nil
	}
	body, err := json.Marshal(map[string]any{"records": recs})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/score", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ml sidecar /score returned %d", resp.StatusCode)
	}
	var out struct {
		Results []Result `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if len(out.Results) != len(recs) {
		return nil, fmt.Errorf("ml sidecar returned %d results for %d records", len(out.Results), len(recs))
	}
	return out.Results, nil
}
