package domain

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/Lercas/prowl/tool/internal/resilience"
	"github.com/Lercas/prowl/tool/internal/safehttp"
)

// hostBreaker stops hammering a host that keeps failing (3 fails -> 30s open).
var hostBreaker = resilience.NewBreaker(3, 30*time.Second)

const userAgent = "prowl-secret-scanner/0.1 (authorized recon)"
const maxBodyBytes = 4 << 20 // 4MB per asset

// budget caps the total number of fetched assets (politeness + bounded work).
type budget struct {
	max int
	n   int64
}

func newBudget(max int) *budget { return &budget{max: max} }
func (b *budget) take() bool    { return atomic.AddInt64(&b.n, 1) <= int64(b.max) }
func (b *budget) done() bool    { return atomic.LoadInt64(&b.n) >= int64(b.max) }
func (b *budget) used() int     { return int(atomic.LoadInt64(&b.n)) }

func newClient(timeout time.Duration) *http.Client {
	if timeout == 0 {
		timeout = 12 * time.Second
	}
	// safehttp.Client adds a dial guard that refuses loopback/link-local/RFC1918/ULA targets (on
	// the resolved IP, so it also defeats DNS rebinding) and caps redirects while refusing any that
	// change host. --recon fetches attacker-influenced third-party URLs, so this is load-bearing.
	return safehttp.Client(timeout)
}

// getText GETs a URL (ctx-cancellable) behind a per-host circuit breaker and bounded retries.
func getText(ctx context.Context, c *http.Client, rawurl string) (string, bool) {
	host := hostOf(rawurl)
	if !hostBreaker.Allow(host) {
		return "", false // breaker open: skip this host
	}
	var body string
	err := resilience.Retry(ctx, 3, 300*time.Millisecond, 3*time.Second, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "*/*")
		resp, err := c.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return errRetryable // retry rate-limit / server errors
		}
		if resp.StatusCode != http.StatusOK {
			return nil // 4xx is definitive: don't retry, leave body empty
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		if err != nil {
			return err
		}
		body = string(b)
		return nil
	})
	ok := err == nil && body != ""
	hostBreaker.Record(host, err == nil)
	return body, ok
}

var errRetryable = &retryErr{}

type retryErr struct{}

func (*retryErr) Error() string { return "retryable" }

func hostOf(rawurl string) string {
	if u, err := url.Parse(rawurl); err == nil {
		return u.Hostname()
	}
	return rawurl
}
