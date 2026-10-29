package domain

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/resilience"
	"github.com/Lercas/prowl/tool/internal/safehttp"
)

// textFetcher shares failure state only within one discovery operation.
type textFetcher struct {
	client  *http.Client
	breaker *resilience.Breaker
}

func newTextFetcher(client *http.Client) *textFetcher {
	return &textFetcher{client: client, breaker: resilience.NewBreaker(3, 30*time.Second)}
}

const userAgent = "prowl-secret-scanner/0.1 (authorized recon)"
const maxBodyBytes = 4 << 20 // 4MB per asset

// budget caps the total number of fetched assets (politeness + bounded work).
type budget struct {
	max int
	n   int64
}

func newBudget(max int) *budget { return &budget{max: max} }
func (b *budget) take() bool {
	for {
		n := atomic.LoadInt64(&b.n)
		if n >= int64(b.max) {
			return false
		}
		if atomic.CompareAndSwapInt64(&b.n, n, n+1) {
			return true
		}
	}
}
func (b *budget) done() bool { return atomic.LoadInt64(&b.n) >= int64(b.max) }
func (b *budget) used() int  { return int(atomic.LoadInt64(&b.n)) }

func newClient(timeout time.Duration) *http.Client {
	if timeout == 0 {
		timeout = 12 * time.Second
	}
	// safehttp.Client adds a dial guard that refuses loopback/link-local/RFC1918/ULA targets (on
	// the resolved IP, so it also defeats DNS rebinding) and caps redirects while refusing any that
	// change host. --recon fetches attacker-influenced third-party URLs, so this is load-bearing.
	return safehttp.Client(timeout)
}

type fetchedText struct {
	text    string
	present bool
	url     string // Address of the last accepted content response, including across retries.
}

func (f *textFetcher) getText(ctx context.Context, rawurl string) (string, bool, error) {
	content, err := f.getDocument(ctx, rawurl)
	return content.text, content.present, err
}

// getDocument GETs a URL (ctx-cancellable) behind a per-origin circuit breaker and bounded retries.
// The presence flag distinguishes an HTTP response with unreadable content from a failed
// alternative endpoint, including across retries. On failure, body is the bounded prefix of the
// last content response, for scanning alongside an incomplete-source diagnostic.
func (f *textFetcher) getDocument(ctx context.Context, rawurl string) (fetchedText, error) {
	content := fetchedText{url: rawurl}
	origin, err := originOf(rawurl)
	if err != nil {
		return content, err
	}
	if !f.breaker.Allow(origin) {
		model.Note(ctx, "web_circuit_open", rawurl, true)
		return content, errors.New("origin circuit breaker is open")
	}
	var contentErr error
	err = resilience.Retry(ctx, 3, 300*time.Millisecond, 3*time.Second, func() (attemptErr error) {
		contentResponse := false
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
		if err != nil {
			return resilience.Permanent(err)
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "*/*")
		resp, err := f.client.Do(req)
		if err != nil {
			return err
		}
		defer func() {
			attemptErr = errors.Join(attemptErr, resp.Body.Close())
			if contentResponse && attemptErr != nil {
				contentErr = attemptErr
			}
		}()
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return errRetryable // retry rate-limit / server errors
		}
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
			if contentErr != nil {
				return resilience.Permanent(errors.Join(errors.New("content unavailable after an incomplete response"), contentErr))
			}
			return nil // Expected absence for guessed source maps and recon paths.
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			return resilience.Permanent(fmt.Errorf("HTTP status %d", resp.StatusCode))
		}
		content.present = true
		contentResponse = true
		content.url, err = responseContentURL(resp, rawurl, origin)
		addressErr := resilience.Permanent(err)
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
		// Preserve readable bytes even if a transport tail, close or byte cap fails. A later complete
		// response replaces this prefix (including with an empty body), never a 404/error response.
		content.text = string(b[:min(len(b), maxBodyBytes)])
		if err != nil {
			return errors.Join(addressErr, err)
		}
		if len(b) > maxBodyBytes {
			model.Note(ctx, "web_body_limit", rawurl, true)
			return errors.Join(addressErr, resilience.Permanent(fmt.Errorf("HTTP body exceeds %d bytes", maxBodyBytes)))
		}
		return addressErr
	})
	f.breaker.Record(origin, err == nil)
	if err != nil {
		model.Note(ctx, "web_fetch_failed", rawurl, true)
	}
	return content, err
}

func responseContentURL(resp *http.Response, requested, origin string) (string, error) {
	if resp.Request == nil || resp.Request.URL == nil {
		return requested, nil // Owned transports may omit optional response metadata.
	}
	address := *resp.Request.URL
	address.Fragment, address.RawFragment = "", ""
	final := address.String()
	finalOrigin, err := originOf(final)
	if err != nil || finalOrigin != origin {
		// Preserve readable content under its requested address, without adopting unsafe metadata.
		return requested, errors.New("HTTP content response has an invalid or changed origin")
	}
	return final, nil
}

var errRetryable = &retryErr{}

type retryErr struct{}

func (*retryErr) Error() string { return "retryable" }

func originOf(rawurl string) (string, error) {
	u, err := url.Parse(rawurl)
	if err != nil || u == nil {
		return "", errors.New("invalid HTTP origin")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("invalid HTTP origin")
	}
	// Reuse authority validation and IDNA/IP normalization without discarding the request path.
	target, err := ParseTarget(rawurl)
	if err != nil {
		return "", errors.New("invalid HTTP origin")
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if scheme == "https" {
			port = "443"
		}
	} else {
		n, _ := strconv.Atoi(port) // ParseTarget already validated the range.
		port = strconv.Itoa(n)
	}
	return scheme + "://" + net.JoinHostPort(target.Host, port), nil
}
