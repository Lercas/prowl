// Package atlassian scans Jira and Confluence (Cloud, Server, and Data Center) for leaked secrets,
// walking EVERY historical version of each issue and page — not just current content — so a
// credential that was added and later removed is still caught. See API_REFERENCE.md for the
// endpoint matrix and the Cloud-vs-Server/DC version differences this package handles.
package atlassian

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/Lercas/prowl/tool/internal/jsonstrict"
	"github.com/Lercas/prowl/tool/internal/safehttp"
)

// Auth carries credentials for one Atlassian instance. Cloud uses Basic(email:api-token);
// Server/Data Center uses a Personal Access Token (Bearer, PAT) or Basic(user:password).
// A Cloud API token is NOT a password and does NOT work on Server/DC, and vice versa.
type Auth struct {
	Email, Token string // Cloud: email + API token  -> Basic base64(email:token)
	PAT          string // Server/DC: personal access token -> Bearer <pat> (literal, not base64)
	User, Pass   string // Server/DC: username + password -> Basic base64(user:pass)
}

func (a Auth) header() string {
	switch {
	case a.PAT != "":
		return "Bearer " + a.PAT
	case a.Email != "" && a.Token != "":
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(a.Email+":"+a.Token))
	case a.User != "":
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(a.User+":"+a.Pass))
	}
	return ""
}

// Empty reports whether no usable credential was provided.
func (a Auth) Empty() bool { return a.header() == "" }

// Client is a thin JSON HTTP client for one Atlassian base URL: it injects auth, honors 429/503
// Retry-After with bounded exponential backoff, and decodes JSON. Safe for concurrent use.
type Client struct {
	http     *http.Client
	base     string // normalized base URL, no trailing slash (may include a context path)
	authHdr  string
	maxRetry int
	initErr  error // invalid input is retained as a safe failure, never as a raw URL
}

// NewClient builds a Client over the SSRF-guarded transport (Server/DC on an internal host needs
// PROWL_ALLOW_PRIVATE_IPS=1, like domain scanning). Any userinfo in the base URL
// (https://user:token@host — a natural attempt to inline credentials) is STRIPPED so the secret
// never reaches a log, an error, or a finding's Meta["url"].
// userAgent identifies prowl to Atlassian (and any WAF in front of a Server/DC instance, which may
// 403 the default Go-http-client UA). maxResponseBytes bounds a single JSON response read.
const (
	userAgent        = "prowl (+https://github.com/Lercas/prowl)"
	maxResponseBytes = 64 << 20 // 64 MB — generous for any real issue/page, finite against a hostile body
)

func NewClient(base string, auth Auth, timeout time.Duration) *Client {
	base, initErr := normalizeBaseURL(base)
	hc := safehttp.Client(timeout)
	// The walk hammers ONE host with many concurrent requests. On HTTP/1.1 (typical Server/DC) Go's
	// default MaxIdleConnsPerHost of 2 means beyond two workers each request re-handshakes TCP+TLS every
	// burst — pure latency; raising it lets the pool reuse keep-alive connections. (On Cloud the
	// transport negotiates HTTP/2 and multiplexes all workers onto one connection, so this is a no-op
	// there — harmless.) Fresh transport per client, so mutating it is local; shared safehttp untouched.
	if tr, ok := hc.Transport.(*http.Transport); ok {
		tr.MaxIdleConnsPerHost = 32
	}
	return &Client{
		http:     hc,
		base:     base,
		authHdr:  auth.header(),
		maxRetry: 5,
		initErr:  initErr,
	}
}

func normalizeBaseURL(raw string) (string, error) {
	invalid := errors.New("invalid Atlassian base URL: expected an absolute HTTP(S) URL with a host and valid port")
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", invalid
	}
	if strings.HasPrefix(u.Host, "[") {
		ip, err := netip.ParseAddr(u.Hostname())
		if err != nil || !ip.Is6() {
			return "", invalid
		}
	} else if strings.Contains(u.Hostname(), ":") {
		return "", invalid
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", invalid
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", invalid
		}
	}
	// Always clear optional URL components, including a bare '?' (ForceQuery). Preserve escaped
	// context paths: trimming decoded Path would reinterpret a trailing encoded slash (%2F).
	u.User, u.RawQuery, u.Fragment, u.RawFragment = nil, "", "", ""
	u.ForceQuery = false
	return strings.TrimRight(u.String(), "/"), nil
}

// clientFailure preserves cause classification without printing provider/transport-controlled
// error text, which may include a redirect URL, userinfo, or a secret response fragment.
type clientFailure struct {
	operation string
	cause     error
}

func (e *clientFailure) Error() string { return "atlassian " + e.operation + " failed" }
func (e *clientFailure) Unwrap() error { return e.cause }

// reqError carries the HTTP status so callers can branch fallbacks on 401/404/410.
type reqError struct {
	Status int
	URL    string
	Body   string
}

func (e *reqError) Error() string {
	return fmt.Sprintf("atlassian HTTP request failed (status %d)", e.Status)
}

// statusOf returns the HTTP status of a request error, or 0 if it was not an HTTP error.
func statusOf(err error) int {
	var re *reqError
	if errors.As(err, &re) {
		return re.Status
	}
	return 0
}

func (c *Client) get(ctx context.Context, path string, params url.Values, out any) error {
	return c.do(ctx, http.MethodGet, path, params, nil, out)
}

func (c *Client) post(ctx context.Context, path string, params url.Values, body, out any) error {
	return c.do(ctx, http.MethodPost, path, params, body, out)
}

func (c *Client) do(ctx context.Context, method, path string, params url.Values, body, out any) error {
	if c.initErr != nil {
		return c.initErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	full := c.base + path
	if len(params) > 0 {
		full += "?" + params.Encode()
	}
	var bodyBytes []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return &clientFailure{operation: "request encoding", cause: err}
		}
		bodyBytes = b
	}

	backoff := 500 * time.Millisecond
	for attempt := 0; ; attempt++ {
		var reader io.Reader
		if bodyBytes != nil {
			reader = strings.NewReader(string(bodyBytes))
		}
		req, err := http.NewRequestWithContext(ctx, method, full, reader)
		if err != nil {
			return &clientFailure{operation: "request construction", cause: err}
		}
		if c.authHdr != "" {
			req.Header.Set("Authorization", c.authHdr)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", userAgent) // some Server/DC WAFs 403 the default Go-http-client UA
		if bodyBytes != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.http.Do(req)
		if err != nil {
			return &clientFailure{operation: "HTTP request", cause: err}
		}

		// Rate limited / transiently unavailable: honor Retry-After, bounded retries.
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			// Add jitter so a pool of workers that all hit a 429 at once don't retry in lockstep (a
			// thundering herd that re-trips the rate limit). Up to +50% of the computed wait, with a hard
			// ceiling so the total can't exceed the intended cap even after jitter.
			wait := retryAfter(resp, backoff)
			wait += time.Duration(rand.Int64N(int64(wait)/2 + 1))
			if wait > 90*time.Second {
				wait = 90 * time.Second
			}
			_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			closeErr := resp.Body.Close()
			if readErr != nil || closeErr != nil {
				return &clientFailure{operation: "rate-limit response cleanup", cause: errors.Join(readErr, closeErr)}
			}
			if attempt >= c.maxRetry {
				return &reqError{Status: resp.StatusCode, URL: full, Body: "rate limited; retries exhausted"}
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
			if backoff < 16*time.Second {
				backoff *= 2
			}
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			resp.Body.Close()
			return &reqError{Status: resp.StatusCode, URL: full, Body: string(b)}
		}

		// Read through EOF even if the first JSON value is already complete. Otherwise trailing
		// bytes, a failed transport tail or an over-budget response could be reported as complete.
		if out == nil {
			n, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes+1))
			closeErr := resp.Body.Close()
			return checkedResponse(ctx, n, readErr, closeErr)
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
		closeErr := resp.Body.Close()
		if err := checkedResponse(ctx, int64(len(raw)), readErr, closeErr); err != nil {
			return err
		}
		// Validate the expected endpoint shape before committing it to the caller. A JSON error
		// object with HTTP 200 must never be confused with an empty issue/version listing.
		dst := reflect.ValueOf(out)
		if dst.Kind() != reflect.Pointer || dst.IsNil() {
			return errors.New("invalid Atlassian response destination")
		}
		parsed := reflect.New(dst.Type().Elem())
		if err := jsonstrict.UnmarshalContext(ctx, raw, parsed.Interface()); err != nil {
			return err
		}
		if err := validateResponse(parsed.Interface()); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		dst.Elem().Set(parsed.Elem())
		return nil
	}
}

func checkedResponse(ctx context.Context, n int64, readErr, closeErr error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if n > maxResponseBytes {
		return errors.New("atlassian response exceeds the byte budget")
	}
	if readErr != nil {
		return errors.New("atlassian response read failed")
	}
	if closeErr != nil {
		return errors.New("atlassian response close failed")
	}
	return nil
}

func retryAfter(resp *http.Response, fallback time.Duration) time.Duration {
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(strings.TrimSpace(ra)); err == nil && secs >= 0 {
			if secs > 60 {
				secs = 60 // cap a hostile Retry-After BEFORE the multiply, else a huge value
			} // overflows int64 nanoseconds to a NEGATIVE Duration (slips past a post-multiply cap and
			return time.Duration(secs) * time.Second // makes the caller's rand.Int64N argument <=0 -> panic)
		}
	}
	return fallback
}
