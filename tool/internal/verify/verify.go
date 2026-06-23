// Package verify checks whether a detected secret is live using data-driven verifiers authored as
// YAML (an HTTP request plus conditional matchers). Verification is opt-in and never logs the secret.
package verify

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Lercas/prowl/tool/internal/safehttp"
)

// Status is the outcome of a verification attempt.
type Status string

const (
	Verified    Status = "verified"    // provider confirmed the credential is live
	Invalid     Status = "invalid"     // provider rejected it — likely revoked/fake
	Unsupported Status = "unsupported" // no verifier matches this type
	Errored     Status = "error"       // network/timeout — inconclusive
	Skipped     Status = "skipped"     // example/placeholder — not attempted
)

// Result carries the status, an optional note, and which verifier produced it.
type Result struct {
	Status   Status
	Verifier string
	Note     string
}

// Matcher is a conditional check on a response: status code, a word in the body/headers, or a regex.
type Matcher struct {
	Type      string   `yaml:"type"` // status | word | regex
	Status    []int    `yaml:"status"`
	Words     []string `yaml:"words"`
	Regex     []string `yaml:"regex"`
	Part      string   `yaml:"part"`      // body (default) | header
	Condition string   `yaml:"condition"` // and | or (default or)
	Negative  bool     `yaml:"negative"`

	res []*regexp.Regexp
}

// Request is one HTTP probe. URL/headers/body are interpolated with the secret before sending.
type Request struct {
	Method            string            `yaml:"method"` // GET (default) | POST | …
	URL               string            `yaml:"url"`
	Headers           map[string]string `yaml:"headers"`
	Body              string            `yaml:"body"`
	MatchersCondition string            `yaml:"matchers-condition"` // and (default) | or
	Matchers          []Matcher         `yaml:"matchers"`
}

// Verifier is one declarative provider check. The secret is live if any request's matchers pass.
type Verifier struct {
	ID   string `yaml:"id"`
	Info struct {
		Name      string `yaml:"name"`
		Author    string `yaml:"author"`
		Reference string `yaml:"reference"`
	} `yaml:"info"`
	Match      []string          `yaml:"match"`
	Extract    map[string]string `yaml:"extract"`     // name -> regex pulled from the finding's context
	Sign       string            `yaml:"sign"`        // signer name (e.g. awsv4) for request signing
	SignParams map[string]string `yaml:"sign_params"` // signer args (region, service, …)
	Requests   []Request         `yaml:"requests"`

	path       string
	extractRes map[string]*regexp.Regexp
}

// Set is a loaded verifier registry with an HTTP client, a per-value result cache, and a
// concurrency limiter.
type Set struct {
	client    *http.Client
	verifiers []*Verifier
	cache     sync.Map      // value -> Result
	sem       chan struct{} // bounds concurrent provider calls
}

// DefaultConcurrency bounds simultaneous verification HTTP calls. concurrency holds the active value,
// overridable via config (performance.verify_concurrency); set once at startup before any verify.
const DefaultConcurrency = 8

var concurrency = DefaultConcurrency

// SetConcurrency overrides the live-verification concurrency; a non-positive value is ignored.
func SetConcurrency(n int) {
	if n > 0 {
		concurrency = n
	}
}

// Supports reports whether any verifier could match the type id.
func (s *Set) Supports(typeID string) bool {
	return s.find(typeID, "") != nil
}

// Count returns the number of loaded verifiers.
func (s *Set) Count() int { return len(s.verifiers) }

// genericStopwords are match keywords too non-specific to identify a provider: nearly every typed
// finding contains "api-"/"token"/"key", so routing on one would mis-route a finding (and exfil its
// plaintext) to whichever verifier lists it. These never qualify as a provider-identity match.
var genericStopwords = map[string]bool{
	"api": true, "api-": true, "api_": true, "apikey": true, "api-key": true, "api_key": true,
	"token": true, "key": true, "secret": true, "auth": true, "bearer": true, "access": true,
	"app": true, "id": true, "pat": true, "sk": true, "pk": true, "v1": true, "dev": true, "prod": true,
	"_": true, "-": true, ".": true, "": true,
}

// alnumCount counts the alphanumeric runes in s (the "stem" of an anchor, separators excluded).
func alnumCount(s string) int {
	n := 0
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			n++
		}
	}
	return n
}

func hasSeparator(s string) bool { return strings.ContainsAny(s, "_-.") }

// typeMatchOK reports whether anchor (a substring of the finding type) is specific enough to route
// on the TYPE: it must relate to the verifier id (one contains the other) or be a distinctive
// provider token (≥5 alphanumeric chars), never a bare stopword like "api-"/"token"/"key".
func typeMatchOK(anchor, id string) bool {
	if genericStopwords[anchor] {
		return false
	}
	if strings.Contains(id, anchor) || strings.Contains(anchor, id) {
		return true
	}
	return alnumCount(anchor) >= 5
}

// valueMatchOK reports whether anchor (a lowercased substring of value) is specific enough to route
// on the VALUE. The discriminator is prefix-anchoring: a real provider token carries its prefix at
// position 0 (re_/pk_/r8_/hf_/ls__…), far more specific than the same fragment buried mid-string.
//   - prefix of the value: a short structured token qualifies (separator or ≥3-char stem);
//   - mid-string only: stricter bar (≥6 chars, or separator + ≥3-char stem, or ≥4-char plain token).
//
// A generic stem ("pk", "sk", "api-", …) is a stopword and never qualifies, even as a prefix.
func valueMatchOK(anchor, value string) bool {
	if genericStopwords[anchor] {
		return false
	}
	// (1) Prefix-anchored: a structured token at the start is provider-specific even when short.
	if strings.HasPrefix(value, anchor) && (hasSeparator(anchor) || alnumCount(anchor) >= 3) {
		return true
	}
	// (2) Mid-string (coincidental): keep the stricter, length-based bar.
	if len(anchor) >= 6 {
		return true
	}
	if hasSeparator(anchor) && alnumCount(anchor) >= 3 {
		return true
	}
	if alnumCount(anchor) >= 4 && !strings.ContainsAny(anchor[:1], "-_.") {
		return true
	}
	return false
}

// find selects the verifier by best match (not load order): a TYPE match (authoritative provider
// identity) outranks a value match, and a longer keyword outranks a shorter one. A minimum-specificity
// guard (typeMatchOK/valueMatchOK) rejects matches too generic to identify a provider — an inadequate
// match yields no route (the finding becomes Unsupported) rather than mis-routing its plaintext to the
// wrong provider. A genuine short provider value-prefix (sk_live_, re_, …) still routes.
func (s *Set) find(typeID, value string) *Verifier {
	lt, lv := strings.ToLower(typeID), strings.ToLower(value)
	var best *Verifier
	bestScore := 0
	for _, v := range s.verifiers {
		lid := strings.ToLower(v.ID)
		for _, m := range v.Match {
			lm := strings.ToLower(m)
			if lm == "" {
				continue
			}
			score := 0
			switch {
			case strings.Contains(lt, lm) && typeMatchOK(lm, lid):
				score = 1000 + len(lm) // TYPE match is authoritative; longer = more specific
			case strings.Contains(lv, lm) && valueMatchOK(lm, lv):
				score = len(lm) // value-only fallback, never beats a type match
			}
			if score > bestScore {
				bestScore, best = score, v
			}
		}
	}
	return best
}

// Verify confirms a secret is live by running its verifier's requests. context is the surrounding
// text, from which a verifier may extract secondary values. Examples are skipped; results cached.
func (s *Set) Verify(ctx context.Context, typeID, value, context string, isExample bool) Result {
	if isExample {
		return Result{Status: Skipped}
	}
	if r, ok := s.cache.Load(value); ok {
		return r.(Result)
	}
	v := s.find(typeID, value)
	if v == nil {
		return Result{Status: Unsupported}
	}
	res := s.run(ctx, v, value, context)
	s.cache.Store(value, res)
	return res
}

func (s *Set) run(ctx context.Context, v *Verifier, value, context string) Result {
	vars := map[string]string{"secret": value}
	for name, re := range v.extractRes {
		if m := re.FindString(context); m != "" {
			vars[name] = m
		}
	}
	var lastErr error
	for i := range v.Requests {
		ok, err := s.probe(ctx, v, &v.Requests[i], vars)
		if err != nil {
			lastErr = err
			continue
		}
		if ok {
			return Result{Status: Verified, Verifier: v.ID, Note: v.Info.Name}
		}
	}
	if lastErr != nil {
		// Never surface lastErr.Error(): a *url.Error embeds the full request URL, which carries
		// the interpolated {{secret}}. Report only a coarse, secret-free category.
		return Result{Status: Errored, Verifier: v.ID, Note: classifyErr(lastErr)}
	}
	return Result{Status: Invalid, Verifier: v.ID}
}

// classifyErr maps a transport error to a fixed, secret-free category string. It inspects error
// values via errors.As (never the error's text, which can embed the URL+secret).
func classifyErr(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, safehttp.ErrBlockedAddress) {
		return "blocked address"
	}
	if errors.Is(err, safehttp.ErrCrossHostRedirect) {
		return "cross-host redirect blocked"
	}
	if errors.Is(err, errBadInterpolation) {
		return "invalid request"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	var tlsErr *tls.CertificateVerificationError
	if errors.As(err, &tlsErr) {
		return "TLS error"
	}
	if _, ok := err.(tls.RecordHeaderError); ok {
		return "TLS error"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "DNS error"
	}
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) {
		return "DNS error"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var syscallErr *os.SyscallError
		if errors.As(opErr.Err, &syscallErr) {
			if errors.Is(syscallErr.Err, syscall.ECONNREFUSED) {
				return "connection refused"
			}
			if errors.Is(syscallErr.Err, syscall.ETIMEDOUT) {
				return "timeout"
			}
		}
		switch opErr.Op {
		case "dial":
			return "connection failed"
		case "read", "write":
			return "connection reset"
		}
		return "connection failed"
	}
	return "request failed"
}

// errBadInterpolation is returned when an interpolated secret reshapes the request (e.g. embeds
// CR/LF or other control characters) or yields an unparseable URL. It carries no secret.
var errBadInterpolation = errors.New("interpolated value contains invalid characters")

// hasControlChars reports whether s contains any control character (CR, LF, NUL, DEL, …) other than
// tab — runes that could split the request or smuggle extra headers from a URL/header value.
func hasControlChars(s string) bool {
	for _, r := range s {
		if r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func (s *Set) probe(ctx context.Context, v *Verifier, r *Request, vars map[string]string) (bool, error) {
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	bodyStr := interpolate(r.Body, vars)
	var body io.Reader
	if bodyStr != "" {
		body = strings.NewReader(bodyStr)
	}
	// Reject control chars in interpolated URL/header positions (request splitting / header
	// smuggling) and confirm the final URL still parses before sending.
	rawURL := interpolate(r.URL, vars)
	if hasControlChars(rawURL) {
		return false, errBadInterpolation
	}
	if _, perr := url.Parse(rawURL); perr != nil {
		return false, errBadInterpolation
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return false, err
	}
	for k, vv := range r.Headers {
		hv := interpolate(vv, vars)
		if hasControlChars(hv) {
			return false, errBadInterpolation
		}
		req.Header.Set(k, hv)
	}
	if v.Sign != "" {
		signer, ok := signers[v.Sign]
		if !ok {
			return false, fmt.Errorf("unknown signer %q", v.Sign)
		}
		if err := signer(req, []byte(bodyStr), vars["secret"], vars, v.SignParams); err != nil {
			return false, err
		}
	}
	if s.sem != nil { // acquire a slot but stay cancellable while waiting
		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return matchResponse(r, resp, respBody), nil
}

func matchResponse(r *Request, resp *http.Response, body []byte) bool {
	and := !strings.EqualFold(r.MatchersCondition, "or") // default AND
	if len(r.Matchers) == 0 {                            // no matchers: 2xx means live
		return resp.StatusCode >= 200 && resp.StatusCode < 300
	}
	all, any := true, false
	for i := range r.Matchers {
		ok := r.Matchers[i].eval(resp, body)
		if r.Matchers[i].Negative {
			ok = !ok
		}
		all = all && ok
		any = any || ok
	}
	if and {
		return all
	}
	return any
}

func (m *Matcher) eval(resp *http.Response, body []byte) bool {
	switch m.Type {
	case "status":
		for _, c := range m.Status {
			if resp.StatusCode == c {
				return true
			}
		}
		return false
	case "word":
		hay := wordHaystack(m.Part, resp, body)
		return listCond(len(m.Words), m.Condition, func(i int) bool {
			return strings.Contains(hay, m.Words[i])
		})
	case "regex":
		hay := wordHaystack(m.Part, resp, body)
		return listCond(len(m.res), m.Condition, func(i int) bool {
			return m.res[i].MatchString(hay)
		})
	}
	return false
}

func wordHaystack(part string, resp *http.Response, body []byte) string {
	if strings.EqualFold(part, "header") {
		var b bytes.Buffer
		_ = resp.Header.Write(&b)
		return b.String()
	}
	return string(body)
}

func listCond(n int, cond string, ok func(int) bool) bool {
	if n == 0 {
		return false
	}
	all := strings.EqualFold(cond, "and")
	for i := 0; i < n; i++ {
		if v := ok(i); all && !v {
			return false
		} else if !all && v {
			return true
		}
	}
	return all
}

// New returns an empty set with the given per-request timeout.
func New(timeout time.Duration) *Set {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &Set{client: safehttp.Client(timeout), sem: make(chan struct{}, concurrency)}
}
