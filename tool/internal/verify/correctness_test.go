package verify

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type verifierRoundTripFunc func(*http.Request) (*http.Response, error)

func (f verifierRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mockSet(t *testing.T, client *http.Client, vs ...*Verifier) *Set {
	t.Helper()
	for _, v := range vs {
		if err := compileVerifier(v); err != nil {
			t.Fatal(err)
		}
	}
	return &Set{client: client, verifiers: vs, sem: make(chan struct{}, 2)}
}

func TestCacheIsScopedToVerifierAndExtractedCredentials(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path == "/beta" || r.Header.Get("X-Account") == "tenant_b" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(server.Close)
	alpha := &Verifier{ID: "alpha", Match: []string{"alpha"}, Extract: map[string]string{"account": `tenant_[ab]`}, Requests: []Request{{URL: server.URL + "/alpha", Headers: map[string]string{"X-Account": "{{account}}"}}}}
	beta := &Verifier{ID: "beta", Match: []string{"beta"}, Requests: []Request{{URL: server.URL + "/beta"}}}
	set := mockSet(t, server.Client(), alpha, beta)
	for _, tc := range []struct {
		typ, context string
		want         Status
	}{{"alpha", "tenant_a", Verified}, {"alpha", "tenant_a unrelated text", Verified}, {"beta", "", Invalid}, {"unknown", "", Unsupported}, {"alpha", "tenant_b", Invalid}} {
		if r := set.Verify(context.Background(), tc.typ, "owned-value", tc.context, false); r.Status != tc.want {
			t.Errorf("%s/%s: got %s want %s", tc.typ, tc.context, r.Status, tc.want)
		}
	}
	if requests != 3 {
		t.Errorf("expected 3 distinct probes, got %d", requests)
	}
}

func TestTransientVerificationErrorDoesNotPoisonCache(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: verifierRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("owned network failure")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	set := mockSet(t, client, &Verifier{ID: "alpha", Match: []string{"alpha"}, Requests: []Request{{URL: "https://owned.invalid/"}}})
	for _, want := range []Status{Errored, Verified, Verified} {
		if r := set.Verify(context.Background(), "alpha", "owned-value", "", false); r.Status != want {
			t.Errorf("got %s want %s", r.Status, want)
		}
	}
	if calls != 2 {
		t.Errorf("cache/retry issued %d probes", calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := set.Verify(ctx, "alpha", "owned-value", "", false); r.Status != Errored {
		t.Errorf("cancelled lookup returned %s", r.Status)
	}
}

type brokenVerifierBody struct{ sent bool }

func (r *brokenVerifierBody) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		return copy(p, "LIVE"), nil
	}
	return 0, io.ErrUnexpectedEOF
}
func (*brokenVerifierBody) Close() error { return nil }

func TestIncompleteProviderResponsesAreInconclusive(t *testing.T) {
	for _, mode := range []string{"read-error", "oversize-positive", "oversize-negative", "http-500", "http-502"} {
		t.Run(mode, func(t *testing.T) {
			body := io.NopCloser(strings.NewReader("LIVE"))
			status := 200
			switch mode {
			case "read-error":
				body = &brokenVerifierBody{}
			case "oversize-positive":
				body = io.NopCloser(strings.NewReader("LIVE" + strings.Repeat("x", 1<<16)))
			case "oversize-negative":
				body = io.NopCloser(strings.NewReader(strings.Repeat("x", 1<<16) + "LIVE"))
			case "http-500":
				status = 500
			case "http-502":
				status = 502
			}
			client := &http.Client{Transport: verifierRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: body}, nil
			})}
			negative := mode == "oversize-negative"
			v := &Verifier{ID: "alpha", Match: []string{"alpha"}, Requests: []Request{{URL: "https://owned.invalid/", Matchers: []Matcher{{Type: "word", Words: []string{"LIVE"}, Negative: negative}, {Type: "status", Status: []int{200}}}}}}
			set := mockSet(t, client, v)
			if r := set.Verify(context.Background(), "alpha", "owned-value", "", false); r.Status != Errored {
				t.Fatalf("incomplete response returned %s", r.Status)
			}
		})
	}
}

func TestInterpolateNeverReinterpretsInsertedValues(t *testing.T) {
	vars := map[string]string{"secret": "my_account_sid_{{account_sid}}", "account_sid": "owned-account"}
	const value = "my_account_sid_{{account_sid}}"
	if got := interpolate("{{secret}}:{{account_sid}}", vars); got != value+":owned-account" {
		t.Errorf("recursive interpolation: %q", got)
	}
	if got := interpolate("{{base64(secret:account_sid)}}", vars); got != base64.StdEncoding.EncodeToString([]byte(value+":owned-account")) {
		t.Errorf("base64 altered inserted credentials: %q", got)
	}
	if got := interpolate("{{base64(secret_suffix:secret)}}", map[string]string{"secret": "owned"}); got != base64.StdEncoding.EncodeToString([]byte("secret_suffix:owned")) {
		t.Errorf("base64 expanded a partial variable name: %q", got)
	}
}

func TestRetryAfterCannotOverflow(t *testing.T) {
	for _, h := range []string{strconv.FormatInt(1<<63-1, 10), "9999999999999999999999999999"} {
		resp := &http.Response{Header: http.Header{"Retry-After": []string{h}}}
		if got := retryAfter(resp); got != verifyMaxBackoff {
			t.Errorf("Retry-After %s = %s, want clamp %s", h, got, verifyMaxBackoff)
		}
	}
}

func TestMissingContextNeverSendsLiteralPlaceholders(t *testing.T) {
	for _, basic := range []bool{false, true} {
		t.Run(fmt.Sprint(basic), func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: verifierRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 401, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
			})}
			header := "{{account}}"
			if basic {
				header = "Basic {{base64(account:secret)}}"
			}
			v := &Verifier{ID: "alpha", Match: []string{"alpha"}, Extract: map[string]string{"account": `tenant_[ab]`}, Requests: []Request{{URL: "https://owned.invalid/", Headers: map[string]string{"Authorization": header}}}}
			set := mockSet(t, client, v)
			if r := set.Verify(context.Background(), "alpha", "owned-value", "no account here", false); r.Status != Errored {
				t.Errorf("missing context returned %s", r.Status)
			}
			if calls != 0 {
				t.Errorf("sent %d invalid probes", calls)
			}
		})
	}
}

func TestResponseAtExactByteLimitIsComplete(t *testing.T) {
	client := &http.Client{Transport: verifierRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 1<<16)))}, nil
	})}
	set := mockSet(t, client, &Verifier{ID: "alpha", Match: []string{"alpha"}, Requests: []Request{{URL: "https://owned.invalid/"}}})
	if r := set.Verify(context.Background(), "alpha", "owned-value", "", false); r.Status != Verified {
		t.Fatal(r)
	}
}

func TestConcurrentDuplicateSharesProbeAndWaiterCanCancel(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var calls atomic.Int64
	client := &http.Client{Transport: verifierRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	v := &Verifier{ID: "alpha", Match: []string{"alpha"}, Requests: []Request{{URL: "https://owned.invalid/", Capability: "owned-capability"}}}
	set := mockSet(t, client, v)
	owner := make(chan Result, 1)
	go func() { owner <- set.Verify(context.Background(), "alpha", "owned-value", "", false) }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if r := set.Verify(ctx, "alpha", "owned-value", "", false); r.Status != Errored || r.Note != "timeout" {
		t.Errorf("waiting caller did not cancel: %+v", r)
	}
	if calls.Load() != 1 {
		t.Errorf("duplicate verification sent %d probes", calls.Load())
	}
	close(release)
	first := <-owner
	if first.Status != Verified {
		t.Fatalf("owner was canceled by waiter: %+v", first)
	}
	first.Access[0] = "caller mutation"
	if cached := set.Verify(context.Background(), "alpha", "owned-value", "", false); cached.Status != Verified || len(cached.Access) != 1 || cached.Access[0] != "owned-capability" {
		t.Fatalf("cached result was mutated: %+v", cached)
	}
}

func TestRateLimitRetryReplaysPOSTBodyExactly(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "credential=owned-value" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer owned-value" {
			t.Errorf("retry altered request: method=%s body=%q err=%v", r.Method, body, err)
		}
		if requests == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	v := &Verifier{ID: "alpha", Match: []string{"alpha"}, Requests: []Request{{Method: "POST", URL: srv.URL, Body: "credential={{secret}}", Headers: map[string]string{"Authorization": "Bearer {{secret}}"}}}}
	set := mockSet(t, srv.Client(), v)
	if r := set.Verify(context.Background(), "alpha", "owned-value", "", false); r.Status != Verified || requests != 2 {
		t.Fatalf("POST retry failed: %+v requests=%d", r, requests)
	}
}

func TestExtractCannotReplaceDetectedSecret(t *testing.T) {
	v := &Verifier{ID: "alpha", Match: []string{"alpha"}, Extract: map[string]string{"secret": ".*"}, Requests: []Request{{URL: "https://owned.invalid/"}}}
	if err := compileVerifier(v); err == nil {
		t.Fatal("context can replace the detected secret")
	}
}
