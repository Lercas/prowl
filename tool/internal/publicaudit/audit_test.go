package publicaudit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testKey = "13ad45b4d0a2f6ea65ecbddf6aa260f2"

var testBindings = map[string]string{"algolia_app_id": "ABCDEF1234"}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(body string, status int) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
func testAuditor(fn roundTrip) *Auditor {
	a := New(time.Second)
	a.client.Transport = fn
	return a
}
func aclBody(acl string) string { return `{"value":"` + testKey + `","acl":` + acl + `}` }

func TestSelfACLReadOnlyAndSeparateVerdict(t *testing.T) {
	for _, tc := range []struct{ acl, status string }{
		{`["search"]`, "search_only"},
		{`["search","addObject"]`, "excess_permissions"},
		{`["deleteIndex","editSettings","search"]`, "excess_permissions"},
		{`["browse"]`, "excess_permissions"},
	} {
		t.Run(tc.status+tc.acl, func(t *testing.T) {
			a := testAuditor(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet || r.URL.String() != "https://abcdef1234.algolia.net/1/keys/"+testKey || r.Body != nil || r.Header.Get("X-Algolia-API-Key") != testKey || r.Header.Get("X-Algolia-Application-Id") != "ABCDEF1234" {
					t.Fatal("unsafe self-ACL request")
				}
				return response(aclBody(tc.acl), 200), nil
			})
			result := a.Audit(t.Context(), "algolia-api-key", testKey, testBindings)
			if result.Status != tc.status || result.CheckedAt == "" {
				t.Fatalf("unexpected result: %+v", result)
			}
			serialized, _ := json.Marshal(result)
			if strings.Contains(string(serialized), testKey) || strings.Contains(string(serialized), "verified") {
				t.Fatal("audit leaked or became live-verification evidence")
			}
		})
	}
}

func TestBindingValidationNeverUsesSiblingValues(t *testing.T) {
	calls := 0
	a := testAuditor(func(*http.Request) (*http.Response, error) { calls++; return response(aclBody(`["search"]`), 200), nil })
	for _, bindings := range []map[string]string{
		nil, {}, {"unrelated": "ABCDEF1234"}, {"app_id": "x.ABCDEF1234"}, {"app_id": "ABCDEF1234.attacker.test"},
		{"app_id": "ABCDEF1234", "applicationId": "ZZZZZZ9999"}, {"app_id": "ABCDEF1234", "algolia_app_id": "invalid"},
	} {
		if got := a.Audit(t.Context(), "algolia-api-key", testKey, bindings); got.Status != "inconclusive" {
			t.Fatal(got)
		}
	}
	large := make(map[string]string)
	for i := 0; i < 129; i++ {
		large[fmt.Sprint(i)] = "x"
	}
	large["app_id"] = "ABCDEF1234"
	_ = a.Audit(t.Context(), "algolia-api-key", testKey, large)
	_ = a.Audit(t.Context(), "algolia-api-key", testKey+"/path", testBindings)
	if got := a.Audit(t.Context(), "google-api-key", testKey, testBindings); got != nil {
		t.Fatal("unsupported provider was audited")
	}
	if calls != 0 {
		t.Fatal("invalid binding triggered network access")
	}
	// Explicit aliases are accepted without searching through arbitrary values.
	if got := a.Audit(t.Context(), "algolia-api-key", testKey, map[string]string{"algoliaApplicationId": "ABCDEF1234"}); got.Status != "search_only" {
		t.Fatal(got)
	}
}

func TestUntrustedACLResponsesFailClosed(t *testing.T) {
	for _, body := range []string{
		`{}`, `null`, `[]`, `{"value":"` + testKey + `","acl":["search"],"ignored":"\ud800"}`, `{"value":"` + testKey + `","acl":["search"],"ACL":["addObject"]}`, aclBody(`null`), aclBody(`[]`), aclBody(`["search",null]`), aclBody(`"search"`),
		aclBody(`["search","unknown-` + testKey + `"]`), aclBody(`["search","search"]`),
		`{"value":"other","acl":["search"]}`, `{"acl":["search"]}`,
		aclBody(`["search"]`) + `{}`, strings.TrimSuffix(aclBody(`["search"]`), "}"),
		`{"value":"` + testKey + `","acl":["search"],"\u0061cl":["addObject"]}`,
		`{"value":"` + testKey + `","acl":["search"],"other":{"a":1,"a":2}}`,
		strings.TrimSuffix(aclBody(`["search"]`), "}") + `,"nested":` + strings.Repeat("[", 20) + `0` + strings.Repeat("]", 20) + `}`,
		strings.TrimSuffix(aclBody(`["search"]`), "}") + `,"number":NaN}`,
	} {
		got := parseACL([]byte(body), testKey)
		if got.Status != "inconclusive" || len(got.Capabilities) != 0 || strings.Contains(got.Reason, testKey) {
			t.Fatalf("unsafe ACL accepted: %s", body)
		}
	}
}

func TestTransportErrorsDenialAndLimits(t *testing.T) {
	for _, status := range []int{201, 204, 301, 302, 400, 401, 403, 404, 429, 500, 503} {
		a := testAuditor(func(*http.Request) (*http.Response, error) { return response(testKey, status), nil })
		if got := a.Audit(t.Context(), "algolia-api-key", testKey, testBindings); got.Status != "inconclusive" {
			t.Fatal(status, got)
		}
	}
	for _, fn := range []roundTrip{
		func(*http.Request) (*http.Response, error) { return nil, errors.New("secret https://host/" + testKey) },
		func(*http.Request) (*http.Response, error) {
			return response(strings.Repeat(testKey, maxBody), 200), nil
		},
	} {
		a := testAuditor(fn)
		got := a.Audit(t.Context(), "algolia-api-key", testKey, testBindings)
		b, _ := json.Marshal(got)
		if got.Status != "inconclusive" || strings.Contains(string(b), testKey) {
			t.Fatal("unsafe failure")
		}
	}
	a := New(time.Second)
	req, _ := http.NewRequest(http.MethodGet, "https://same.algolia.net/other", nil)
	if a.client.CheckRedirect(req, nil) != http.ErrUseLastResponse {
		t.Fatal("redirects can forward credentials")
	}
}

func TestCacheCoalescingIsolationAndBudget(t *testing.T) {
	var calls atomic.Int32
	a := testAuditor(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return response(aclBody(`["search","addObject"]`), 200), nil
	})
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Go(func() {
			got := a.Audit(t.Context(), "algolia-api-key", testKey, testBindings)
			if got.Status != "excess_permissions" {
				t.Error(got)
			}
			got.Capabilities[0] = "mutated"
		})
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("duplicate provider requests", calls.Load())
	}
	if got := a.Audit(t.Context(), "algolia-api-key", testKey, testBindings); got.Capabilities[0] == "mutated" {
		t.Fatal("mutable cached evidence")
	}
	_ = a.Audit(t.Context(), "algolia-api-key", testKey, map[string]string{"app_id": "ZZZZZZ9999"})
	if calls.Load() != 2 {
		t.Fatal("application ID omitted from cache key")
	}
	b := testAuditor(func(*http.Request) (*http.Response, error) { calls.Add(1); return response("denied", 403), nil })
	for i := 0; i < maxRequests+5; i++ {
		_ = b.Audit(t.Context(), "algolia-api-key", testKey, testBindings)
	}
	if calls.Load() != maxRequests+2 {
		t.Fatal("request budget or inconclusive retry changed", calls.Load())
	}
	if len(b.entries) != 0 {
		t.Fatal("inconclusive responses became cached evidence")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := a.Audit(ctx, "algolia-api-key", testKey, testBindings); got.Status != "inconclusive" {
		t.Fatal("canceled audit returned cached success")
	}
}

func TestWaitingCallerCancellation(t *testing.T) {
	started, finish := make(chan struct{}), make(chan struct{})
	a := testAuditor(func(*http.Request) (*http.Response, error) {
		close(started)
		<-finish
		return response(aclBody(`["search"]`), 200), nil
	})
	done := make(chan struct{})
	go func() { defer close(done); _ = a.Audit(t.Context(), "algolia-api-key", testKey, testBindings) }()
	<-started
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := a.Audit(ctx, "algolia-api-key", testKey, testBindings); got.Status != "inconclusive" {
		t.Fatal(got)
	}
	close(finish)
	<-done
}

func TestOwnedHTTPFixture(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "GET" || r.URL.Path != "/1/keys/"+testKey || r.Header.Get("X-Algolia-API-Key") != testKey || r.Header.Get("X-Algolia-Application-Id") != "ABCDEF1234" {
			t.Error("incorrect wire request")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, aclBody(`["search","addObject"]`))
	}))
	defer server.Close()
	local, _ := url.Parse(server.URL)
	a := New(time.Second)
	transport := server.Client().Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	a.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.URL.Host != "abcdef1234.algolia.net" {
			t.Error("provider authority changed")
		}
		clone := r.Clone(r.Context())
		u := *r.URL
		u.Scheme, u.Host = local.Scheme, local.Host
		clone.URL = &u
		return transport.RoundTrip(clone)
	})
	if result := a.Audit(t.Context(), "algolia-api-key", testKey, testBindings); result.Status != "excess_permissions" || requests.Load() != 1 {
		t.Fatal("owned wire fixture failed", result)
	}
}
