package hermesaudit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

type testTransport func(*http.Request) (*http.Response, error)

func (f testTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPassiveProvidersRestrictQueriesToExactIPAndOmitPayload(t *testing.T) {
	for _, name := range []string{"CENSYS_API_TOKEN", "SHODAN_API_KEY", "FOFA_EMAIL", "FOFA_KEY", "ZOOMEYE_API_KEY", "LEAKIX_API_KEY"} {
		t.Setenv(name, "synthetic-operator-credential")
	}
	client := &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" {
			t.Fatal("provider request must use HTTPS")
		}
		switch r.URL.Host {
		case "api.platform.censys.io", "api.shodan.io", "leakix.net":
			if !strings.HasSuffix(r.URL.Path, "/203.0.113.10") {
				t.Fatalf("lookup expanded the exact target: %s", r.URL.Path)
			}
		case "fofa.so", "api.zoomeye.ai":
			query := r.URL.Query().Get("qbase64")
			if r.Method == http.MethodPost {
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				query, _ = body["qbase64"].(string)
			}
			decoded, err := base64.StdEncoding.DecodeString(query)
			if err != nil || string(decoded) != `ip="203.0.113.10"` {
				t.Fatalf("non-exact passive query: %q", decoded)
			}
		default:
			t.Fatalf("unexpected provider: %s", r.URL.Host)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(
			`{"services":[{"port":9119,"banner":"Hermes Agent raw-private-payload"},{"port":"443"},{"port":443},{"port":0},{"port":65536},{"port":1.5}]}`))}, nil
	})}
	providers := newProviders(client, Options{})
	if len(providers) != 5 {
		t.Fatalf("configured providers: %d", len(providers))
	}
	for _, provider := range providers {
		result := provider.Lookup(context.Background(), "203.0.113.10:9120", 0)
		if result.Status != "found" || !result.HermesEvidence || !reflect.DeepEqual(result.Ports, []int{443, 9119}) {
			t.Fatalf("unexpected summary: %+v", result)
		}
		serialized, err := json.Marshal(result)
		if err != nil || strings.Contains(string(serialized), "raw-private-payload") || strings.Contains(string(serialized), "synthetic-operator-credential") {
			t.Fatal("passive report retained payload or operator credential")
		}
		if result := provider.Lookup(context.Background(), "example.invalid", 0); result.Status != "error" {
			t.Fatal("passive lookup accepted a domain instead of an exact IP")
		}
	}
}

func TestProviderErrorStatesStayBoundedAndDoNotRetainBodies(t *testing.T) {
	for _, tc := range []struct {
		code   int
		status string
	}{
		{401, "unauthorized"}, {403, "unauthorized"}, {404, "not_found"},
		{429, "rate_limited"}, {500, "error"}, {302, "error"},
	} {
		client := &http.Client{Transport: testTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: tc.code, Header: http.Header{"Retry-After": {"1"}}, Body: io.NopCloser(strings.NewReader("private-response-body"))}, nil
		})}
		p := &apiProvider{name: "test", base: "https://provider.invalid", client: client}
		result := p.get(context.Background(), "203.0.113.10", "/host", nil, nil, 0)
		if result.Status != tc.status || result.HTTPStatus != tc.code || strings.Contains(result.Error, "private-response-body") {
			t.Fatalf("HTTP %d: %+v", tc.code, result)
		}
	}
	client := &http.Client{Transport: testTransport(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("GET https://provider.invalid?key=private-query-value")
	})}
	p := &apiProvider{name: "test", base: "https://provider.invalid", client: client}
	result := p.get(context.Background(), "203.0.113.10", "/host", nil, nil, 0)
	if result.Status != "error" || strings.Contains(result.Error, "private-query-value") {
		t.Fatal("transport error exposed query credentials")
	}
	client.Transport = testTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxProviderBody+1)))}, nil
	})
	if result := p.get(context.Background(), "203.0.113.10", "/host", nil, nil, 0); result.Status != "error" || !strings.Contains(result.Error, "bounded") {
		t.Fatal("oversized provider response accepted")
	}
}

func TestMaskedMetadataDropsCookiesBlocksRedirectsAndBoundsResponses(t *testing.T) {
	var redirected bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" {
			t.Error("ambient cookie escaped to audit target")
		}
		if r.Header.Get("X-Hermes-Session-Token") != "synthetic-session-marker" {
			t.Error("masked request lost scoped session marker")
		}
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/outside-scope", http.StatusFound)
		case "/oversized":
			_, _ = io.WriteString(w, strings.Repeat("x", maxStatusBody+1))
		default:
			redirected = true
		}
	}))
	defer srv.Close()
	client := srv.Client()
	client.Jar, _ = cookiejar.New(nil)
	u, _ := url.Parse(srv.URL)
	client.Jar.SetCookies(u, []*http.Cookie{{Name: "ambient", Value: "private-cookie"}})
	code, _, err := getMaskedJSON(context.Background(), client, srv.URL+"/redirect", "synthetic-session-marker")
	if err != nil || code != 302 || redirected {
		t.Fatal("masked marker followed a redirect")
	}
	if _, body, err := getMaskedJSON(context.Background(), client, srv.URL+"/oversized", "synthetic-session-marker"); err == nil || body != nil {
		t.Fatal("oversized masked response retained")
	}
}

func TestAuditValidationAndCancellationPrecedeNetwork(t *testing.T) {
	client := &http.Client{Transport: testTransport(func(*http.Request) (*http.Response, error) {
		t.Error("invalid or cancelled audit attempted network I/O")
		return nil, errors.New("unexpected request")
	})}
	for _, opts := range []Options{
		{Authorized: true},
		{Authorized: true, IncludeActive: true, MaxRetries: -1},
		{Authorized: true, IncludeActive: true, MaxRetries: 6},
	} {
		opts.HTTPClient = client
		if _, err := Audit(context.Background(), []string{"203.0.113.10"}, opts); err == nil {
			t.Fatal("invalid audit options accepted")
		}
	}
	opts := Options{Authorized: true, IncludeActive: true, HTTPClient: client}
	for _, targets := range [][]string{nil, {"# comment", " "}, {"example.invalid"}} {
		if _, err := Audit(context.Background(), targets, opts); err == nil {
			t.Fatal("invalid target list accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Audit(ctx, []string{"203.0.113.10"}, opts); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled audit: %v", err)
	}
	if waitBackoff(ctx, 10, time.Minute) {
		t.Fatal("cancelled retry continued")
	}
}
