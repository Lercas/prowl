package hermesaudit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/safehttp"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		input, host, port string
		wantErr           bool
	}{
		{"203.0.113.10", "203.0.113.10", "9119", false},
		{"203.0.113.10:9120", "203.0.113.10", "9120", false},
		{"[2001:db8::10]:9119", "2001:db8::10", "9119", false},
		{"2001:db8::10", "2001:db8::10", "9119", false},
		{"https://203.0.113.10", "", "", true},
		{"127.0.0.1:0", "", "", true},
	}
	for _, tt := range tests {
		host, port, err := parseTarget(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseTarget(%q) did not error", tt.input)
			}
			continue
		}
		if err != nil || host != tt.host || port != tt.port {
			t.Errorf("parseTarget(%q) = (%q, %q, %v), want (%q, %q)", tt.input, host, port, err, tt.host, tt.port)
		}
	}
}

func TestProbeEndpointsBareIPChecksStandardPortsBeforeHermesPort(t *testing.T) {
	got := probeEndpoints("203.0.113.10", "203.0.113.10", "9119")
	if len(got) != 4 {
		t.Fatalf("bare IP endpoints = %#v, want four candidates", got)
	}
	want := []probeEndpoint{
		{scheme: "https", port: "443", host: "203.0.113.10"},
		{scheme: "http", port: "80", host: "203.0.113.10"},
		{scheme: "https", port: "9119", host: "203.0.113.10"},
		{scheme: "http", port: "9119", host: "203.0.113.10"},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("endpoint %d = %#v, want %#v", i, got[i], want[i])
		}
	}
	got = probeEndpoints("203.0.113.10:9120", "203.0.113.10", "9120")
	if len(got) != 2 || got[0].port != "9120" || got[1].port != "9120" {
		t.Fatalf("explicit-port endpoints = %#v", got)
	}
}

func TestProbeFallsBackToDashboardRootAndScansSameOriginAssets(t *testing.T) {
	old := safehttp.AllowPrivate.Load()
	safehttp.AllowPrivate.Store(true)
	defer safehttp.AllowPrivate.Store(old)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<title>Hermes Agent Dashboard</title><script src="/assets/app.js?v=1"></script>`))
		case "/assets/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`window.cfg={api_key:"AAAAAAAAAAAAAAAAAAAA"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	port := strings.TrimPrefix(srv.URL, "http://127.0.0.1:")
	got := Probe(context.Background(), "127.0.0.1:"+port, srv.Client())
	if !got.Reachable || !got.RootHermesEvidence || got.Risk != "root_dashboard_no_api" {
		t.Fatalf("unexpected root-only result: %+v", got)
	}
	if got.RootStatus != http.StatusOK || got.StaticAssetsChecked != 1 {
		t.Fatalf("missing root metadata: %+v", got)
	}
	if len(got.PublicFindings) == 0 {
		t.Fatalf("expected redacted public finding: %+v", got)
	}
	for _, finding := range got.PublicFindings {
		if strings.Contains(finding.Redacted, "AAAAAAAAAAAAAAAAAAAA") {
			t.Fatalf("raw public secret leaked: %+v", finding)
		}
	}
}

func TestProbeUsesExposedSessionTokenOnlyForMaskedEnvMetadata(t *testing.T) {
	old := safehttp.AllowPrivate.Load()
	safehttp.AllowPrivate.Store(true)
	defer safehttp.AllowPrivate.Store(old)

	const sessionToken = "session-token-abcdefghijklmnopqrstuvwxyz"
	var revealCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/status":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"auth_required":false,"version":"0.17.0"}`))
		case "/api/config/schema":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"fields":[]}`))
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<script>window.__HERMES_SESSION_TOKEN__="` + sessionToken + `";</script><title>Hermes Agent Dashboard</title>`))
		case "/api/env":
			if r.Header.Get("X-Hermes-Session-Token") != sessionToken {
				t.Errorf("masked env request did not use the exposed session token")
			}
			if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
				t.Errorf("masked env request sent unrelated credential headers")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"DEEPSEEK_API_KEY":{"is_set":true,"redacted_value":"present"}}`))
		case "/api/credentials/pool":
			if r.Header.Get("X-Hermes-Session-Token") != sessionToken {
				t.Errorf("credential-pool request did not use the exposed session token")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"providers":[{"provider":"deepseek","entries":[{"source":"env:DEEPSEEK_API_KEY","token_preview":"raw-must-not-return"}]}]}`))
		case "/api/providers/custom-endpoints":
			if r.Header.Get("X-Hermes-Session-Token") != sessionToken {
				t.Errorf("custom-endpoint request did not use the exposed session token")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"endpoints":[{"id":"deepseek-direct","has_api_key":true,"api_key_preview":"raw-must-not-return"}]}`))
		case "/api/env/reveal":
			revealCalls.Add(1)
			t.Errorf("probe must never request /api/env/reveal")
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	port := strings.TrimPrefix(srv.URL, "http://127.0.0.1:")
	got := Probe(context.Background(), "127.0.0.1:"+port, srv.Client())
	if !got.SessionTokenExposed || got.EnvStatus != http.StatusOK || got.CredentialPoolStatus != http.StatusOK || got.CustomEndpointsStatus != http.StatusOK {
		t.Fatalf("missing exposed-token metadata: %+v", got)
	}
	if len(got.ConfiguredSecrets) != 3 {
		t.Fatalf("unexpected configured secret metadata: %+v", got.ConfiguredSecrets)
	}
	var sawEnv, sawPool, sawConfig bool
	for _, secret := range got.ConfiguredSecrets {
		if strings.Contains(secret.Name+secret.Source, "raw-must-not-return") {
			t.Fatalf("redacted metadata leaked into report: %+v", got.ConfiguredSecrets)
		}
		switch secret.Surface {
		case "env":
			sawEnv = secret.Name == "DEEPSEEK_API_KEY" && secret.Present
		case "credential_pool":
			sawPool = secret.Provider == "deepseek" && secret.Source == "env:DEEPSEEK_API_KEY" && secret.Present
		case "config.providers":
			sawConfig = secret.Name == "deepseek-direct" && secret.Present
		}
	}
	if !sawEnv || !sawPool || !sawConfig {
		t.Fatalf("missing secret surfaces: %+v", got.ConfiguredSecrets)
	}
	if revealCalls.Load() != 0 {
		t.Fatalf("reveal endpoint calls = %d, want 0", revealCalls.Load())
	}
}

func TestClassifySessionTokenFinding(t *testing.T) {
	const path = "http://203.0.113.10/"
	const token = "session-token-abcdefghijklmnopqrstuvwxyz"
	findings := []PublicFinding{{
		Type:        "generic_high_entropy",
		Severity:    "medium",
		Confidence:  0.55,
		Path:        path,
		Fingerprint: model.ComputeFingerprint("generic_high_entropy", path, token),
	}}
	got := classifySessionTokenFinding(findings, path, token)
	if got[0].Type != "hermes_session_token" || got[0].Severity != "critical" || got[0].Confidence != 1 {
		t.Fatalf("session token finding was not classified: %+v", got[0])
	}
}

func TestProbeFindsUnauthenticatedControlPlaneWithoutReadingSecrets(t *testing.T) {
	old := safehttp.AllowPrivate.Load()
	safehttp.AllowPrivate.Store(true)
	defer safehttp.AllowPrivate.Store(old)

	var statusCalls, schemaCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/status":
			statusCalls.Add(1)
			if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
				t.Error("probe sent credential-bearing headers")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"auth_required":false,"version":"0.9.1"}`))
		case "/api/config/schema":
			schemaCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"fields":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	port := strings.TrimPrefix(srv.URL, "http://127.0.0.1:")
	got := Probe(context.Background(), "127.0.0.1:"+port, srv.Client())
	if !got.Reachable || !got.ControlPlaneUnauthenticated || got.Risk != "critical_unauthenticated_dashboard" {
		t.Fatalf("unexpected probe result: %+v", got)
	}
	if got.SchemaStatus != http.StatusOK || got.Version != "0.9.1" || got.AuthRequired == nil || *got.AuthRequired {
		t.Fatalf("missing status metadata: %+v", got)
	}
	if statusCalls.Load() != 1 || schemaCalls.Load() != 1 {
		t.Fatalf("status/schema calls = %d/%d, want 1/1", statusCalls.Load(), schemaCalls.Load())
	}
}

func TestProbeDistinguishesOuterGate(t *testing.T) {
	old := safehttp.AllowPrivate.Load()
	safehttp.AllowPrivate.Store(true)
	defer safehttp.AllowPrivate.Store(old)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/status" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"auth_required":false,"version":"0.8"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	port := strings.TrimPrefix(srv.URL, "http://127.0.0.1:")
	got := Probe(context.Background(), "127.0.0.1:"+port, srv.Client())
	if got.Risk != "status_local_only_outer_gate" || got.ControlPlaneUnauthenticated {
		t.Fatalf("unexpected outer-gate result: %+v", got)
	}
}

func TestProbeGatedStatusDoesNotProbeSchema(t *testing.T) {
	old := safehttp.AllowPrivate.Load()
	safehttp.AllowPrivate.Store(true)
	defer safehttp.AllowPrivate.Store(old)
	var schemaCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/config/schema" {
			schemaCalls.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"auth_required":true,"version":"1.0"}`))
	}))
	defer srv.Close()
	port := strings.TrimPrefix(srv.URL, "http://127.0.0.1:")
	got := Probe(context.Background(), "127.0.0.1:"+port, srv.Client())
	if got.Risk != "auth_gate_present" || got.AuthRequired == nil || !*got.AuthRequired {
		t.Fatalf("unexpected gated result: %+v", got)
	}
	if schemaCalls.Load() != 0 {
		t.Fatalf("schema endpoint called for gated status")
	}
}

func TestProviderHonorsRateLimitAndDoesNotExposePayload(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("x-limited-for", "1ms")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"203.0.113.10","services":[{"port":9119,"banner":"Hermes Agent API_KEY=do-not-return"}]}`))
	}))
	defer srv.Close()
	p := &apiProvider{name: "test", base: srv.URL, client: srv.Client()}
	got := p.get(context.Background(), "203.0.113.10", "/host/203.0.113.10", nil, nil, 2)
	if got.Status != "found" || !got.HermesEvidence || len(got.Ports) != 1 || got.Ports[0] != 9119 {
		t.Fatalf("unexpected provider result: %+v", got)
	}
	if calls.Load() != 2 {
		t.Fatalf("provider calls = %d, want 2", calls.Load())
	}
	if strings.Contains(got.Error+got.Endpoint, "do-not-return") {
		t.Fatalf("provider payload leaked into result: %+v", got)
	}
}

func TestAuditRequiresAuthorization(t *testing.T) {
	_, err := Audit(context.Background(), []string{"203.0.113.10"}, Options{IncludeActive: true})
	if err == nil {
		t.Fatal("Audit accepted missing authorization attestation")
	}
}

func TestParseRetryAfter(t *testing.T) {
	h := http.Header{}
	h.Set("x-limited-for", "344.24ms")
	if got := parseRetryAfter(h); got != 344*time.Millisecond+240*time.Microsecond {
		t.Fatalf("parseRetryAfter duration = %v", got)
	}
	h = http.Header{}
	h.Set("Retry-After", "2")
	if got := parseRetryAfter(h); got != 2*time.Second {
		t.Fatalf("parseRetryAfter seconds = %v", got)
	}
}
