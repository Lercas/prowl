package verify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/safehttp"
)

// TestMain enables the private-address dial guard's escape hatch so tests can reach httptest
// servers, which bind 127.0.0.1. Production code leaves safehttp.AllowPrivate false.
func TestMain(m *testing.M) {
	safehttp.AllowPrivate.Store(true)
	os.Exit(m.Run())
}

// writeVerifier writes a verifier YAML pointed at a local mock server.
func writeVerifier(t *testing.T, srv string) string {
	t.Helper()
	body := `id: mock
match: [mocktoken, mock_]
requests:
  - method: GET
    url: ` + srv + `/user
    headers:
      Authorization: "token {{secret}}"
    matchers:
      - type: status
        status: [200]
`
	p := filepath.Join(t.TempDir(), "mock.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDataDrivenVerify(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "token LIVEKEY" {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(401)
	}))
	defer srv.Close()

	set, err := Load(2*time.Second, writeVerifier(t, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if set.Count() != 1 || !set.Supports("mocktoken_api_key") {
		t.Fatalf("verifier not loaded/matched: count=%d", set.Count())
	}
	ctx := context.Background()
	if r := set.Verify(ctx, "mocktoken", "LIVEKEY", "", false); r.Status != Verified {
		t.Errorf("live key: got %s, want verified", r.Status)
	}
	if r := set.Verify(ctx, "mocktoken", "DEADKEY", "", false); r.Status != Invalid {
		t.Errorf("dead key: got %s, want invalid", r.Status)
	}
	if r := set.Verify(ctx, "mocktoken", "AKIAEXAMPLE", "", true); r.Status != Skipped {
		t.Errorf("example: got %s, want skipped", r.Status)
	}
	if r := set.Verify(ctx, "unknown_type", "x", "", false); r.Status != Unsupported {
		t.Errorf("unknown: got %s, want unsupported", r.Status)
	}
}

func TestBlastRadius(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/a" || r.URL.Path == "/b" {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	body := "id: blast\nmatch: [blasttoken]\nrequests:\n" +
		"  - {method: GET, url: " + srv.URL + "/a, capability: cap A, matchers: [{type: status, status: [200]}]}\n" +
		"  - {method: GET, url: " + srv.URL + "/b, capability: cap B, matchers: [{type: status, status: [200]}]}\n" +
		"  - {method: GET, url: " + srv.URL + "/c, capability: cap C, matchers: [{type: status, status: [200]}]}\n"
	p := filepath.Join(t.TempDir(), "blast.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := Load(2*time.Second, p)
	if err != nil {
		t.Fatal(err)
	}
	r := set.Verify(context.Background(), "blasttoken", "KEY", "", false)
	if r.Status != Verified {
		t.Fatalf("status = %s, want verified", r.Status)
	}
	if got := strings.Join(r.Access, ","); got != "cap A,cap B" {
		t.Errorf("access = %q, want the two reachable capabilities", got)
	}
}

func TestInterpolateBase64(t *testing.T) {
	v := map[string]string{"secret": "sk_live_abc"}
	if got := interpolate("Basic {{base64(secret:)}}", v); got != "Basic c2tfbGl2ZV9hYmM6" {
		t.Errorf("base64 interpolation wrong: %q", got)
	}
	if got := interpolate("token {{secret}}", map[string]string{"secret": "abc"}); got != "token abc" {
		t.Errorf("plain interpolation wrong: %q", got)
	}
}

func TestAWSSigV4(t *testing.T) {
	now = func() time.Time { return time.Unix(1700000000, 0).UTC() }
	defer func() { now = time.Now }()
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if strings.Contains(gotAuth, "AWS4-HMAC-SHA256") && r.Header.Get("X-Amz-Date") != "" {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(403)
	}))
	defer srv.Close()
	v := &Verifier{ID: "aws", Match: []string{"aws"}, Sign: "awsv4",
		SignParams: map[string]string{"service": "sts", "region": "us-east-1"},
		Extract:    map[string]string{"aws_access_key_id": `AKIA[0-9A-Z]{16}`, "aws_secret_access_key": `[A-Za-z0-9/+]{40}`},
		Requests:   []Request{{Method: "POST", URL: srv.URL, Body: "Action=GetCallerIdentity"}}}
	if err := compileVerifier(v); err != nil {
		t.Fatal(err)
	}
	set := &Set{client: srv.Client(), verifiers: []*Verifier{v}}
	ctx := "id=AKIAIOSFODNN7EXAMPLE secret=wJalrXUtnFEMIaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if r := set.Verify(context.Background(), "aws", "wJalrXUtnFEMIaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ctx, false); r.Status != Verified {
		t.Errorf("AWS SigV4: got %s (auth=%q)", r.Status, gotAuth)
	}
}

// TestCanonicalQuerySorted locks in the SigV4 query canonicalization: params sorted by key, each
// k/v RFC 3986 encoded, space as %20 (not '+'), '~' left literal. Pre-fix this used RawQuery as-is.
func TestCanonicalQuerySorted(t *testing.T) {
	cases := map[string]string{
		"":        "",
		"b=2&a=1": "a=1&b=2",
		"Version=2011-06-15&Action=GetCallerIdentity": "Action=GetCallerIdentity&Version=2011-06-15",
		"k=a b~c":  "k=a%20b~c",
		"x=1&x=0":  "x=0&x=1",
		"flag":     "flag=",
		"k=a%2Fb":  "k=a%2Fb", // already-encoded slash stays encoded
		"path=a/b": "path=a%2Fb",
	}
	for in, want := range cases {
		if got := canonicalQuery(in); got != want {
			t.Errorf("canonicalQuery(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestErrorNoteCarriesNoSecret is the regression test for the HIGH secret-leak finding: when the
// HTTP call errors, Note must be a coarse category and must never contain the URL or the secret.
func TestErrorNoteCarriesNoSecret(t *testing.T) {
	const secret = "SUPERSECRETVALUE123"
	// Point at a closed port on loopback so Do() returns a *url.Error embedding the full URL+secret.
	v := &Verifier{ID: "x", Match: []string{"x"},
		Requests: []Request{{Method: "GET", URL: "http://127.0.0.1:1/" + "{{secret}}"}}}
	if err := compileVerifier(v); err != nil {
		t.Fatal(err)
	}
	set := &Set{client: safehttp.Client(2 * time.Second), verifiers: []*Verifier{v},
		sem: make(chan struct{}, 1)}
	r := set.Verify(context.Background(), "x", secret, "", false)
	if r.Status != Errored {
		t.Fatalf("want Errored, got %s (note=%q)", r.Status, r.Note)
	}
	if strings.Contains(r.Note, secret) || strings.Contains(r.Note, "127.0.0.1") || strings.Contains(r.Note, "http") {
		t.Errorf("Note leaks URL/secret: %q", r.Note)
	}
	if r.Note != "connection refused" && r.Note != "connection failed" && r.Note != "timeout" {
		t.Errorf("unexpected category: %q", r.Note)
	}
}

// TestControlCharsInSecretRejected is the regression test for the CRLF/URL-injection finding: a
// secret with CR/LF must not reshape the request; probe returns an error and never sends.
func TestControlCharsInSecretRejected(t *testing.T) {
	var hit int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit++
		w.WriteHeader(200)
	}))
	defer srv.Close()
	v := &Verifier{ID: "x", Match: []string{"x"},
		Requests: []Request{{Method: "GET", URL: srv.URL + "/{{secret}}"}}}
	if err := compileVerifier(v); err != nil {
		t.Fatal(err)
	}
	set := &Set{client: srv.Client(), verifiers: []*Verifier{v}, sem: make(chan struct{}, 1)}
	r := set.Verify(context.Background(), "x", "abc\r\nX-Injected: 1", "", false)
	if r.Status != Errored {
		t.Errorf("control-char secret: want Errored, got %s (note=%q)", r.Status, r.Note)
	}
	if hit != 0 {
		t.Errorf("request with control chars should not have been sent (hit=%d)", hit)
	}
}

// TestCrossHostRedirectBlocked is the regression test for cross-host secret forwarding: a redirect
// to a different host must be refused so secret-bearing headers are never re-sent to a third party.
func TestCrossHostRedirectBlocked(t *testing.T) {
	var leakedToB string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leakedToB = r.Header.Get("X-Api-Key")
		w.WriteHeader(200)
	}))
	defer target.Close()
	// origin redirects to target (a different host:port == different origin).
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/leak", http.StatusFound)
	}))
	defer origin.Close()
	v := &Verifier{ID: "x", Match: []string{"x"},
		Requests: []Request{{Method: "GET", URL: origin.URL,
			Headers: map[string]string{"X-Api-Key": "{{secret}}"}}}}
	if err := compileVerifier(v); err != nil {
		t.Fatal(err)
	}
	set := &Set{client: safehttp.Client(2 * time.Second), verifiers: []*Verifier{v},
		sem: make(chan struct{}, 1)}
	r := set.Verify(context.Background(), "x", "SECRETKEY", "", false)
	if leakedToB != "" {
		t.Fatalf("secret header forwarded across hosts: %q", leakedToB)
	}
	if r.Status != Errored {
		t.Errorf("cross-host redirect: want Errored, got %s (note=%q)", r.Status, r.Note)
	}
}

// loggingMock is a local httptest server that records every request it receives (host path,
// Authorization header, and any header that could carry a token). It lets a test PROVE whether a
// secret's plaintext reached the wire — no real provider is ever contacted; all tokens are fake.
type loggingMock struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits []mockHit
}

type mockHit struct {
	path string
	auth string
	body string
}

func newLoggingMock(t *testing.T) *loggingMock {
	t.Helper()
	lm := &loggingMock{}
	lm.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		lm.mu.Lock()
		lm.hits = append(lm.hits, mockHit{path: r.URL.Path, auth: r.Header.Get("Authorization"), body: string(b)})
		lm.mu.Unlock()
		// Reject everything: stand in for "provider says this token is dead".
		w.WriteHeader(401)
	}))
	t.Cleanup(lm.srv.Close)
	return lm
}

func (lm *loggingMock) count() int {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	return len(lm.hits)
}

// sawSecret reports whether the fake secret appeared anywhere in any recorded request.
func (lm *loggingMock) sawSecret(secret string) bool {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	for _, h := range lm.hits {
		if strings.Contains(h.auth, secret) || strings.Contains(h.path, secret) || strings.Contains(h.body, secret) {
			return true
		}
	}
	return false
}

// ldVerifier builds a launchdarkly-style verifier whose request targets the logging mock instead of
// app.launchdarkly.com, with the same over-broad anchors as verifiers/launchdarkly.yaml.
func ldVerifier(srv string) *Verifier {
	v := &Verifier{ID: "launchdarkly", Match: []string{"launchdarkly", "api-"},
		Requests: []Request{{Method: "GET", URL: srv + "/api/v2/caller-identity",
			Headers: map[string]string{"Authorization": "{{secret}}"}}}}
	_ = compileVerifier(v)
	return v
}

// yandexVerifier builds a yandex-apikey-style verifier (over-broad short value anchor "aje")
// targeting the logging mock instead of the real Yandex Cloud host.
func yandexVerifier(srv string) *Verifier {
	v := &Verifier{ID: "yandex-apikey", Match: []string{"yandex", "aqvn", "aje"},
		Requests: []Request{{Method: "GET", URL: srv + "/resource-manager/v1/clouds",
			Headers: map[string]string{"Authorization": "Api-Key {{secret}}"}}}}
	_ = compileVerifier(v)
	return v
}

// TestExfiltrationGuard proves the secret-exfiltration defect is fixed. Pre-fix, an okta token
// (type "okta-api-token", NO okta verifier loaded) was routed to launchdarkly by the over-broad
// "api-" anchor and its plaintext was POSTed to LaunchDarkly's host (here, the logging mock). Same
// for a generic value containing "aje" routed to yandex. After the fix:
//
//	(a) the okta token is NOT routed anywhere — find() returns nil, Verify SKIPS, the mock sees
//	    nothing, the plaintext never leaves;
//	(b) a generic "...aje..." token is not routed to yandex (mock sees nothing);
//	(c) correct providers (mailgun/stripe via provider-name type match, github via a distinctive
//	    value prefix) still route to the right verifier.
func TestExfiltrationGuard(t *testing.T) {
	mock := newLoggingMock(t)

	// Real-looking but FAKE tokens. 42-char okta token starts "00", a generic 32-char value that
	// happens to contain the 3-char "aje" fragment by coincidence.
	const oktaToken = "00aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCd" // 42 chars, fake
	const genericAje = "zZq9aje7Kp2Lm4Nr6Tv8Wx0Yb1Dc3Fg5Hj7Kl9Mn"  // generic, contains "aje"

	set := &Set{client: mock.srv.Client(), verifiers: []*Verifier{
		ldVerifier(mock.srv.URL),     // launchdarkly: match [launchdarkly, api-]
		yandexVerifier(mock.srv.URL), // yandex: match [yandex, aqvn, aje]
	}, sem: make(chan struct{}, 1)}

	t.Run("okta_token_not_routed_or_exfiltrated", func(t *testing.T) {
		// (a) routing decision: an okta-typed finding (no okta verifier) must NOT route.
		if v := set.find("okta-api-token", oktaToken); v != nil {
			t.Fatalf("okta-api-token mis-routed to verifier %q — its plaintext would be sent there", v.ID)
		}
		// And the end-to-end Verify must skip it, sending nothing on the wire.
		r := set.Verify(context.Background(), "okta-api-token", oktaToken, "", false)
		if r.Status != Unsupported {
			t.Errorf("okta token: want Unsupported (skipped), got %s (verifier=%q)", r.Status, r.Verifier)
		}
		if mock.count() != 0 {
			t.Errorf("okta token reached the wire (%d request(s)) — plaintext exfiltrated", mock.count())
		}
		if mock.sawSecret(oktaToken) {
			t.Errorf("okta token plaintext was transmitted to the mock provider")
		}
	})

	t.Run("generic_aje_not_routed_to_yandex", func(t *testing.T) {
		// (b) a generic high-entropy value that coincidentally contains "aje" must not route to yandex.
		if v := set.find("generic_high_entropy", genericAje); v != nil {
			t.Fatalf("generic 'aje' value mis-routed to %q — would be exfiltrated to that provider", v.ID)
		}
		r := set.Verify(context.Background(), "generic_high_entropy", genericAje, "", false)
		if r.Status != Unsupported {
			t.Errorf("generic 'aje' value: want Unsupported, got %s", r.Status)
		}
		if mock.sawSecret(genericAje) {
			t.Errorf("generic 'aje' value plaintext was transmitted to the mock provider")
		}
	})

	t.Run("correct_providers_still_route", func(t *testing.T) {
		// (c) legitimate routings must keep working.
		correct := &Set{verifiers: []*Verifier{
			ldVerifier(mock.srv.URL),
			{ID: "mailgun", Match: []string{"mailgun"}},
			{ID: "stripe", Match: []string{"stripe"}},
			{ID: "github", Match: []string{"github", "ghp_"}},
			{ID: "datadog", Match: []string{"datadog"}},
			{ID: "resend", Match: []string{"resend", "re_"}}, // short structured prefix
		}}
		cases := []struct{ typeID, value, want string }{
			{"mailgun-api-key", "key-abc123def456789", "mailgun"},    // provider-name type match
			{"stripe-secret-key", "sk_live_abc123", "stripe"},        // provider-name type match
			{"datadog-api-key", "abcdef0123456789abcdef", "datadog"}, // provider-name type match
			{"generic_high_entropy", "ghp_abcDEF123456", "github"},   // distinctive value prefix
			{"generic_high_entropy", "re_abc123def456ghi", "resend"}, // SHORT structured prefix (re_) routes
			{"launchdarkly-api-token", "api-xyz", "launchdarkly"},    // its own provider name still routes
		}
		for _, c := range cases {
			got := correct.find(c.typeID, c.value)
			gid := "nil"
			if got != nil {
				gid = got.ID
			}
			if gid != c.want {
				t.Errorf("find(%q,%q) routed to %q, want %q", c.typeID, c.value, gid, c.want)
			}
		}
	})
}

// prefixVerifier builds a verifier with the given id + value anchors, targeting the logging mock
// instead of the real provider host. Used to prove that a short structured provider prefix routes.
func prefixVerifier(id, srv string, anchors ...string) *Verifier {
	v := &Verifier{ID: id, Match: append([]string{id}, anchors...),
		Requests: []Request{{Method: "GET", URL: srv + "/" + id,
			Headers: map[string]string{"Authorization": "Bearer {{secret}}"}}}}
	_ = compileVerifier(v)
	return v
}

// TestValuePrefixRouting is the regression test for the round-4 OVER-correction: the minimum-
// specificity gate in valueMatchOK also rejected LEGITIMATE short structured provider value-prefixes
// (re_/pk_/r8_/yc_/t1./hf_/ls__/…). A genuinely live secret of one of those providers that the
// cascade only labeled "generic_high_entropy" then failed valueMatchOK → find() returned nil →
// Unsupported → and under --verify --verified-only the live finding was SILENTLY DROPPED (a new
// fail-open). This proves BOTH directions with a logging mock (no real provider is ever contacted):
//
//	(a) a real re_…/pk_…/r8_…/yc_… token (prefix-anchored) routes to its verifier and is probed;
//	(b) the SAME fragments buried MID-string in a generic high-entropy blob route NOWHERE — the mock
//	    sees nothing, so the round-4 exfiltration target stays closed (no over-correction back).
func TestValuePrefixRouting(t *testing.T) {
	mock := newLoggingMock(t)
	set := &Set{client: mock.srv.Client(), verifiers: []*Verifier{
		prefixVerifier("resend", mock.srv.URL, "re_"),
		prefixVerifier("clickup", mock.srv.URL, "pk_"),
		prefixVerifier("replicate", mock.srv.URL, "r8_"),
		prefixVerifier("yandex-iam", mock.srv.URL, "yc_", "t1."),
		yandexVerifier(mock.srv.URL), // brings the short mid-string-prone "aje" anchor into the set
	}, sem: make(chan struct{}, 1)}

	t.Run("real_prefixed_tokens_route_and_probe", func(t *testing.T) {
		// Fake but real-shaped tokens; each carries its provider prefix at position 0.
		cases := []struct{ value, want string }{
			{"re_abc123def456ghi789jkl", "resend"},
			{"pk_abc123def456ghi789jkl", "clickup"},
			{"r8_abcDEF123456ghiJKL789", "replicate"},
			{"yc_abc123def456ghi789jkl", "yandex-iam"},
			{"t1.abc123def456ghi789jkl", "yandex-iam"},
		}
		for _, c := range cases {
			// (a) routing: a generic-typed finding routes purely on the prefix-anchored value.
			v := set.find("generic_high_entropy", c.value)
			if v == nil {
				t.Fatalf("live %q dropped: find() returned nil (Unsupported) — fail-open under --verified-only", c.value)
			}
			if v.ID != c.want {
				t.Fatalf("find(generic, %q) routed to %q, want %q", c.value, v.ID, c.want)
			}
			// And the end-to-end Verify actually probes the provider (mock answers 401 → Invalid,
			// i.e. "reached the provider and got a verdict", NOT Unsupported).
			before := mock.count()
			r := set.Verify(context.Background(), "generic_high_entropy", c.value, "", false)
			if r.Status == Unsupported {
				t.Errorf("%q: Verify returned Unsupported — the live finding would be silently dropped", c.value)
			}
			if mock.count() == before {
				t.Errorf("%q: verifier %q never probed the provider", c.value, c.want)
			}
			if !mock.sawSecret(c.value) {
				t.Errorf("%q: token was not sent to its (mock) verifier — not actually verified", c.value)
			}
		}
	})

	t.Run("midstring_fragments_route_nowhere", func(t *testing.T) {
		mid := newLoggingMock(t)
		s2 := &Set{client: mid.srv.Client(), verifiers: []*Verifier{
			prefixVerifier("resend", mid.srv.URL, "re_"),
			prefixVerifier("clickup", mid.srv.URL, "pk_"),
			prefixVerifier("replicate", mid.srv.URL, "r8_"),
			yandexVerifier(mid.srv.URL),
		}, sem: make(chan struct{}, 1)}
		// Generic high-entropy values that merely CONTAIN re_/pk_/r8_/aje mid-string by coincidence.
		junk := []string{
			"zZq9aje7Kp2Lm4Nr6Tv8Wx0Yb1Dc3Fg5Hj7Kl9Mn", // contains "aje" mid-string
			"abcxyz123re_456randomblob789padding",      // contains "re_" mid-string
			"randomtextpk_morerandomtextpadding00",     // contains "pk_" mid-string
			"someblobr8_middlepaddingtext00",           // contains "r8_" mid-string
		}
		for _, val := range junk {
			if v := s2.find("generic_high_entropy", val); v != nil {
				t.Errorf("mid-string junk %q mis-routed to %q — round-4 target reopened", val, v.ID)
			}
			r := s2.Verify(context.Background(), "generic_high_entropy", val, "", false)
			if r.Status != Unsupported {
				t.Errorf("mid-string junk %q: want Unsupported, got %s", val, r.Status)
			}
			if mid.sawSecret(val) {
				t.Errorf("mid-string junk %q plaintext was transmitted to a mock provider", val)
			}
		}
		if mid.count() != 0 {
			t.Errorf("mid-string junk reached the wire (%d request(s)) — exfiltration", mid.count())
		}
	})
}

// TestFindRoutesByBestTypeMatch guards the verifier routing fix: the launchdarkly verifier's
// over-broad "api-" anchor must NOT hijack a "<provider>-api-key" finding away from that provider's
// own verifier (which silently marked live keys dead). A TYPE match on the provider name outscores a
// generic substring; a value-only anchor still works when the type carries no provider.
func TestFindRoutesByBestTypeMatch(t *testing.T) {
	s := &Set{verifiers: []*Verifier{
		{ID: "launchdarkly", Match: []string{"launchdarkly", "api-"}}, // loads first, over-broad anchor
		{ID: "mailgun", Match: []string{"mailgun"}},
		{ID: "clickup", Match: []string{"clickup", "pk_"}},
		{ID: "stripe", Match: []string{"stripe", "sk_live_", "pk_live_"}},
		{ID: "resend", Match: []string{"resend", "re_"}},       // legit short structured prefix
		{ID: "replicate", Match: []string{"replicate", "r8_"}}, // legit short structured prefix
		{ID: "yandex-iam", Match: []string{"yandex", "yc_", "t1."}},
	}}
	cases := []struct{ typeID, value, want string }{
		{"mailgun-api-key", "key-abc123def456", "mailgun"},      // "mailgun" beats "api-"
		{"launchdarkly-api-token", "abc123", "launchdarkly"},    // its own type still routes right
		{"stripe-publishable-key", "pk_live_abc123", "stripe"},  // "stripe" (type) beats clickup "pk_" (value)
		{"generic_high_entropy", "sk_live_abc123def", "stripe"}, // value-only fallback when type is generic
		// Legit short provider prefixes route on a PREFIX-anchored value even though they are short
		// (regression for the round-4 over-correction that dropped these as live false-negatives).
		{"generic_high_entropy", "re_abc123def456ghi789", "resend"},
		{"generic_high_entropy", "r8_abcDEF123456ghiJKL", "replicate"},
		{"generic_high_entropy", "yc_abc123def456ghi", "yandex-iam"},
		{"generic_high_entropy", "t1.abc123def456ghi", "yandex-iam"},
		{"generic_high_entropy", "pk_abc123def456ghi789", "clickup"}, // pk_ as a prefix routes to clickup
		// But the SAME short anchors buried mid-string in a random blob must NOT route anywhere
		// (round-4 target stays closed — no over-correction back into the junk).
		{"generic_high_entropy", "abcxyz123re_456randomblob789", ""},
		{"generic_high_entropy", "randomtextpk_morerandomtext00", ""},
		{"generic_high_entropy", "someblobr8_middlepadding00", ""},
	}
	for _, c := range cases {
		got := s.find(c.typeID, c.value)
		gid := ""
		if got != nil {
			gid = got.ID
		}
		if gid != c.want {
			want := c.want
			if want == "" {
				want = "nil (no route)"
			}
			t.Errorf("find(%q,%q) routed to %q, want %q", c.typeID, c.value, gid, want)
		}
	}
}
