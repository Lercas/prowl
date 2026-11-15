package publicaudit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const ownedSupabaseRef = "abcdefghijklmnopqrst"
const ownedPublishable = "sb_publishable_q7Mn9Jk3Qw5Er8Ty2Ui6Op4As1Df0Gh9Lz"

func anonFixture(payload string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString([]byte("q7Mn9Jk3Qw5Er8Ty2Ui6Op4As1Df0Gh9"))
}

func legacyAnon() string {
	return anonFixture(`{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"anon","iat":1700000000,"exp":2100000000}`)
}

func headResponse(status int, contentRange string) *http.Response {
	r := response("PRIVATE_BODY_MUST_NOT_BE_READ", status)
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	r.Header.Set("Content-Range", contentRange)
	return r
}

func TestSupabasePublicKeyClassification(t *testing.T) {
	for _, key := range []string{ownedPublishable, legacyAnon()} {
		if _, ok := supabasePublicKey(key); !ok {
			t.Fatal("owned public fixture rejected")
		}
	}
	for _, payload := range []string{
		`{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"service_role","iat":1700000000,"exp":2100000000}`,
		`{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"authenticated","iat":1700000000,"exp":2100000000}`,
		`{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"anon","iat":1700000000,"exp":2100000000,"sub":"user-session"}`,
		`{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"anon","role":"service_role","iat":1700000000,"exp":2100000000}`,
		`{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"anon","iat":"1700000000","exp":2100000000}`,
		`{"iss":"foreign","ref":"abcdefghijklmnopqrst","role":"anon","iat":1700000000,"exp":2100000000}`,
		`{"iss":"supabase","ref":"foreign/path","role":"anon","iat":1700000000,"exp":2100000000}`,
	} {
		if _, ok := supabasePublicKey(anonFixture(payload)); ok {
			t.Fatal("privileged, session or malformed claims accepted")
		}
	}
	for _, key := range []string{"sb_secret_" + strings.Repeat("x", 30), legacyAnon() + "=", "sb_publishable_foo\r\nX: attack", strings.Repeat("x", 8193)} {
		if _, ok := supabasePublicKey(key); ok {
			t.Fatal("unsafe key accepted")
		}
	}
}

func TestSupabaseHeadOnlyNoValuesOrUserSession(t *testing.T) {
	for _, key := range []string{ownedPublishable, legacyAnon()} {
		calls := 0
		a, _ := NewWithTargets(time.Second, nil, []string{"owned_table"})
		a.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Method != "HEAD" || r.Body != nil || r.URL.String() != "https://abcdefghijklmnopqrst.supabase.co/rest/v1/owned_table?limit=1" || r.Header.Get("apikey") != key || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Accept-Profile") != "public" || r.Header.Get("Prefer") != "" {
				t.Error("unsafe Supabase request")
			}
			return headResponse(200, "0-0/*"), nil
		})
		for i := 0; i < 2; i++ {
			result := a.Audit(t.Context(), "generic_api_key", key, map[string]string{"supabaseUrl": "https://" + ownedSupabaseRef + ".supabase.co/"})
			if result == nil || result.Status != "public_read_allowed" || result.CheckedAt == "" || len(result.Checks) != 1 || len(result.Checks[0].Scope) != 64 || result.Checks[0].CheckedAt != result.CheckedAt {
				t.Fatal("missing observation")
			}
			raw, _ := json.Marshal(result)
			for _, private := range []string{key, ownedSupabaseRef, "owned_table", "PRIVATE_BODY", "verified", "rls_disabled"} {
				if strings.Contains(string(raw), private) {
					t.Fatal("private data or unsupported conclusion in audit")
				}
			}
			result.Checks[0].Scope = "mutated caller copy"
		}
		if calls != 1 {
			t.Fatal("definitive result not cached")
		}
	}
}

func TestSupabaseRejectsUnsafeTargetsBeforeTransport(t *testing.T) {
	calls := 0
	a, _ := NewWithTargets(time.Second, nil, []string{"owned_table"})
	a.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) { calls++; return headResponse(200, "0-0/*"), nil })
	for _, raw := range []string{"", "http://abcdefghijklmnopqrst.supabase.co", "https://abcdefghijklmnopqrst.supabase.co.attacker.test", "https://abcdefghijklmnopqrst.supabase.co:443", "https://abcdefghijklmnopqrst.supabase.co/extra", "https://abcdefghijklmnopqrst.supabase.co?", "https://abcdefghijklmnopqrst.supabase.co#x", "https://user@abcdefghijklmnopqrst.supabase.co", "https://127.0.0.1", "https://a.supabase.co", "https://abcdefghijklmnopqrsu.supabase.co"} {
		result := a.Audit(t.Context(), "jwt", legacyAnon(), map[string]string{"supabaseUrl": raw})
		if result == nil || result.Status != "inconclusive" {
			t.Fatal("unsafe target accepted")
		}
	}
	for _, bindings := range []map[string]string{nil, {"supabaseUrl": "https://abcdefghijklmnopqrst.supabase.co", "SUPABASE_URL": ""}, {"supabaseUrl": "https://abcdefghijklmnopqrst.supabase.co", "VITE_SUPABASE_URL": "https://abcdefghijklmnopqrsu.supabase.co"}} {
		if got := a.Audit(t.Context(), "generic_api_key", ownedPublishable, bindings); got == nil || got.Status != "inconclusive" {
			t.Fatal("missing/conflicting bindings accepted")
		}
	}
	for _, name := range []string{"", "public.table", "rpc/mutate", "../table", "table?select=secret", "x#frag", "x%2fy", strings.Repeat("x", 64), "x\nHeader: bad"} {
		if _, err := NewWithTargets(time.Second, nil, []string{name}); err == nil {
			t.Fatal("unsafe table identifier accepted")
		}
	}
	if _, err := ValidateTables(make([]string, 9)); err == nil {
		t.Fatal("table limit ignored")
	}
	if got, err := ValidateTables([]string{"b", "a", "b"}); err != nil || strings.Join(got, ",") != "a,b" {
		t.Fatal("table canonicalization failed")
	}
	if calls != 0 {
		t.Fatal("invalid configuration reached transport")
	}
}

func TestSupabaseHeadResponsesAndPartialCoverage(t *testing.T) {
	for _, tc := range []struct {
		code       int
		cr, status string
	}{
		{200, "0-0/*", "public_read_allowed"}, {200, "*/*", "public_read_allowed"}, {206, "0-0/*", "public_read_allowed"},
		{403, "", "read_denied"}, {401, "", "inconclusive"}, {404, "", "inconclusive"}, {429, "", "inconclusive"}, {500, "", "inconclusive"},
		{200, "", "inconclusive"}, {200, "0-100/*", "inconclusive"}, {200, "0-0/10000", "inconclusive"}, {200, "0-0/*\r\nother", "inconclusive"},
	} {
		if got := supabaseHeadResult(headResponse(tc.code, tc.cr)); got.Status != tc.status {
			t.Fatalf("status=%d range=%q: %s", tc.code, tc.cr, got.Status)
		}
	}
	r := headResponse(200, "0-0/*")
	r.Header.Set("Content-Type", "text/html")
	if supabaseHeadResult(r).Status != "inconclusive" {
		t.Fatal("HTML success accepted")
	}
	r = headResponse(200, "0-0/*")
	r.Header.Add("Content-Range", "*/*")
	if supabaseHeadResult(r).Status != "inconclusive" {
		t.Fatal("conflicting headers accepted")
	}
	a, _ := NewWithTargets(time.Second, nil, []string{"a", "b"})
	a.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/a") {
			return headResponse(200, "0-0/*"), nil
		}
		return headResponse(429, ""), nil
	})
	got := a.Audit(t.Context(), "generic_api_key", ownedPublishable, map[string]string{"SUPABASE_URL": "https://abcdefghijklmnopqrst.supabase.co"})
	if got.Status != "inconclusive" || !got.HasAccessObservation() || len(got.Checks) != 2 || len(got.Capabilities) != 1 {
		t.Fatal("partial known access discarded")
	}
}

func TestSupabaseBudgetCancellationAndKeyCacheIsolation(t *testing.T) {
	calls := 0
	a, _ := NewWithTargets(time.Second, nil, []string{"a"})
	a.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) { calls++; return headResponse(200, "0-0/*"), nil })
	bindings := map[string]string{"SUPABASE_URL": "https://abcdefghijklmnopqrst.supabase.co"}
	for i := 0; i < 33; i++ {
		key := ownedPublishable + fmt.Sprint(i)
		result := a.Audit(t.Context(), "generic_api_key", key, bindings)
		if i < 32 && result.Status != "public_read_allowed" || i == 32 && result.Status != "inconclusive" {
			t.Fatal("shared budget or key separation failed")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if a.Audit(ctx, "generic_api_key", ownedPublishable+"0", bindings).Status != "inconclusive" || calls != 32 {
		t.Fatal("cancellation or budget failed open")
	}
	for _, key := range []string{"sb_secret_" + strings.Repeat("x", 32), "ordinary-secret"} {
		if a.Audit(t.Context(), "generic_api_key", key, bindings) != nil {
			t.Fatal("nonpublic key used by public audit")
		}
	}
}

type unreadHeadBody struct{ closed bool }

func (*unreadHeadBody) Read([]byte) (int, error) { panic("HEAD response body must not be read") }
func (b *unreadHeadBody) Close() error           { b.closed = true; return nil }

func TestSupabaseNeverReadsBodyAndRetriesInconclusive(t *testing.T) {
	a, _ := NewWithTargets(time.Second, nil, []string{"a"})
	calls := 0
	body := &unreadHeadBody{}
	a.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		r := headResponse(200, "0-0/*")
		if calls == 1 {
			r.StatusCode = 429
		}
		r.Body = body
		return r, nil
	})
	bindings := map[string]string{"SUPABASE_URL": "https://abcdefghijklmnopqrst.supabase.co"}
	if a.Audit(t.Context(), "generic_api_key", ownedPublishable, bindings).Status != "inconclusive" || !body.closed {
		t.Fatal("HEAD body lifecycle or error changed")
	}
	if a.Audit(t.Context(), "generic_api_key", ownedPublishable, bindings).Status != "public_read_allowed" || calls != 2 {
		t.Fatal("inconclusive read cached as definitive")
	}
}

func TestSupabaseRedirectNeverForwardsPublicKey(t *testing.T) {
	for _, sameHost := range []bool{true, false} {
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			target := "https://foreign.invalid/key-collector"
			if sameHost {
				target = "https://abcdefghijklmnopqrst.supabase.co/other"
			}
			w.Header().Set("Location", target)
			w.WriteHeader(http.StatusFound)
		}))
		local, _ := url.Parse(server.URL)
		a, _ := NewWithTargets(time.Second, nil, []string{"a"})
		a.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host != "abcdefghijklmnopqrst.supabase.co" || r.URL.Path != "/rest/v1/a" {
				t.Fatal("redirect credential forwarding attempted")
			}
			copy := r.Clone(r.Context())
			u := *r.URL
			u.Scheme, u.Host = local.Scheme, local.Host
			copy.URL = &u
			return http.DefaultTransport.RoundTrip(copy)
		})
		result := a.Audit(t.Context(), "generic_api_key", ownedPublishable, map[string]string{"SUPABASE_URL": "https://abcdefghijklmnopqrst.supabase.co"})
		server.Close()
		if result.Status != "inconclusive" || calls != 1 {
			t.Fatal("redirect followed or accepted")
		}
	}
}

func FuzzSupabasePublicKey(f *testing.F) {
	f.Add(legacyAnon())
	f.Add(ownedPublishable)
	f.Add("sb_secret_never_send")
	f.Fuzz(func(t *testing.T, key string) {
		ref, ok := supabasePublicKey(key)
		if ok && !publishableKey.MatchString(key) && !supabaseRef.MatchString(ref) {
			t.Fatal("unbound public key accepted")
		}
	})
}
