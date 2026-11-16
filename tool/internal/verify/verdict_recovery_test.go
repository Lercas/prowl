package verify

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestUnmatchedResponseCanRecoverWithoutCachedRejection(t *testing.T) {
	for _, status := range []int{200, 400, 403, 404} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if calls.Add(1) == 1 {
					w.WriteHeader(status)
					return
				}
				_, _ = w.Write([]byte("authenticated-private-response"))
			}))
			defer srv.Close()
			v := &Verifier{ID: "owned", Match: []string{"owned"}, Requests: []Request{{URL: srv.URL, Matchers: []Matcher{{Type: "word", Words: []string{"authenticated-private-response"}}}}}}
			set := mockSet(t, srv.Client(), v)
			first := set.Verify(t.Context(), "owned_token", "synthetic-key", "", false)
			second := set.Verify(t.Context(), "owned_token", "synthetic-key", "", false)
			if first.Status != Errored || first.Note != "provider response inconclusive" || second.Status != Verified || calls.Load() != 2 {
				t.Fatal("unmatched response became a definitive/cached credential verdict")
			}
		})
	}
}

func TestUnstructuredCompanionBudgetBeforeCache(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer srv.Close()
	v := &Verifier{ID: "owned", Match: []string{"owned"}, Extract: map[string]string{"account": `account-[AB]`}, Requests: []Request{{URL: srv.URL, Headers: map[string]string{"X-Account": "{{account}}"}}}}
	set := mockSet(t, srv.Client(), v)
	if result := set.Verify(t.Context(), "owned_token", "synthetic-key", strings.Repeat("account-A ", 1024), false); result.Status != Verified {
		t.Fatal("exact repeated-match budget rejected")
	}
	for _, text := range []string{strings.Repeat("account-A ", 1025), "account-A account-B"} {
		if result := set.Verify(t.Context(), "owned_token", "synthetic-key", text, false); result.Status != Errored {
			t.Fatal("invalid context borrowed cached verdict")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("unsafe context reached provider")
	}
}

func TestGenericRoutingRequiresEstablishedIdentity(t *testing.T) {
	set := &Set{verifiers: []*Verifier{{ID: "stripe", Match: []string{"stripe", "sk_live_"}}}}
	for _, typ := range []string{"generic_password", "generic_api_key", "generic_semantic_secret", "generic-password", "generic-semantic-secret"} {
		if set.find(typ, "sk_live_owned_synthetic") != nil {
			t.Fatal("generic candidate borrowed provider identity", typ)
		}
	}
	if set.find("generic_high_entropy", "my_stripe_password") != nil || set.find("generic_high_entropy", "sk_live_owned_synthetic") == nil {
		t.Fatal("entropy fallback must require a provider prefix")
	}
	if set.find("stripe_secret", "opaque-owned-value") == nil {
		t.Fatal("typed provider route lost")
	}
}
