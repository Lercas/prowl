package verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestNonMatchingResponseDoesNotProveCredentialRejection(t *testing.T) {
	for _, status := range []int{200, 301, 400, 403, 404} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			defer srv.Close()
			v := &Verifier{ID: "mock", Match: []string{"mocktoken"}, Requests: []Request{{URL: srv.URL, Matchers: []Matcher{{Type: "word", Words: []string{"authenticated-private-response"}}}}}}
			if err := compileVerifier(v); err != nil {
				t.Fatal(err)
			}
			s := &Set{client: srv.Client(), verifiers: []*Verifier{v}}
			if r := s.Verify(context.Background(), "mocktoken", "synthetic-key", "", false); r.Status != Errored {
				t.Fatal("missing positive evidence was reported as credential rejection")
			}
		})
	}
}

func TestNonProviderSpecificGenericCandidatesAreNeverSentToAProvider(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	v := &Verifier{ID: "stripe", Match: []string{"stripe", "sk_live_"}, Requests: []Request{{URL: srv.URL}}}
	s := &Set{client: srv.Client(), verifiers: []*Verifier{v}}
	for _, typ := range []string{"generic_password", "generic_semantic_secret"} {
		if r := s.Verify(context.Background(), typ, "\x73k_live_synthetic_value", "", false); r.Status != Unsupported {
			t.Fatal("generic candidate was routed by value alone")
		}
	}
	if r := s.Verify(context.Background(), "generic_high_entropy", "my_stripe_password", "", false); r.Status != Unsupported {
		t.Fatal("entropy candidate routed by an incidental provider word")
	}
	if calls.Load() != 0 {
		t.Fatal("provider received a generic candidate")
	}
}

func TestMalformedVerificationMatchersAreRejected(t *testing.T) {
	for _, matcher := range []Matcher{{Type: "typo", Negative: true}, {Type: "word", Negative: true}, {Type: "regex", Negative: true}, {Type: "status", Status: []int{0}}} {
		v := &Verifier{ID: "mock", Match: []string{"mocktoken"}, Requests: []Request{{URL: "https://example.invalid", Matchers: []Matcher{matcher}}}}
		if err := compileVerifier(v); err == nil {
			t.Fatal("malformed matcher can manufacture a live verdict")
		}
	}
}
