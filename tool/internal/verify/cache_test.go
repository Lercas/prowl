package verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCacheSeparatesContextAndCoalesces(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-Account") == "account-A" {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(401)
		}
	}))
	defer srv.Close()
	v := &Verifier{ID: "vendor", Match: []string{"vendor"}, Extract: map[string]string{"account": `account-[AB]`}, Requests: []Request{{URL: srv.URL, Headers: map[string]string{"Authorization": "Bearer {{secret}}", "X-Account": "{{account}}"}, Matchers: []Matcher{{Type: "status", Status: []int{200}}}}}}
	if err := compileVerifier(v); err != nil {
		t.Fatal(err)
	}
	set := &Set{client: srv.Client(), verifiers: []*Verifier{v}, sem: make(chan struct{}, 8)}
	var wg sync.WaitGroup
	for range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := set.Verify(context.Background(), "vendor_token", "synthetic-secret", "account-A", false); r.Status != Verified {
				t.Errorf("expected live: %v", r.Status)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("duplicate provider requests: %d", calls.Load())
	}
	if r := set.Verify(context.Background(), "vendor_token", "synthetic-secret", "account-B", false); r.Status != Invalid {
		t.Fatal("cached another account's result")
	}
	if calls.Load() != 2 {
		t.Fatal("context not included in cache identity")
	}
	// Ambiguity must be checked before a cache hit for the first extracted account.
	if r := set.Verify(context.Background(), "vendor_token", "synthetic-secret", "account-A account-B", false); r.Status != Errored {
		t.Fatal("ambiguous companion context borrowed a cached LIVE verdict")
	}
	if calls.Load() != 2 {
		t.Fatal("ambiguous context was sent to the provider")
	}
	if r := set.Verify(context.Background(), "vendor_token", "synthetic-secret", "account-A account-A", false); r.Status != Verified {
		t.Fatal("repeated identical companion value became ambiguous")
	}
}
func TestInconclusiveResponseIsNotCached(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(500)
		} else {
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()
	set, err := Load(0, writeVerifier(t, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	first := set.Verify(context.Background(), "mocktoken", "synthetic-secret", "", false)
	// The helper verifier routes by its own provider ID.
	if first.Status == Unsupported {
		t.Fatal("incorrect test routing")
	}
	if first.Status != Errored {
		t.Fatalf("provider outage classified %v", first.Status)
	}
	second := set.Verify(context.Background(), "mocktoken", "synthetic-secret", "", false)
	if second.Status != Verified || calls.Load() != 2 {
		t.Fatalf("transient result cached: %v calls %d", second.Status, calls.Load())
	}
}
