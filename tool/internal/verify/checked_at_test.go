package verify

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCachedResultPreservesOriginalAttemptTime(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer srv.Close()
	set, err := Load(time.Second, writeVerifier(t, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC()
	first := set.Verify(t.Context(), "mocktoken", "owned-value", "", false)
	cached := set.Verify(t.Context(), "mocktoken", "owned-value", "", false)
	if calls.Load() != 1 || first.CheckedAt.IsZero() || first.CheckedAt.Before(before) || first.CheckedAt.After(time.Now()) || !first.CheckedAt.Equal(cached.CheckedAt) {
		t.Fatal("cache hit acquired a new verification timestamp or lost its source attempt")
	}
	for _, r := range []Result{set.Verify(t.Context(), "unknown", "owned-value", "", false), set.Verify(t.Context(), "mocktoken", "owned-value", "", true)} {
		if !r.CheckedAt.IsZero() {
			t.Fatal("an unattempted check acquired a provider timestamp")
		}
	}
}
