package mlscore

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/Lercas/prowl/tool/internal/safehttp"
)

// TestClientNormalSidecarWorks confirms a plain, well-behaved sidecar URL still works end-to-end
// through the safehttp client: the request reaches the server and the decoded results come back.
// httptest binds 127.0.0.1, so the production private-IP dial guard is relaxed for the test only
// (AllowPrivate is restored to false on return); the cross-origin redirect guard stays on regardless.
func TestClientNormalSidecarWorks(t *testing.T) {
	defer safehttp.AllowPrivate.Store(false)
	safehttp.AllowPrivate.Store(true)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/score" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []Result{{Score: 0.9, IsSecret: true, Type: "aws", Stage: "l2"}},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, 0.2)
	res, err := c.Score(context.Background(), []Record{{Value: "masked"}})
	if err != nil {
		t.Fatalf("Score against a normal sidecar: %v", err)
	}
	if len(res) != 1 || res[0].Score != 0.9 || !res[0].IsSecret {
		t.Fatalf("Score result = %+v, want one secret result score 0.9", res)
	}
}

// TestClientRefusesCrossOriginRedirect is the regression for the redirect-forwarding fix: a sidecar
// that 302-redirects /score to a DIFFERENT origin must NOT cause the (masked) payload to be re-POSTed
// to the redirect target. Before the fix the mlscore client used a default http.Client (nil
// CheckRedirect), which would follow the redirect and re-send the body cross-origin. With safehttp the
// hop is refused, so the target server is never hit.
func TestClientRefusesCrossOriginRedirect(t *testing.T) {
	defer safehttp.AllowPrivate.Store(false)
	safehttp.AllowPrivate.Store(true)

	// target stands in for the attacker's origin. If the client follows the redirect, this records it.
	var targetHits int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&targetHits, 1)
		// Drain the body so we'd notice the payload arriving.
		_, _ = io.Copy(io.Discard, r.Body)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []Result{{Score: 1.0, IsSecret: true}},
		})
	}))
	defer target.Close()

	// sidecar 302s every request to the target's origin (a different host:port → different origin).
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loc := target.URL + r.URL.Path
		http.Redirect(w, r, loc, http.StatusFound)
	}))
	defer sidecar.Close()

	// Sanity: the two servers really are different origins, else the test proves nothing.
	su, _ := url.Parse(sidecar.URL)
	tu, _ := url.Parse(target.URL)
	if su.Host == tu.Host {
		t.Fatalf("test setup: sidecar and target share host %q; need distinct origins", su.Host)
	}

	c := New(sidecar.URL, 0.2)
	_, err := c.Score(context.Background(), []Record{{Value: "masked-payload"}})
	if err == nil {
		t.Fatal("Score followed a cross-origin redirect (no error); the payload could reach the attacker")
	}
	if got := atomic.LoadInt32(&targetHits); got != 0 {
		t.Fatalf("payload reached the redirect target %d time(s); cross-origin redirect was followed", got)
	}
}
