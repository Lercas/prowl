package safehttp

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestInferencePinsLocalServiceAndBlocksRedirects(t *testing.T) {
	var calls atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer trap.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, trap.URL, http.StatusFound) }))
	defer server.Close()
	before := AllowPrivate.Load()
	client, err := InferenceClient(server.URL, false, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := client.Get(server.URL); err == nil {
		resp.Body.Close()
		t.Fatal("inference followed a redirect")
	}
	if resp, err := client.Get(trap.URL); err == nil {
		resp.Body.Close()
		t.Fatal("inference reached an unselected loopback port")
	}
	if calls.Load() != 0 || AllowPrivate.Load() != before {
		t.Fatal("inference leaked to another service or changed global SSRF policy")
	}
}

func TestInferenceEndpointValidationIsIndependentOfGlobalPolicy(t *testing.T) {
	for _, endpoint := range []string{"http://example.invalid/model", "https://example.invalid/model", "http://127.0.0.1:8080/?key=owned", "http://user:owned@127.0.0.1/model", "file:///owned"} {
		if _, err := InferenceClient(endpoint, false, time.Second); err == nil {
			t.Fatalf("endpoint accepted: %s", endpoint)
		}
	}
	if _, err := InferenceClient("http://example.invalid/model", true, time.Second); err == nil {
		t.Fatal("remote plaintext inference accepted")
	}
	if _, err := InferenceClient("https://example.invalid/model", true, time.Second); err != nil {
		t.Fatal(err)
	}
}
