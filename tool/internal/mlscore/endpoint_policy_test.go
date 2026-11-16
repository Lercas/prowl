package mlscore

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lercas/prowl/tool/internal/safehttp"
)

func TestLegacySidecarRejectsRemoteBeforeTransport(t *testing.T) {
	client := New("https://owned.invalid/model", 0.3)
	calls := 0
	if client.http != nil {
		client.http.Transport = scoreRoundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"results":[{"score":1}]}`))}, nil
		})
	}
	healthErr := client.Health(context.Background())
	results, scoreErr := client.Score(context.Background(), []Record{{Value: "owned-candidate", Context: Context{Line: "owned context"}}})
	if healthErr == nil || scoreErr == nil || results != nil || calls != 0 {
		t.Fatalf("remote sidecar without opt-in reached transport: calls=%d health_error=%v score_error=%v", calls, healthErr, scoreErr)
	}
}

func TestSidecarEndpointPolicyMatrix(t *testing.T) {
	for _, test := range []struct {
		url           string
		remote, valid bool
	}{
		{"http://127.0.0.1:8799", false, true}, {"http://localhost:8799/selected", false, true}, {"http://[::1]:8799", false, true},
		{"https://owned.invalid", false, false}, {"http://owned.invalid", false, false}, {"http://owned.invalid", true, false}, {"https://owned.invalid", true, true},
		{"https://192.0.2.1", false, false}, {"http://user:PRIVATE_ENDPOINT@127.0.0.1:8799", true, false},
		{"http://127.0.0.1:8799/?token=PRIVATE_ENDPOINT", true, false}, {"http://127.0.0.1:8799/#PRIVATE_ENDPOINT", true, false},
		{"file:///PRIVATE_ENDPOINT", true, false}, {"ftp://owned.invalid", true, false}, {"not-an-endpoint", true, false},
	} {
		client, err := NewWithPolicy(test.url, 0.3, test.remote)
		if (err == nil) != test.valid || (client != nil) != test.valid {
			t.Fatalf("endpoint policy mismatch: remote=%v valid=%v error=%v", test.remote, test.valid, err)
		}
		if err != nil && strings.Contains(err.Error(), "PRIVATE_ENDPOINT") {
			t.Fatal("endpoint validation disclosed URL credentials or metadata")
		}
	}
}

func TestSidecarLocalWithoutGlobalBypassIgnoresProxy(t *testing.T) {
	before := safehttp.AllowPrivate.Swap(false)
	defer safehttp.AllowPrivate.Store(before)
	var proxyCalls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { proxyCalls.Add(1); w.WriteHeader(500) }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)
	var scoreCalls atomic.Int32
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/selected/health":
			w.WriteHeader(200)
		case "/selected/score":
			var input struct {
				Records []Record `json:"records"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if len(input.Records) != 1 || input.Records[0].Value != "owned-candidate" {
				t.Error("selected sidecar lost input")
			}
			scoreCalls.Add(1)
			fmt.Fprint(w, `{"results":[{"score":0.9}]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer local.Close()
	client := New(local.URL+"/selected", 0.3)
	if err := client.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	results, err := client.Score(t.Context(), []Record{{Value: "owned-candidate"}})
	if err != nil || len(results) != 1 || results[0].Score != 0.9 || scoreCalls.Load() != 1 || proxyCalls.Load() != 0 || safehttp.AllowPrivate.Load() {
		t.Fatal("local endpoint required global bypass, used proxy, or changed policy", err)
	}
}

func TestSidecarBlocksSameOriginAndCrossOriginRedirects(t *testing.T) {
	before := safehttp.AllowPrivate.Swap(false)
	defer safehttp.AllowPrivate.Store(before)
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, cross := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/cross=%v", status, cross), func(t *testing.T) {
				var forwarded atomic.Int32
				trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { forwarded.Add(1); w.WriteHeader(200) }))
				defer trap.Close()
				local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/trap" {
						forwarded.Add(1)
						w.WriteHeader(200)
						return
					}
					target := "/trap"
					if cross {
						target = trap.URL + "/trap"
					}
					http.Redirect(w, r, target, status)
				}))
				defer local.Close()
				client := New(local.URL, 0.3)
				healthErr := client.Health(t.Context())
				results, scoreErr := client.Score(t.Context(), []Record{{Value: "owned-candidate"}})
				if healthErr == nil || scoreErr == nil || results != nil || forwarded.Load() != 0 {
					t.Fatal("redirect forwarded sidecar request", healthErr, scoreErr, forwarded.Load())
				}
			})
		}
	}
}

func TestSidecarExplicitHTTPSOptInUsesSelectedTransport(t *testing.T) {
	client, err := NewWithPolicy("https://owned.invalid/selected", 0.3, true)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	client.http.Transport = scoreRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://owned.invalid/selected/score" {
			t.Error("wrong selected endpoint")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"results":[{"score":1}]}`))}, nil
	})
	results, err := client.Score(t.Context(), []Record{{Value: "owned-candidate"}})
	if err != nil || len(results) != 1 || results[0].Score != 1 || calls != 1 {
		t.Fatal("explicit HTTPS opt-in did not reach selected owned transport", err)
	}
}
