package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"github.com/Lercas/prowl/tool/internal/verify"
)

func TestMalformedStructuredLiteralsAreNeverSubmitted(t *testing.T) {
	const raw = "\x73k_live_Q5t7U9i2O4p6A8s0D3f5G7h9"
	previous := safehttp.AllowPrivate.Load()
	safehttp.AllowPrivate.Store(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(previous) })
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	p := filepath.Join(t.TempDir(), "stripe.yaml")
	definition := "id: stripe\nmatch: [stripe]\nrequests:\n  - method: GET\n    url: " + srv.URL + "\n    headers:\n      Authorization: 'Bearer {{secret}}'\n    matchers:\n      - type: status\n        status: [200]\n"
	if err := os.WriteFile(p, []byte(definition), 0600); err != nil {
		t.Fatal(err)
	}
	for _, item := range []model.Item{
		{Path: "production.json", Source: "code", Text: `{"token":"` + raw + `\uD800"}`},
		{Path: "production.json", Source: "code", Text: `{"token":"` + raw + `\q"}`},
		{Path: "production.toml", Source: "code", Text: `token="` + raw + `\q"`},
		{Path: "production.yaml", Source: "code", Text: `token: "` + raw + `\q"`},
		{Path: "production.json", Source: "code", Text: `{"token":"` + raw + `","account":"account-A","account":null}`},
		{Path: "production.yaml", Source: "code", Text: "token: " + raw + "\naccount: account-A\naccount: null\n"},
	} {
		vset, err := verify.Load(time.Second, p)
		if err != nil {
			t.Fatal(err)
		}
		cov := model.NewCoverage()
		ctx := WithOptions(model.WithCoverage(context.Background(), cov), Options{VerifyAll: true})
		fs := Findings(ctx, detector(t), nil, vset, item, nil, nil)
		complete, _, _ := cov.Snapshot()
		if len(fs) == 0 || complete {
			t.Fatal("malformed input lost lexical findings or its incomplete diagnostic")
		}
		for _, f := range fs {
			if f.Verified != nil || f.Verification == nil || f.Verification.Status != "error" {
				t.Fatalf("malformed value got a provider verdict: %s %+v", item.Path, f)
			}
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("malformed literals submitted %d provider requests", calls.Load())
	}
}
