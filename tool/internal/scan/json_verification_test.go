package scan

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"github.com/Lercas/prowl/tool/internal/secretindex"
	"github.com/Lercas/prowl/tool/internal/verify"
)

func TestJSONVerificationUsesOnlyUnambiguousSiblingBindings(t *testing.T) {
	previous := safehttp.AllowPrivate.Load()
	safehttp.AllowPrivate.Store(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(previous) })
	const value = "sk_live_Q5t7U9i2O4p6A8s0D3f5G7h9"
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+value || r.Header.Get("X-Account") != "tenant_a" {
			t.Error("provider received an invented credential or companion")
		}
		w.WriteHeader(401)
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "stripe.yaml")
	definition := "id: stripe\nmatch: [stripe]\nextract:\n  account: 'tenant_[ab]'\nrequests:\n  - method: GET\n    url: " + srv.URL + "\n    headers:\n      Authorization: 'Bearer {{secret}}'\n      X-Account: '{{account}}'\n    matchers:\n      - type: status\n        status: [200]\n"
	if err := os.WriteFile(path, []byte(definition), 0600); err != nil {
		t.Fatal(err)
	}
	id, err := secretindex.LoadIdentity(filepath.Join(t.TempDir(), "index"), true)
	if err != nil {
		t.Fatal(err)
	}
	token := `"token":"` + escapedJSON(value) + `"`
	for _, c := range []struct {
		text  string
		calls int32
	}{
		{"{\n" + token + `,"account":"tenant_a"}`, 1},
		{`{` + token + `,"Account":"tenant_a"}`, 1},
		{`{` + token + `,"note":"account=tenant_a"}`, 0},
		{`{` + token + `,"account":"tenant_a\n"}`, 0},
		{`{` + token + `,"other":{"account":"tenant_a"}}`, 0},
		{`{"account":"tenant_a","other":{` + token + `}}`, 0},
		{`{` + token + `,"account":"tenant_a","Account":"tenant_b"}`, 0},
		{`{` + token + `,"account":"tenant_a","account":null}`, 0},
		{`{"token":"` + value + `\uD800"}`, 0},
		{`{"token":"` + value + `\q"}`, 0},
	} {
		set, err := verify.Load(time.Second, path)
		if err != nil {
			t.Fatal(err)
		}
		var observations []model.Finding
		p := New(Options{Detector: detector(t), Verifiers: set, ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location, ObserveVerification: func(f model.Finding) { observations = append(observations, f) }})
		before := calls.Load()
		it := model.Item{Source: "code", Path: "production.json", Text: c.text}
		fs := p.Findings(t.Context(), it)
		if calls.Load()-before != c.calls {
			t.Fatalf("provider calls=%d want %d", calls.Load()-before, c.calls)
		}
		if c.calls == 1 {
			if len(observations) != 1 || observations[0].Verified == nil || *observations[0].Verified {
				t.Fatal("provider rejection lost before ML")
			}
			f := observations[0]
			wantLine, wantCol := newLineIndex(c.text).cols(strings.Index(c.text, escapedJSON(value)))
			if f.Line != wantLine || f.Col != wantCol || f.IndexLocationID != id.Location(it.Source, it.Path, wantLine, wantCol) || len(fs) != 1 {
				t.Fatal("verification observation used synthetic source coordinates")
			}
		}
	}
}
