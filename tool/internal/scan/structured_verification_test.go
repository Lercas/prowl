package scan

import (
	"encoding/base64"
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
	"github.com/Lercas/prowl/tool/internal/verify"
)

func TestStructuredCompanionVerificationRespectsObjectBoundaries(t *testing.T) {
	previous := safehttp.AllowPrivate.Load()
	safehttp.AllowPrivate.Store(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(previous) })
	const first = "sk_live_Q5t7U9i2O4p6A8s0D3f5G7h9"
	const second = "sk_live_W1e3R5t7Y9u2I4o6P8a0S3d5"
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		token, account := r.Header.Get("Authorization"), r.Header.Get("X-Account")
		if token != "Bearer "+first && token != "Bearer "+second || account != "tenant_a" && account != "tenant_b" {
			t.Error("provider received an invented value or companion")
		}
		if token == "Bearer "+second && account != "tenant_b" {
			t.Error("provider received another object's companion")
		}
		w.WriteHeader(401)
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "stripe.yaml")
	definition := "id: stripe\nmatch: [stripe]\nextract:\n  account: 'tenant_[ab]'\nrequests:\n  - method: GET\n    url: " + srv.URL + "\n    headers:\n      Authorization: 'Bearer {{secret}}'\n      X-Account: '{{account}}'\n    matchers:\n      - type: status\n        status: [200]\n"
	if err := os.WriteFile(path, []byte(definition), 0600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, ext, text string
		calls           int32
		incomplete      bool
	}{
		{"yaml-objects", ".yaml", "one: {account: tenant_a, token: " + first + "}\ntwo: {account: tenant_b, token: " + second + "}\n", 2, false},
		{"yaml-sequence", ".yaml", "accounts:\n  - {account: tenant_a, token: " + first + "}\n  - {account: tenant_b, token: " + second + "}\n", 2, false},
		{"yaml-merge-override", ".yaml", "base: &a {account: tenant_a, token: " + first + "}\ncopy: {<<: *a, account: tenant_b}\n", 2, false},
		{"yaml-scalar-alias", ".yaml", "definition: &a " + first + "\none: {account: tenant_a, token: *a}\ntwo: {account: tenant_b, token: *a}\n", 2, true},
		{"yaml-binary", ".yaml", "account: tenant_a\ntoken: !!binary " + base64.StdEncoding.EncodeToString([]byte(first)) + "\n", 1, false},
		{"toml-tables", ".toml", "[one]\naccount='tenant_a'\ntoken='" + first + "'\n[two]\naccount='tenant_b'\ntoken='" + second + "'\n", 2, false},
		{"toml-array-tables", ".toml", "[[accounts]]\naccount='tenant_a'\ntoken='" + first + "'\n[[accounts]]\naccount='tenant_b'\ntoken='" + second + "'\n", 2, false},
		{"toml-dotted-keys", ".toml", "one.account='tenant_a'\none.token='" + first + "'\ntwo.account='tenant_b'\ntwo.token='" + second + "'\n", 2, false},
		{"toml-inline-array", ".toml", "accounts=[{account='tenant_a', token='" + first + "'}, {account='tenant_b', token='" + second + "'}]\n", 2, false},
		{"yaml-other-object", ".yaml", "account: tenant_a\nother: {token: " + first + "}\n", 0, true},
		{"toml-other-object", ".toml", "account='tenant_a'\n[other]\ntoken='" + first + "'\n", 0, true},
		{"yaml-string-injection", ".yaml", "token: " + first + "\nnote: 'account=tenant_a'\n", 0, true},
		{"toml-string-injection", ".toml", "token='" + first + "'\nnote='account=tenant_a'\n", 0, true},
		{"yaml-duplicate", ".yaml", "token: " + first + "\naccount: tenant_a\naccount: tenant_b\n", 0, true},
		{"yaml-unknown-tag", ".yaml", "token: !env " + first + "\naccount: tenant_a\n", 0, true},
		{"yaml-alias-cycle", ".yaml", "base: &a {self: *a, account: tenant_a, token: " + first + "}\n", 0, true},
		{"yaml-malformed", ".yaml", "token: \"" + first + "\\q\"\naccount: tenant_a\n", 0, true},
		{"toml-malformed", ".toml", "token=\"" + first + "\\q\"\naccount='tenant_a'\n", 0, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			set, err := verify.Load(time.Second, path)
			if err != nil {
				t.Fatal(err)
			}
			before := calls.Load()
			fs := New(Options{Detector: detector(t), Verifiers: set}).Findings(t.Context(), model.Item{Source: "code", Path: "production" + c.ext, Text: c.text})
			if calls.Load()-before != c.calls {
				t.Fatalf("provider calls=%d want %d", calls.Load()-before, c.calls)
			}
			incomplete := false
			verdicts := 0
			for _, f := range fs {
				incomplete = incomplete || model.IsIncompleteFinding(f)
				if f.Verified != nil {
					verdicts++
					if f.Verification == nil || f.Verification.Status != "invalid" || f.Verification.Verifier == "" || f.Verification.CheckedAt == "" {
						t.Fatal("confirmed rejection lost its detailed source verdict")
					}
				}
				if c.calls == 0 && f.Verification != nil && f.Verification.CheckedAt != "" {
					t.Fatal("a blocked structured check acquired a provider attempt timestamp")
				}
				if strings.Contains(f.Rationale, first) || strings.Contains(f.Rationale, second) {
					t.Fatal("verification rationale leaked a credential")
				}
			}
			if incomplete != c.incomplete || c.calls == 0 && verdicts != 0 {
				t.Fatal("unsafe content received a verdict or lost its diagnostic")
			}
		})
	}
}
