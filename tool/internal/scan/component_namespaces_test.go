package scan

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Lercas/prowl/tool/internal/credentialset"
	"github.com/Lercas/prowl/tool/internal/model"
)

func TestCrossFileNestedNamespaces(t *testing.T) {
	allowOrderFixture(t)
	for _, tc := range []struct{ name, keyPath, key, accountPath, account string }{
		{"json", "a.json", `{"prod":{"service":{"accessKeyId":"AKIANAFGYOEYPXU1DSYP"}}}`, "b.json", `{"prod":{"service":{"account":"tenant_a","timeout":30}}}`},
		{"yaml", "a.yaml", "prod:\n  service:\n    accessKeyId: AKIANAFGYOEYPXU1DSYP\n", "b.yaml", "prod:\n  service:\n    account: tenant_a\n"},
		{"toml-tables", "a.toml", "[prod.service]\naccessKeyId='AKIANAFGYOEYPXU1DSYP'\n", "b.toml", "[prod.service]\naccount='tenant_a'\n"},
		{"toml-dotted", "a.toml", "prod.service.accessKeyId='AKIANAFGYOEYPXU1DSYP'\n", "b.toml", "prod.service.account='tenant_a'\n"},
		{"toml-inline", "a.toml", "prod={service={accessKeyId='AKIANAFGYOEYPXU1DSYP'}}\n", "b.toml", "prod={service={account='tenant_a'}}\n"},
		{"cross-format", "a.json", `{"prod":{"service":{"accessKeyId":"AKIANAFGYOEYPXU1DSYP"}}}`, "b.yaml", "prod:\n  service:\n    account: tenant_a\n"},
		{"quoted-dot", "a.json", `{"prod.service":{"accessKeyId":"AKIANAFGYOEYPXU1DSYP"}}`, "b.toml", "['prod.service']\naccount='tenant_a'\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("X-Account") != "tenant_a" {
					t.Error("wrong namespace reached verifier")
				}
				w.WriteHeader(200)
			}))
			defer srv.Close()
			scope := credentialset.NewScope()
			items := []model.Item{{Source: "code", Path: tc.keyPath, Text: tc.key, CredentialScope: scope}, {Source: "code", Path: tc.accountPath, Text: tc.account, CredentialScope: scope}}
			fs, coverage := runComponentItems(t, Options{Detector: detector(t), Verifiers: orderVerifier(t, srv.URL, "extract:\n  account: 'tenant_[ab]'\n"), CrossFile: true}, items)
			complete, _, _ := coverage.Snapshot()
			if !complete || calls.Load() != 1 {
				t.Fatalf("namespace failed: complete=%v calls=%d findings=%v", complete, calls.Load(), fs)
			}
			found := false
			for _, f := range fs {
				if f.Type == "aws_access_key_id" {
					found = f.Verified != nil && *f.Verified && f.Verification != nil && f.Verification.Components != nil && len(f.Verification.Components.Fields["account"]) == 1
				}
			}
			if !found {
				t.Fatal("nested primary lost verdict/component evidence")
			}
		})
	}
}

func TestCrossFileNestedNamespacesNeverBorrow(t *testing.T) {
	allowOrderFixture(t)
	for _, tc := range []struct{ name, path, text string }{
		{"sibling", "b.json", `{"dev":{"account":"tenant_a"}}`},
		{"parent", "b.json", `{"account":"tenant_a"}`},
		{"child", "b.json", `{"prod":{"service":{"account":"tenant_a"}}}`},
		{"case", "b.json", `{"Prod":{"account":"tenant_a"}}`},
		{"dots", "b.json", `{"prod.account":"tenant_a"}`},
		{"array", "b.json", `{"prod":[{"account":"tenant_a"}]}`},
		{"null-shadow", "b.json", `{"prod":{"Account":null,"account":"tenant_a"}}`},
		{"container-shadow", "b.json", `{"prod":{"Account":{},"account":"tenant_a"}}`},
		{"duplicate", "b.json", `{"prod":{"account":"tenant_a"},"prod":{"account":"tenant_a"}}`},
		{"yaml-alias", "b.yaml", "defaults: &d {account: tenant_a}\nprod: *d\n"},
		{"yaml-multiple", "b.yaml", "prod: {account: tenant_a}\n---\nprod: {account: tenant_b}\n"},
		{"toml-array", "b.toml", "[[prod]]\naccount='tenant_a'\n"},
		{"comment", "b.yaml", "# prod: {account: tenant_a}\nprod: {timeout: 30}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(200) }))
			defer srv.Close()
			scope := credentialset.NewScope()
			items := []model.Item{{Source: "code", Path: "a.json", Text: `{"prod":{"accessKeyId":"AKIANAFGYOEYPXU1DSYP"}}`, CredentialScope: scope}, {Source: "code", Path: tc.path, Text: tc.text, CredentialScope: scope}}
			fs, _ := runComponentItems(t, Options{Detector: detector(t), Verifiers: orderVerifier(t, srv.URL, "extract:\n  account: 'tenant_[ab]'\n"), CrossFile: true}, items)
			if calls.Load() != 0 || !hasIncompleteFinding(fs) {
				t.Fatal("foreign or ambiguous namespace accepted")
			}
		})
	}
}

func TestComponentNamespaceSegmentsAreUnambiguous(t *testing.T) {
	if componentNamespace([]string{"prod.service"}) == componentNamespace([]string{"prod", "service"}) {
		t.Fatal("namespace segment boundary collapsed")
	}
	// Default scans do not retain cross-file namespace metadata.
	it := model.Item{Source: "code", Path: "a.json", Text: `{"prod":{"key":"ordinary"}}`}
	for _, ext := range []string{"json", "yaml", "toml"} {
		it.Path = "a." + ext
		it.Text = map[string]string{"json": `{"prod":{"key":"ordinary"}}`, "yaml": "prod:\n  key: ordinary\n", "toml": "[prod]\nkey='ordinary'\n"}[ext]
		doc := parseLiterals(t.Context(), it, false)
		if doc == nil || len(doc.componentNamespaces) != 0 {
			t.Fatal("default parser retained cross-file metadata", strings.TrimSpace(it.Path))
		}
	}
}

func TestCrossFileSiblingNamespacesCanVerifyIndependently(t *testing.T) {
	allowOrderFixture(t)
	var mu sync.Mutex
	accounts := make(map[string]int)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		accounts[r.Header.Get("X-Account")]++
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()
	scope := credentialset.NewScope()
	items := []model.Item{
		{Source: "code", Path: "a.json", Text: `{"prod":{"accessKeyId":"AKIANAFGYOEYPXU1DSYP"},"dev":{"accessKeyId":"AKIANAFGYOEYPXU1DSYP"}}`, CredentialScope: scope},
		{Source: "code", Path: "b.yaml", Text: "prod:\n  account: tenant_a\ndev:\n  account: tenant_b\n", CredentialScope: scope},
	}
	fs, coverage := runComponentItems(t, Options{Detector: detector(t), Verifiers: orderVerifier(t, srv.URL, "extract:\n  account: 'tenant_[ab]'\n"), CrossFile: true, Workers: 2}, items)
	complete, _, _ := coverage.Snapshot()
	mu.Lock()
	defer mu.Unlock()
	if !complete || accounts["tenant_a"] != 1 || accounts["tenant_b"] != 1 || len(accounts) != 2 {
		t.Fatalf("siblings mixed or conflicted: complete=%v accounts=%v findings=%v", complete, accounts, fs)
	}
}
