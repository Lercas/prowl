package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Lercas/prowl/tool/internal/credentialset"
	"github.com/Lercas/prowl/tool/internal/model"
	"gopkg.in/yaml.v3"
)

func TestCrossFileYAMLExplicitAliasAndMergeRelationships(t *testing.T) {
	allowOrderFixture(t)
	for _, tc := range []struct{ name, text, account string }{
		{"scalar-alias", "value: &a tenant_a\nprod: {account: *a}\n", "tenant_a"},
		{"mapping-alias", "defaults: &d {account: tenant_a}\nprod: *d\n", "tenant_a"},
		{"nested-alias", "defaults: &d {service: {account: tenant_a}}\nprod: *d\n", "tenant_a"},
		{"merge", "defaults: &d {account: tenant_a}\nprod: {<<: *d}\n", "tenant_a"},
		{"merge-explicit-first", "defaults: &d {account: tenant_b}\nprod: {account: tenant_a, <<: *d}\n", "tenant_a"},
		{"merge-explicit-last", "defaults: &d {account: tenant_b}\nprod: {<<: *d, account: tenant_a}\n", "tenant_a"},
		{"merge-sequence", "first: &a {account: tenant_a}\nsecond: &b {account: tenant_b}\nprod: {<<: [*a, *b]}\n", "tenant_a"},
		{"merge-sequence-alias", "first: &a {account: tenant_a}\nsecond: &b {account: tenant_b}\nlist: &l [*a, *b]\nprod: {<<: *l}\n", "tenant_a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("X-Account") != tc.account {
					t.Error("alias/merge used the wrong effective account")
				}
				w.WriteHeader(200)
			}))
			defer srv.Close()
			key := `{"prod":{"accessKeyId":"AKIANAFGYOEYPXU1DSYP"}}`
			if tc.name == "nested-alias" {
				key = `{"prod":{"service":{"accessKeyId":"AKIANAFGYOEYPXU1DSYP"}}}`
			}
			scope := credentialset.NewScope()
			fs, cov := runComponentItems(t, Options{Detector: detector(t), Verifiers: orderVerifier(t, srv.URL, "extract:\n  account: 'tenant_[ab]'\n"), CrossFile: true}, []model.Item{
				{Source: "code", Path: "a.json", Text: key, CredentialScope: scope},
				{Source: "code", Path: "b.yaml", Text: tc.text, CredentialScope: scope},
			})
			if complete, _, _ := cov.Snapshot(); !complete || calls.Load() != 1 {
				t.Fatalf("explicit relationship failed: complete=%v calls=%d", complete, calls.Load())
			}
			if len(fs) != 1 || fs[0].Verified == nil || !*fs[0].Verified || fs[0].Verification.Components == nil || len(fs[0].Verification.Components.Fields["account"]) != 1 {
				t.Fatal("cross-file alias lost verdict or source-backed component evidence")
			}
			raw, err := json.Marshal(fs)
			if err != nil || strings.Contains(string(raw), tc.account) || strings.Contains(string(raw), "AKIANAFGYOEYPXU1DSYP") {
				t.Fatal("alias relationship disclosed component values")
			}
		})
	}
}

func TestCrossFileYAMLPrimaryAliasKeepsIndependentUseContexts(t *testing.T) {
	allowOrderFixture(t)
	var mu sync.Mutex
	accounts := make(map[string]int)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account := r.Header.Get("X-Account")
		mu.Lock()
		accounts[account]++
		mu.Unlock()
		if account == "tenant_a" {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(401)
		}
	}))
	defer srv.Close()
	scope := credentialset.NewScope()
	fs, coverage := runComponentItems(t, Options{Detector: detector(t), Verifiers: orderVerifier(t, srv.URL, "extract:\n  account: 'tenant_[ab]'\n"), CrossFile: true}, []model.Item{
		{Source: "code", Path: "a.yaml", Text: "defaults: &d {accessKeyId: AKIANAFGYOEYPXU1DSYP}\nprod: *d\n", CredentialScope: scope},
		{Source: "code", Path: "b.json", Text: `{"defaults":{"account":"tenant_a"},"prod":{"account":"tenant_b"}}`, CredentialScope: scope},
	})
	if complete, _, _ := coverage.Snapshot(); !complete || len(fs) != 2 {
		t.Fatalf("primary declaration/alias contexts lost: complete=%v findings=%d", complete, len(fs))
	}
	live, dead := 0, 0
	for _, f := range fs {
		if f.Verified == nil || f.Verification.Components == nil {
			t.Fatal("primary alias lost verification/component evidence")
		}
		if *f.Verified {
			live++
		} else {
			dead++
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if live != 1 || dead != 1 || len(accounts) != 2 || accounts["tenant_a"] != 1 || accounts["tenant_b"] != 1 {
		t.Fatal("primary alias shared another namespace's account or cached verdict")
	}
}

func TestCrossFileYAMLUnsafeRelationshipsNeverProbe(t *testing.T) {
	allowOrderFixture(t)
	for _, text := range []string{
		"defaults: &d {account: tenant_a}\ndev: *d\n",
		"defaults: &d {account: tenant_a}\nprod: {<<: *d, account: null}\n",
		"defaults: &d {account: tenant_a}\nprod: {<<: *d, Account: null}\n",
		"defaults: &d {account: tenant_a}\nprod: {<<: *d, account: {value: tenant_a}}\n",
		"defaults: &d {account: tenant_a}\nprod: {account: tenant_a, account: tenant_b}\n",
		"defaults: &d {account: tenant_a}\nprod: {<<: *d, <<: *d}\n",
		"defaults: &d {child: *d}\nprod: {account: tenant_a}\n",
		"prod: {account: *missing}\n",
		"value: &a tenant_a\n---\nprod: {account: *a}\n",
		"value: &a tenant_a\nprod: {<<: *a}\n",
		"defaults: &d {account: tenant_a}\nprod: [*d]\n",
		"value: &a null\nprod: {account: *a}\n",
		"value: &a 30\nprod: {account: *a}\n",
	} {
		t.Run(text, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(200) }))
			defer srv.Close()
			scope := credentialset.NewScope()
			fs, cov := runComponentItems(t, Options{Detector: detector(t), Verifiers: orderVerifier(t, srv.URL, "extract:\n  account: 'tenant_[ab]'\n"), CrossFile: true}, []model.Item{
				{Source: "code", Path: "a.json", Text: `{"prod":{"accessKeyId":"AKIANAFGYOEYPXU1DSYP"}}`, CredentialScope: scope},
				{Source: "code", Path: "b.yaml", Text: text, CredentialScope: scope},
			})
			if complete, _, _ := cov.Snapshot(); complete || calls.Load() != 0 || !hasIncompleteFinding(fs) {
				t.Fatal("unsafe alias/merge relationship reached the verifier or certified complete")
			}
		})
	}
}

func TestComponentYAMLRelationshipGraphBoundAndCancellation(t *testing.T) {
	text := "base: &n0 {account: tenant_a}\n"
	for i := 1; i <= 20; i++ {
		text += fmt.Sprintf("node%d: &n%d {left: *n%d, right: *n%d}\n", i, i, i-1, i-1)
	}
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(text), &root); err != nil {
		t.Fatal(err)
	}
	if _, ok := componentYAMLMapping(context.Background(), root.Content[0], 0); ok {
		t.Fatal("exponentially repeated alias graph exceeded the shared work budget")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := componentYAMLMapping(ctx, root.Content[0], 0); ok {
		t.Fatal("cancelled relationship resolution succeeded")
	}
}
