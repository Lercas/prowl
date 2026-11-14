package verify

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestVerifyLiteralUsesExactBindingsAndScopedCache(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: verifierRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("Authorization") != "Bearer owned-value" || r.Header.Get("X-Account") != "tenant_a" {
			t.Fatal("provider received an invented binding")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	v := &Verifier{ID: "alpha", Match: []string{"alpha"}, Extract: map[string]string{"account": `tenant_[ab]`}, Requests: []Request{{URL: "https://owned.invalid/", Headers: map[string]string{"Authorization": "Bearer {{secret}}", "X-Account": "{{account}}"}}}}
	set := mockSet(t, client, v)
	for _, bindings := range []map[string]string{
		{"account": "tenant_a"}, {"Account": "tenant_a", "secret": "must-not-replace-primary"},
	} {
		if r := set.VerifyLiteral(context.Background(), "alpha", "owned-value", bindings, false); r.Status != Verified {
			t.Fatalf("valid binding rejected: %+v", r)
		}
	}
	if calls != 1 {
		t.Fatal("identical resolved variables did not share the cache")
	}
	for _, bindings := range []map[string]string{
		nil, {"note": "account=tenant_a"}, {"account": "prefix tenant_a"},
		{"account": "tenant_a\n"}, {"account": "tenant_a", "Account": "tenant_b"},
		{"account": "", "Account": "tenant_a"},
	} {
		if r := set.VerifyLiteral(context.Background(), "alpha", "owned-value", bindings, false); r.Status != Errored {
			t.Fatal("invalid or ambiguous binding got a verdict")
		}
	}
	many := map[string]string{"account": "tenant_a"}
	for i := 0; i < 129; i++ {
		many[strings.Repeat("x", i+1)] = "irrelevant"
	}
	if r := set.VerifyLiteral(context.Background(), "alpha", "owned-value", many, false); r.Status != Errored || calls != 1 {
		t.Fatal("binding budget bypassed or invalid data reached provider")
	}
}

func TestLiteralVarsTypedPrimaryAliasesAndAmbiguity(t *testing.T) {
	v := &Verifier{ID: "aws", Match: []string{"aws"}, Extract: map[string]string{"aws_access_key_id": `(?:AKIA|ASIA)[0-9A-Z]{16}`, "aws_secret_access_key": `[A-Za-z0-9/+]{40}`}, Requests: []Request{{URL: "https://owned.invalid/"}}}
	set := mockSet(t, &http.Client{}, v)
	v = set.verifiers[0]
	const key = "AKIANAFGYOEYPXU1DSYP"
	const secret = "Q5t7U9i2O4p6A8s0D3f5G7h9J1k3L5m7N9o2P4q6"
	vars, ok := literalVars(v, "aws_access_key_id", key, map[string]string{"secretAccessKey": secret})
	if !ok || vars["aws_access_key_id"] != key || vars["aws_secret_access_key"] != secret || vars["secret"] != key {
		t.Fatal("typed primary or explicit alias lost")
	}
	if _, ok := literalVars(v, "aws_access_key_id", key, map[string]string{"secretAccessKey": secret, "AWS_ACCESS_KEY_ID": "AKIA4MNQ2RST7UVWX9YZ"}); ok {
		t.Fatal("sibling replaced the typed primary")
	}
}
