package verify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/credentialset"
)

func TestCrossFileProviderUsesObservedRolesAndScopedCache(t *testing.T) {
	ctx := context.Background()
	calls := 0
	client := &http.Client{Transport: verifierRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("Authorization") != "Bearer owned-value" || r.Header.Get("X-Account") != "tenant_a" {
			t.Fatal("provider received invented credential components")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	v := &Verifier{ID: "alpha", Match: []string{"alpha"}, Extract: map[string]string{"account": `tenant_[ab]`}, Requests: []Request{{URL: "https://owned.invalid/", Headers: map[string]string{"Authorization": "Bearer {{secret}}", "X-Account": "{{account}}"}}}}
	set := mockSet(t, client, v)
	components, err := credentialset.New(credentialset.Limits{Observations: 10, Bytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer components.Close()
	scope := credentialset.NewScope()
	for _, p := range []struct{ name, value, location string }{{"alpha_token", "owned-value", "file-a-literal"}, {"account", "tenant_a", "file-b-literal"}} {
		if err := components.Observe(ctx, scope, p.name, p.value, p.location); err != nil {
			t.Fatal(err)
		}
	}
	if err := components.Seal(ctx, true); err != nil {
		t.Fatal(err)
	}
	r, evidence := set.VerifyComponents(ctx, "alpha", "alpha_token", "owned-value", components, scope, false)
	if r.Status != Verified || evidence == nil || len(evidence.Fields["account"]) != 1 || evidence.Fields["account"][0] != "file-b-literal" || len(evidence.Primary) != 1 || evidence.Primary[0] != "file-a-literal" {
		t.Fatal("provider result or cross-file evidence lost")
	}
	encoded, err := json.Marshal(evidence)
	if err != nil || strings.Contains(string(encoded), "alpha_token") || strings.Contains(string(encoded), "owned-value") || strings.Contains(string(encoded), "tenant_a") {
		t.Fatal("evidence echoed source names or component values")
	}
	if r, _ := set.VerifyComponents(ctx, "alpha", "alpha_token", "owned-value", components, scope, false); r.Status != Verified || calls != 1 {
		t.Fatal("resolved components did not share the exact-variable cache")
	}
	for _, tc := range []struct {
		name, value string
		scope       *credentialset.Scope
	}{{"alpha_token", "not-observed", scope}, {"guessed_token", "owned-value", scope}, {"alpha_token", "owned-value", credentialset.NewScope()}} {
		r, ev := set.VerifyComponents(ctx, "alpha", tc.name, tc.value, components, tc.scope, false)
		if r.Status != Errored || ev != nil {
			t.Fatal("invented primary or foreign scope got a verdict")
		}
	}
}

func TestCrossFileCompanionConflictDoesNotProbe(t *testing.T) {
	ctx := context.Background()
	client := &http.Client{Transport: verifierRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("ambiguous components reached provider")
		return nil, nil
	})}
	set := mockSet(t, client, &Verifier{ID: "alpha", Match: []string{"alpha"}, Extract: map[string]string{"account": `tenant_[ab]`}, Requests: []Request{{URL: "https://owned.invalid/"}}})
	for _, mode := range []string{"unsealed", "incomplete", "conflict", "partial-literal", "closed"} {
		t.Run(mode, func(t *testing.T) {
			components, err := credentialset.New(credentialset.Limits{Observations: 10, Bytes: 4096})
			if err != nil {
				t.Fatal(err)
			}
			defer components.Close()
			scope := credentialset.NewScope()
			parts := []struct{ n, v string }{{"alpha_token", "owned-value"}, {"account", "tenant_a"}}
			if mode == "conflict" {
				parts = append(parts, struct{ n, v string }{"Account", "tenant_b"})
			}
			if mode == "partial-literal" {
				parts[1].v = "prefix tenant_a suffix"
			}
			for _, p := range parts {
				if err := components.Observe(ctx, scope, p.n, p.v, "opaque"); err != nil {
					t.Fatal(err)
				}
			}
			if mode != "unsealed" {
				err := components.Seal(ctx, mode != "incomplete")
				if err != nil && mode != "incomplete" {
					t.Fatal(err)
				}
			}
			if mode == "closed" {
				components.Close()
			}
			r, evidence := set.VerifyComponents(ctx, "alpha", "alpha_token", "owned-value", components, scope, false)
			if r.Status != Errored || evidence != nil || r.Note != "cross-file companion binding is missing, ambiguous or invalid" {
				t.Fatal("unsafe inventory got a verdict or exposed raw diagnostics")
			}
		})
	}
}

func TestCrossFileAWSPairFromEitherTypedPrimary(t *testing.T) {
	ctx := context.Background()
	const key = "AKIANAFGYOEYPXU1DSYP"
	secret := strings.Repeat("Q7z/", 10)
	client := &http.Client{Transport: verifierRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if !strings.Contains(r.Header.Get("Authorization"), "Credential="+key+"/") || strings.Contains(r.Header.Get("Authorization"), secret) {
			t.Fatal("AWS signer did not receive the exact observed pair")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	set := mockSet(t, client, &Verifier{ID: "aws", Match: []string{"aws"}, Sign: "awsv4", SignParams: map[string]string{"service": "sts", "region": "us-east-1"}, Extract: map[string]string{"aws_access_key_id": `(?:AKIA|ASIA)[0-9A-Z]{16}`, "aws_secret_access_key": `[A-Za-z0-9/+]{40}`}, Requests: []Request{{Method: "POST", URL: "https://owned.invalid/", Body: "Action=GetCallerIdentity&Version=2011-06-15"}}})
	components, err := credentialset.New(credentialset.Limits{Observations: 10, Bytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer components.Close()
	scope := credentialset.NewScope()
	for _, part := range []struct{ name, value string }{{"accessKeyId", key}, {"secretAccessKey", secret}} {
		if err := components.Observe(ctx, scope, part.name, part.value, "opaque-"+part.name); err != nil {
			t.Fatal(err)
		}
	}
	if err := components.Seal(ctx, true); err != nil {
		t.Fatal(err)
	}
	for _, primary := range []struct{ typ, name, value string }{{"aws_access_key_id", "accessKeyId", key}, {"aws_secret_access_key", "secretAccessKey", secret}} {
		r, evidence := set.VerifyComponents(ctx, primary.typ, primary.name, primary.value, components, scope, false)
		if r.Status != Verified || evidence == nil || len(evidence.Primary) != 1 || len(evidence.Fields) != 2 {
			t.Fatal("AWS pair resolution failed")
		}
	}
}
