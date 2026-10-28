package scan

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"github.com/Lercas/prowl/tool/internal/verify"
)

type rejectingScorer struct{}

func (rejectingScorer) Threshold() float64 { return .5 }
func (rejectingScorer) Local() bool        { return true }
func (rejectingScorer) Score(_ context.Context, rs []mlscore.Record) ([]mlscore.Result, error) {
	return make([]mlscore.Result, len(rs)), nil
}

func TestMLSuppressionCannotCertifyCredentialAbsence(t *testing.T) {
	cov := model.NewCoverage()
	ctx := model.WithCoverage(context.Background(), cov)
	item := model.Item{Text: "AWS_KEY=\x41KIANAFGYOEYPXU1DSYP", Source: "code", Path: "config.env"}
	if fs := Findings(ctx, detector(t), nil, nil, item, nil, rejectingScorer{}); len(fs) != 0 {
		t.Fatal("test scorer did not suppress the candidate")
	}
	r := model.NewResult(nil, cov)
	if !r.Complete || !r.Filtered {
		t.Fatal("ML suppression could be mistaken for an absent credential")
	}
}

func TestLiveVerificationSurvivesMLWithOrganizationIdentity(t *testing.T) {
	const raw = "\x73k_live_Q5t7U9i2O4p6A8s0D3f5G7h9"
	previous := safehttp.AllowPrivate.Load()
	safehttp.AllowPrivate.Store(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(previous) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+raw {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	p := filepath.Join(t.TempDir(), "stripe.yaml")
	yaml := "id: stripe\nmatch: [stripe]\nrequests:\n  - method: GET\n    url: " + srv.URL + "\n    headers:\n      Authorization: 'Bearer {{secret}}'\n    matchers:\n      - type: status\n        status: [200]\n"
	if err := os.WriteFile(p, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	vset, err := verify.Load(time.Second, p)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithOptions(context.Background(), Options{VerifyAll: true, IdentityKey: []byte(strings.Repeat("k", 32))})
	fs := Findings(ctx, detector(t), nil, vset, model.Item{Text: "STRIPE_KEY = '" + raw + "'", Source: "code", Path: "production.env"}, nil, rejectingScorer{})
	for _, f := range fs {
		if f.Type == "stripe_secret" || strings.Contains(f.Type, "stripe") {
			if f.SecretID == "" || f.Verified == nil || !*f.Verified || f.Verification.Status != "verified" {
				t.Fatalf("live credential lost or verified using incorrect raw value: %+v", f)
			}
			return
		}
	}
	t.Fatal("ML suppressed a verified credential")
}

func TestDecodedVerificationUsesEachOriginalBlobContext(t *testing.T) {
	const raw = "\x73k_live_Q5t7U9i2O4p6A8s0D3f5G7h9"
	previous := safehttp.AllowPrivate.Load()
	safehttp.AllowPrivate.Store(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(previous) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+raw && r.Header.Get("X-Account") == "account-A" {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(401)
		}
	}))
	defer srv.Close()
	p := filepath.Join(t.TempDir(), "stripe.yaml")
	definition := "id: stripe\nmatch: [stripe]\nextract:\n  account: 'account-[AB]'\nrequests:\n  - method: GET\n    url: " + srv.URL + "\n    headers:\n      Authorization: 'Bearer {{secret}}'\n      X-Account: '{{account}}'\n    matchers:\n      - type: status\n        status: [200]\n"
	if err := os.WriteFile(p, []byte(definition), 0600); err != nil {
		t.Fatal(err)
	}
	vset, err := verify.Load(time.Second, p)
	if err != nil {
		t.Fatal(err)
	}
	a := base64.StdEncoding.EncodeToString([]byte("account-A\ntoken=" + raw))
	b := base64.StdEncoding.EncodeToString([]byte("account-B\ntoken=" + raw))
	text := `first="` + a + `"` + "\n" + `second="` + b + `"`
	for _, text := range []string{text, `payload="` + base64.StdEncoding.EncodeToString([]byte(text)) + `"`} {
		fs := Findings(context.Background(), detector(t), nil, vset, model.Item{Path: "payload.env", Text: text, Source: "code"}, nil, nil)
		if len(fs) != 2 || fs[0].Verified == nil || !*fs[0].Verified || fs[1].Verified == nil || *fs[1].Verified {
			t.Fatal("decoded occurrences shared or lost companion context during loopback verification")
		}
	}
}

func TestStructuredVerificationUsesCanonicalValueAndImmediateObject(t *testing.T) {
	const raw = "\x73k_live_Q5t7U9i2O4p6A8s0D3f5G7h9"
	previous := safehttp.AllowPrivate.Load()
	safehttp.AllowPrivate.Store(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(previous) })
	requests := []string{}
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Header.Get("Authorization")+"/"+r.Header.Get("X-Account"))
		mu.Unlock()
		if r.Header.Get("Authorization") == "Bearer "+raw && r.Header.Get("X-Account") == "account-A" {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(401)
		}
	}))
	defer srv.Close()
	p := filepath.Join(t.TempDir(), "stripe.yaml")
	definition := "id: stripe\nmatch: [stripe]\nextract:\n  account: 'account-[AB]'\nrequests:\n  - method: GET\n    url: " + srv.URL + "\n    headers:\n      Authorization: 'Bearer {{secret}}'\n      X-Account: '{{account}}'\n    matchers:\n      - type: status\n        status: [200]\n"
	if err := os.WriteFile(p, []byte(definition), 0600); err != nil {
		t.Fatal(err)
	}
	text := `[{"account":"account-A","token":"` + escapedJSON(raw) + `"},{"account":"account-B","token":"` + escapedJSON(raw) + `"}]`
	ctx := WithOptions(context.Background(), Options{VerifyAll: true})
	for _, item := range []model.Item{
		{Path: "production.json", Text: text, Source: "code"},
		{Path: "production.json", Text: strings.ReplaceAll(text, escapedJSON(raw), raw), Source: "code"},
		{Path: "production.toml", Text: "[first]\naccount='account-A'\ntoken=\"" + escapedJSON(raw) + "\"\n[second]\naccount='account-B'\ntoken=\"" + escapedJSON(raw) + "\"", Source: "code"},
		{Path: "production.toml", Text: "[[accounts]]\naccount='account-A'\ntoken=\"" + escapedJSON(raw) + "\"\n[[accounts]]\naccount='account-B'\ntoken=\"" + escapedJSON(raw) + "\"", Source: "code"},
		{Path: "production.yaml", Text: "first: {account: account-A, token: \"" + escapedJSON(raw) + "\"}\nsecond: {account: account-B, token: \"" + escapedJSON(raw) + "\"}\n", Source: "code"},
		{Path: "production.yaml", Text: "definition: &a {account: account-A, token: " + raw + "}\nsecond: {<<: *a, account: account-B}\n", Source: "code"},
		{Path: "production.yaml", Text: "first: {account: account-A, token: &a " + raw + "}\nsecond: {account: account-B, token: *a}\n", Source: "code"},
		{Path: "production.yaml", Text: "first: {account: account-A, token: &a !!binary '" + base64.StdEncoding.EncodeToString([]byte(raw)) + "'}\nsecond: {account: account-B, token: *a}\n", Source: "code"},
	} {
		vset, err := verify.Load(time.Second, p)
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		requests = nil
		mu.Unlock()
		fs := Findings(ctx, detector(t), nil, vset, item, nil, nil)
		mu.Lock()
		ok := len(fs) == 2 && fs[0].Verified != nil && *fs[0].Verified && fs[1].Verified != nil && !*fs[1].Verified && len(requests) == 2 && requests[0] == "Bearer "+raw+"/account-A" && requests[1] == "Bearer "+raw+"/account-B"
		mu.Unlock()
		if !ok {
			t.Fatalf("structured occurrences mixed companion fields, lost canonical values or verified extra candidates: %s", item.Path)
		}
	}
	// A credential-shaped alias name and its canonical use cannot enter ML/verification twice.
	// Otherwise the name can borrow account-A and survive as LIVE after the real account-B use
	// is rejected by ML, even if a later source-span deduplicator would normally merge them.
	vset, err := verify.Load(time.Second, p)
	if err != nil {
		t.Fatal(err)
	}
	item := model.Item{Path: "production.yaml", Source: "code", Text: "first: {account: account-A, token: &" + raw + " " + raw + "}\nsecond: {account: account-B, token: *" + raw + "}\n"}
	mu.Lock()
	requests = nil
	mu.Unlock()
	fs := Findings(ctx, detector(t), nil, vset, item, nil, rejectingScorer{})
	mu.Lock()
	requestCount := len(requests)
	mu.Unlock()
	if len(fs) != 1 || requestCount != 2 {
		t.Fatalf("alias presentation entered verification/ML as an extra credential use: findings=%+v requests=%d", fs, requestCount)
	}
	for _, f := range fs {
		if strings.HasPrefix(item.Text[f.ByteStart:f.ByteEnd], "*") || f.ByteStart > strings.Index(item.Text, "second:") {
			t.Fatal("rejected YAML alias became LIVE through its presentation spelling")
		}
	}
	vset, err = verify.Load(time.Second, p)
	if err != nil {
		t.Fatal(err)
	}
	item.Text = "value: &token " + raw + "\ndefinition: &a\n  first: {account: account-A, token: *token}\n  second: {account: account-B, token: *token}\ncopy: *a\n"
	ctx = WithOptions(context.Background(), Options{VerifyAll: true, IdentityKey: []byte(strings.Repeat("k", 32))})
	fs = Findings(ctx, detector(t), nil, vset, item, nil, nil)
	if len(fs) != 5 {
		t.Fatal("shared alias reference collapsed distinct account-scoped occurrences")
	}
	copies, live, dead := map[string]bool{}, 0, 0
	for _, f := range fs {
		if item.Text[f.ByteStart:f.ByteEnd] != "*a" {
			continue
		}
		copies[f.OccurrenceID] = true
		if f.Verified != nil && *f.Verified {
			live++
		} else if f.Verified != nil {
			dead++
		}
	}
	if len(copies) != 2 || live != 1 || dead != 1 {
		t.Fatal("alias proof paths lost identity or their individual verification verdicts")
	}
}
