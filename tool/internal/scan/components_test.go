package scan

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/credentialset"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
)

func componentItems(scope *credentialset.Scope, format string) []model.Item {
	a, b := `{"accessKeyId":"AKIANAFGYOEYPXU1DSYP"}`, `{"account":"tenant_a","timeout":30}`
	switch format {
	case ".toml":
		a, b = `accessKeyId="AKIANAFGYOEYPXU1DSYP"`, "account=\"tenant_a\"\ntimeout=30\n"
	case ".yaml":
		a, b = "accessKeyId: AKIANAFGYOEYPXU1DSYP\n", "account: tenant_a\ntimeout: 30\n"
	case ".env":
		a, b = "export accessKeyId='AKIANAFGYOEYPXU1DSYP'\r\n", "account=\"tenant_a\" # owned\r\n# ordinary comment\r\n"
	}
	return []model.Item{{Source: "code", Path: "prod-key" + format, Text: a, CredentialScope: scope}, {Source: "code", Path: "prod-account" + format, Text: b, CredentialScope: scope}}
}

func runComponentItems(t *testing.T, opts Options, items []model.Item) ([]model.Finding, *model.Coverage) {
	t.Helper()
	coverage := model.NewCoverage()
	input := make(chan model.Item, len(items))
	for _, it := range items {
		input <- it
	}
	close(input)
	return New(opts).Run(model.WithCoverage(t.Context(), coverage), input), coverage
}

func TestCrossFileRunUsesCompleteOriginalConfigurationInventory(t *testing.T) {
	allowOrderFixture(t)
	for _, format := range []string{".json", ".toml", ".yaml", ".env"} {
		t.Run(format, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("Authorization") != "Bearer AKIANAFGYOEYPXU1DSYP" || r.Header.Get("X-Account") != "tenant_a" {
					t.Error("provider received invented components")
				}
				w.WriteHeader(200)
			}))
			defer srv.Close()
			opts := Options{Detector: detector(t), Verifiers: orderVerifier(t, srv.URL, "extract:\n  account: 'tenant_[ab]'\n"), CrossFile: true, Workers: 2}
			fs, coverage := runComponentItems(t, opts, componentItems(credentialset.NewScope(), format))
			complete, _, _ := coverage.Snapshot()
			if !complete || calls.Load() != 1 {
				t.Fatal("complete components were not verified", calls.Load(), fs)
			}
			found := false
			for _, f := range fs {
				if f.Type == "aws_access_key_id" {
					found = true
					if f.Verified == nil || !*f.Verified || f.Verification == nil || f.Verification.Components == nil || len(f.Verification.Components.Primary) != 1 || len(f.Verification.Components.Fields["account"]) != 1 {
						t.Fatal("component evidence or verdict lost", f.Type)
					}
					for _, id := range append(f.Verification.Components.Primary, f.Verification.Components.Fields["account"]...) {
						if !strings.HasPrefix(id, "hmac-component-location:v1:") {
							t.Fatal("unkeyed evidence location")
						}
					}
				}
			}
			if !found {
				t.Fatal("typed primary disappeared")
			}
		})
	}
}

func TestCrossFileInvalidOrForeignComponentsNeverProbe(t *testing.T) {
	allowOrderFixture(t)
	for _, mode := range []string{"foreign-root", "missing-scope", "source-error", "ambiguous", "unknown-role", "empty-role", "nested", "duplicate", "interpolation", "derived-jwt"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(200) }))
			defer srv.Close()
			items := componentItems(credentialset.NewScope(), ".json")
			switch mode {
			case "foreign-root":
				items[1].CredentialScope = credentialset.NewScope()
			case "missing-scope":
				items[0].CredentialScope = nil
			case "source-error":
				items = append(items, model.Item{Path: "unreadable", Error: errors.New("source failure")})
			case "ambiguous":
				items = append(items, model.Item{Source: "code", Path: "other.json", Text: `{"Account":"tenant_b"}`, CredentialScope: items[0].CredentialScope})
			case "unknown-role":
				items = append(items, model.Item{Source: "code", Path: "other.json", Text: `{"Account":false}`, CredentialScope: items[0].CredentialScope})
			case "empty-role":
				items = append(items, model.Item{Source: "code", Path: "other.json", Text: `{"Account":""}`, CredentialScope: items[0].CredentialScope})
			case "nested":
				items[1].Text = `{"nested":{"account":"tenant_a"}}`
			case "duplicate":
				items[1].Text = `{"account":"tenant_b","account":"tenant_a"}`
			case "interpolation":
				items[1].Path = "prod.env"
				items[1].Text = "account=${OTHER}\n"
			case "derived-jwt":
				items[0].Text = `{"token":"eyJhbGciOiJub25lIn0.eyJhd3NfYWNjZXNzX2tleV9pZCI6IkFLSUFOQUZHWU9FWVBYVTFEU1lQIn0."}`
			}
			fs, coverage := runComponentItems(t, Options{Detector: detector(t), Verifiers: orderVerifier(t, srv.URL, "extract:\n  account: 'tenant_[ab]'\n"), CrossFile: true}, items)
			complete, _, _ := coverage.Snapshot()
			if calls.Load() != 0 {
				t.Fatal("unsafe component set reached provider")
			}
			if complete && !hasIncompleteFinding(fs) {
				t.Fatal("missing or ambiguous required components appeared complete")
			}
		})
	}
}

func TestCrossFileWaitsForDrainAndKeepsRunStatePrivate(t *testing.T) {
	allowOrderFixture(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer srv.Close()
	p := New(Options{Detector: detector(t), Verifiers: orderVerifier(t, srv.URL, "extract:\n  account: 'tenant_[ab]'\n"), CrossFile: true})
	items := componentItems(credentialset.NewScope(), ".json")
	in := make(chan model.Item, 2)
	for _, it := range items {
		in <- it
	}
	done := make(chan []model.Finding, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { done <- p.Run(ctx, in) }()
	select {
	case <-done:
		t.Fatal("run completed before source drain")
	case <-time.After(50 * time.Millisecond):
	}
	if calls.Load() != 0 {
		t.Fatal("provider ran before source drain")
	}
	close(in)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("closed source did not complete")
	}
	if calls.Load() != 1 {
		t.Fatal("complete source was not checked")
	}
	_, _ = runComponentItems(t, p.options, items[:1])
	if calls.Load() != 1 {
		t.Fatal("later run borrowed retained plaintext")
	}
	if fs := p.Findings(t.Context(), items[0]); !hasIncompleteFinding(fs) {
		t.Fatal("single-item API certified a cross-file stream")
	}
}

func TestCrossFileIntakeLimitsStayIncomplete(t *testing.T) {
	allowOrderFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("incomplete intake reached provider") }))
	defer srv.Close()
	for _, mode := range []string{"items", "bytes"} {
		t.Run(mode, func(t *testing.T) {
			items := make([]model.Item, componentMaxItems+1)
			if mode == "bytes" {
				items = []model.Item{{Source: "code", Path: "large.txt", Text: strings.Repeat("x", componentMaxBytes+1)}}
			}
			fs, _ := runComponentItems(t, Options{Detector: detector(t), Verifiers: orderVerifier(t, srv.URL, "extract:\n  account: 'tenant_[ab]'\n"), CrossFile: true}, items)
			if !hasIncompleteFinding(fs) {
				t.Fatal("intake limit appeared complete")
			}
		})
	}
}

func TestCrossFilePreservesMLOrderingAndPrivateIndexObservation(t *testing.T) {
	allowOrderFixture(t)
	for _, mode := range []struct {
		name                    string
		all, index              bool
		score                   float64
		before, total, findings int
	}{
		{"post-ml-filtered", false, false, 0, 0, 0, 0},
		{"post-ml-kept", false, false, 1, 0, 1, 1},
		{"verify-all-rescues", true, false, 0, 1, 1, 1},
		{"index-before-ml", false, true, 0, 1, 1, 1},
	} {
		t.Run(mode.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(200) }))
			defer srv.Close()
			scored, observed := false, 0
			opts := Options{Detector: detector(t), Verifiers: orderVerifier(t, srv.URL, "extract:\n  account: 'tenant_[ab]'\n"), CrossFile: true, VerifyAll: mode.all, Workers: 1,
				ML: orderScorer{fixedMLScorer: fixedMLScorer{results: []mlscore.Result{{Score: mode.score}}, threshold: .3}, before: func() {
					scored = true
					if int(calls.Load()) != mode.before {
						t.Error("provider ran on wrong side of ML")
					}
				}}}
			if mode.index {
				opts.ValueFingerprint = func(string) string { return "keyed" }
				opts.ObserveVerification = func(f model.Finding) {
					observed++
					if f.Redacted != "" || f.Context != nil || f.Verification != nil || f.Verified == nil {
						t.Error("index observer received plaintext/context or lost verdict")
					}
				}
			}
			fs, coverage := runComponentItems(t, opts, componentItems(credentialset.NewScope(), ".json"))
			complete, _, _ := coverage.Snapshot()
			if !complete || !scored || int(calls.Load()) != mode.total || len(fs) != mode.findings {
				t.Fatal("cross-file ML retention/order changed")
			}
			if mode.index && observed != 1 {
				t.Fatal("private index observation was lost")
			}
		})
	}
}
