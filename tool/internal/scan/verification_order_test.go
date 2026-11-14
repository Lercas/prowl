package scan

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"github.com/Lercas/prowl/tool/internal/verify"
)

type orderScorer struct {
	fixedMLScorer
	before func()
}

func (s orderScorer) Score(ctx context.Context, rows []mlscore.Record) ([]mlscore.Result, error) {
	s.before()
	return s.fixedMLScorer.Score(ctx, rows)
}

func orderVerifier(t *testing.T, endpoint, extra string) *verify.Set {
	t.Helper()
	path := filepath.Join(t.TempDir(), "owned.yaml")
	rule := "id: owned\nmatch: [aws_access_key_id]\n" + extra + "requests:\n  - url: " + endpoint + "\n    headers:\n      Authorization: 'Bearer {{secret}}'\n      X-Account: '{{account}}'\n    matchers:\n      - type: status\n        status: [200]\n"
	// account is optional only when the fixture does not declare companion extraction.
	if extra == "" {
		rule = "id: owned\nmatch: [aws_access_key_id]\nrequests:\n  - url: " + endpoint + "\n    headers:\n      Authorization: 'Bearer {{secret}}'\n    matchers:\n      - type: status\n        status: [200]\n"
	}
	if err := os.WriteFile(path, []byte(rule), 0600); err != nil {
		t.Fatal(err)
	}
	set, err := verify.Load(time.Second, path)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func allowOrderFixture(t *testing.T) {
	t.Helper()
	before := safehttp.AllowPrivate.Load()
	safehttp.AllowPrivate.Store(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(before) })
}

func TestVerificationOrderingDefaultAllAndIndex(t *testing.T) {
	allowOrderFixture(t)
	for _, c := range []struct {
		name                                            string
		all, index                                      bool
		score                                           float64
		response, before, total, findings, observations int
	}{
		{"default-filtered", false, false, 0, 200, 0, 0, 0, 0},
		{"default-kept", false, false, 1, 200, 0, 1, 1, 0},
		{"all-rescues-live", true, false, 0, 200, 1, 1, 1, 0},
		{"all-drops-rejected", true, false, 0, 401, 1, 1, 0, 0},
		{"index-retains-rejection", false, true, 0, 401, 1, 1, 0, 1},
		{"invalid-ml-fails-open", false, false, math.NaN(), 200, 0, 1, 1, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(c.response) }))
			defer srv.Close()
			var observations []model.Finding
			scored := false
			opts := Options{Detector: detector(t), Verifiers: orderVerifier(t, srv.URL, ""), VerifyAll: c.all, ML: orderScorer{fixedMLScorer: fixedMLScorer{results: []mlscore.Result{{Score: c.score}}, threshold: .3}, before: func() {
				scored = true
				if int(calls.Load()) != c.before {
					t.Error("provider ran on the wrong side of ML")
				}
			}}}
			if c.index {
				opts.ValueFingerprint = func(string) string { return "keyed" }
				opts.ObserveVerification = func(f model.Finding) { observations = append(observations, f) }
			}
			fs := New(opts).Findings(t.Context(), model.Item{Source: "code", Path: "prod.env", Text: "AWS=AKIANAFGYOEYPXU1DSYP"})
			if !scored || int(calls.Load()) != c.total || len(fs) != c.findings || len(observations) != c.observations {
				t.Fatal("verification order changed retention or index evidence")
			}
			if c.index && (observations[0].Verified == nil || *observations[0].Verified || observations[0].Redacted != "") {
				t.Fatal("index lost sanitized provider rejection")
			}
		})
	}
}

func TestPostMLVerificationKeepsOriginalStructuredCompanion(t *testing.T) {
	allowOrderFixture(t)
	for _, c := range []struct{ path, text string }{
		{"prod.json", `{"first":{"account":"tenant_a","key":"` + escapedJSON("AKIANAFGYOEYPXU1DSYP") + `"},"second":{"account":"tenant_b","key":"` + escapedJSON("AKIANAFGYOEYPXU1DSYP") + `"}}`},
		{"prod.yaml", "one: {account: tenant_a, key: AKIANAFGYOEYPXU1DSYP}\ntwo: {account: tenant_b, key: AKIANAFGYOEYPXU1DSYP}\n"},
		{"prod.toml", "[one]\naccount='tenant_a'\nkey='AKIANAFGYOEYPXU1DSYP'\n[two]\naccount='tenant_b'\nkey='AKIANAFGYOEYPXU1DSYP'\n"},
	} {
		t.Run(c.path, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("X-Account") != "tenant_b" {
					t.Error("post-ML candidate used another object's companion")
				}
				w.WriteHeader(200)
			}))
			defer srv.Close()
			set := orderVerifier(t, srv.URL, "extract:\n  account: 'tenant_[ab]'\n")
			fs := New(Options{Detector: detector(t), Verifiers: set, ML: fixedMLScorer{results: []mlscore.Result{{Score: 0}, {Score: 1}}, threshold: .3}}).Findings(t.Context(), model.Item{Source: "code", Path: c.path, Text: c.text})
			if calls.Load() != 1 || len(fs) != 1 || fs[0].Verified == nil || !*fs[0].Verified || len(fs[0].Evidence) == 0 {
				t.Fatal("source mapping or ML compaction lost the verification candidate")
			}
		})
	}
}

func TestMLSelectionTracksStructurallyExemptCandidate(t *testing.T) {
	fs, indices := mlFilterSelected(t.Context(), fixedMLScorer{results: []mlscore.Result{{Score: 0}, {Score: 0}, {Score: 1}}, threshold: .3}, []model.Finding{{Type: "owned"}, {Type: "private_key_pem"}, {Type: "owned"}}, make([]mlscore.Record, 3))
	if len(fs) != 2 || len(indices) != 2 || indices[0] != 1 || indices[1] != 2 {
		t.Fatal("ML source selection dropped or misindexed a protected candidate")
	}
}

func TestVerificationUsesWinningRuleCandidateOnly(t *testing.T) {
	allowOrderFixture(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/template" {
			t.Error("discarded builtin candidate reached the provider")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	rulePath := filepath.Join(t.TempDir(), "owned.yaml")
	definition := "id: owned-template\ninfo:\n  name: Owned fixture\n  severity: critical\nmatchers:\n  - type: regex\n    regex: ['AKIA[A-Z0-9]{16}']\n"
	if err := os.WriteFile(rulePath, []byte(definition), 0600); err != nil {
		t.Fatal(err)
	}
	engine, err := rules.Load(rulePath)
	if err != nil {
		t.Fatal(err)
	}
	verifierDir := t.TempDir()
	for _, c := range []struct{ file, match, endpoint string }{{"builtin.yaml", "aws_access_key_id", "builtin"}, {"template.yaml", "owned-template", "template"}} {
		body := "id: " + c.endpoint + "\nmatch: [" + c.match + "]\nrequests:\n  - url: " + srv.URL + "/" + c.endpoint + "\n    matchers:\n      - type: status\n        status: [200]\n"
		if err := os.WriteFile(filepath.Join(verifierDir, c.file), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, all := range []bool{false, true} {
		before := calls.Load()
		// Each mode gets its own cache, making the provider-call assertion meaningful.
		set, err := verify.Load(time.Second, verifierDir)
		if err != nil {
			t.Fatal(err)
		}
		fs := New(Options{Detector: detector(t), Rules: engine, Verifiers: set, VerifyAll: all, ML: fixedMLScorer{results: []mlscore.Result{{Score: 1}}, threshold: .3}}).Findings(t.Context(), model.Item{Path: "prod.env", Text: "AWS=AKIANAFGYOEYPXU1DSYP"})
		if calls.Load()-before != 1 || len(fs) != 1 || fs[0].Type != "owned-template" || fs[0].Verification == nil || fs[0].Verification.Verifier != "template" {
			t.Fatal("rule replacement lost its parallel verification candidate")
		}
	}
}
