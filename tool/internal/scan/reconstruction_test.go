package scan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"github.com/Lercas/prowl/tool/internal/secretindex"
	"github.com/Lercas/prowl/tool/internal/verify"
)

func TestReconstructionPipelineSourceIdentityAndPrivacy(t *testing.T) {
	const key = "AKIANAFGYOEYPXU1DSYP"
	id, err := secretindex.LoadIdentity(filepath.Join(t.TempDir(), "index"), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"bundle.js", "bundle.tsx", "https://user:private-password@example.invalid/bundle.js?key=private-query"} {
		text := "const head='AKIA';\n/*🚀*/ const first=head+'NAFGYOEYPXU1DSYP';\nconst second=head+'NAFGYOEYPXU1DSYP';"
		scorer := &tableRecordScorer{}
		it := model.Item{Text: text, Source: "code", Path: path}
		fs := New(Options{Detector: detector(t), Reconstruct: true, RevealSecrets: true, ML: scorer, ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location}).Findings(t.Context(), it)
		count := 0
		locations := map[string]bool{}
		for _, f := range fs {
			if f.Type != "aws_access_key_id" {
				continue
			}
			count++
			if !strings.HasPrefix(f.Stage, "reconstructed/") || len(f.Evidence) < 2 || f.Context != nil || f.ValueFingerprint != id.Fingerprint(key) || f.Fingerprint != model.ComputeFingerprint(f.Type, path, key) {
				t.Fatalf("reconstruction lost identity or original evidence: stage=%s evidence=%d context=%t value_identity=%t fingerprint=%t", f.Stage, len(f.Evidence), f.Context != nil, f.ValueFingerprint == id.Fingerprint(key), f.Fingerprint == model.ComputeFingerprint(f.Type, path, key))
			}
			if f.Line != 2 && f.Line != 3 || text[f.ByteStart:f.ByteEnd] != "head+'NAFGYOEYPXU1DSYP'" || f.UTF16Col != newLineIndex(text).utf16Col(f.ByteStart) {
				t.Fatal("reconstruction reports synthetic coordinates")
			}
			locations[f.IndexLocationID] = true
		}
		if count != 2 || len(locations) != 2 || len(scorer.records) != 2 {
			t.Fatal("distinct expressions were collapsed or ML was bypassed")
		}
		for _, record := range scorer.records {
			if record.Value != key {
				t.Fatal("ML received source spelling")
			}
		}
		masked := New(Options{Detector: detector(t), Reconstruct: true}).Findings(t.Context(), it)
		encoded, _ := json.Marshal(masked)
		for _, hidden := range []string{key, "private-password", "private-query"} {
			if strings.Contains(string(encoded), hidden) {
				t.Fatal("reconstructed report leaked private data")
			}
		}
	}
}

func TestReconstructionOptInPragmasAndCoverage(t *testing.T) {
	text := "const head='AKIA';\nconst key=head+'NAFGYOEYPXU1DSYP'; // prowl:allow"
	for _, c := range []struct {
		enabled, ignore bool
		want            int
	}{{false, false, 0}, {true, false, 0}, {true, true, 1}} {
		coverage := model.NewCoverage()
		ctx := model.WithCoverage(t.Context(), coverage)
		fs := New(Options{Detector: detector(t), Reconstruct: c.enabled, IgnorePragmas: c.ignore}).Findings(ctx, model.Item{Path: "bundle.js", Text: text})
		if len(fs) != c.want {
			t.Fatal("opt-in or untrusted pragma policy changed")
		}
		if c.enabled && !c.ignore && !model.NewResult(fs, coverage).Filtered {
			t.Fatal("suppression is missing from coverage")
		}
	}
	for _, path := range []string{"bundle.txt", "bundle.json"} {
		for _, f := range New(Options{Detector: detector(t), Reconstruct: true}).Findings(t.Context(), model.Item{Path: path, Text: strings.Split(text, " //")[0]}) {
			if strings.HasPrefix(f.Stage, "reconstructed/") {
				t.Fatal("non-JS source reconstructed")
			}
		}
	}
	coverage := model.NewCoverage()
	fs := New(Options{Detector: detector(t), Reconstruct: true}).Findings(model.WithCoverage(t.Context(), coverage), model.Item{Path: "huge.js", Text: strings.Repeat(" ", (1<<20)+1)})
	complete, _, _ := coverage.Snapshot()
	if complete || len(fs) == 0 || !model.IsIncompleteFinding(fs[len(fs)-1]) {
		t.Fatal("reconstruction limit looks complete")
	}
}

func TestReconstructionObserverUsesSourceBeforeML(t *testing.T) {
	previous := safehttp.AllowPrivate.Load()
	safehttp.AllowPrivate.Store(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(previous) })
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Account") != "tenant_a" {
			t.Error("verification lost the original source context")
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer api.Close()
	path := filepath.Join(t.TempDir(), "owned.yaml")
	if err := os.WriteFile(path, []byte("id: owned-check\nmatch: [aws_access_key_id]\nextract:\n  account: 'tenant_a'\nrequests:\n  - url: "+api.URL+"\n    headers:\n      X-Account: '{{account}}'\n    matchers:\n      - type: status\n        status: [200]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	set, err := verify.Load(time.Second, path)
	if err != nil {
		t.Fatal(err)
	}
	var observations []model.Finding
	text := "const account='tenant_a';\nconst head='AKIA';\nconst key=head+'NAFGYOEYPXU1DSYP';"
	location := func(source, path string, line, col int) string {
		return fmt.Sprintf("%s:%s:%d:%d", source, path, line, col)
	}
	fs := New(Options{Detector: detector(t), Reconstruct: true, Verifiers: set, ML: fixedMLScorer{results: []mlscore.Result{{Score: 0}}, threshold: .3}, ValueFingerprint: func(string) string { return "keyed" }, LocationFingerprint: location, ObserveVerification: func(f model.Finding) { observations = append(observations, f) }}).Findings(t.Context(), model.Item{Source: "code", Path: "bundle.js", Text: text})
	if len(fs) != 0 || len(observations) != 1 || observations[0].Line != 3 || observations[0].IndexLocationID != location("code", "bundle.js", 3, 11) || observations[0].Verified == nil || *observations[0].Verified {
		t.Fatal("observer lost rejected reconstructed value or recorded synthetic coordinates")
	}
}

func TestReconstructionBudgetIsSharedBeforeML(t *testing.T) {
	coverage := model.NewCoverage()
	text := "const head='AKIA';\nconst first=head+'NAFGYOEYPXU1DSYP';\nconst second=head+'NAFGYOEYPXU1DSYP';"
	scorer := &tableRecordScorer{}
	p := New(Options{Detector: detector(t), Reconstruct: true, ML: scorer, matchLimit: 1})
	fs := p.Findings(model.WithCoverage(t.Context(), coverage), model.Item{Path: "bundle.js", Text: text})
	complete, _, _ := coverage.Snapshot()
	if len(scorer.records) != 1 || complete || len(fs) != 2 || !model.IsIncompleteFinding(fs[1]) {
		t.Fatal("reconstructed expressions bypass the shared candidate budget")
	}
	p.options.ML = fixedMLScorer{results: []mlscore.Result{{Score: 0}}, threshold: .3}
	coverage = model.NewCoverage()
	fs = p.Findings(model.WithCoverage(t.Context(), coverage), model.Item{Path: "bundle.js", Text: text})
	complete, _, _ = coverage.Snapshot()
	if complete || len(fs) != 1 || !model.IsIncompleteFinding(fs[0]) {
		t.Fatal("ML suppression replenished the shared candidate budget")
	}
}
