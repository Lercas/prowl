package scan

import (
	"github.com/Lercas/prowl/tool/internal/correlation"
	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/model"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPipelineTuningIsIndependentOfLaterLegacyChanges(t *testing.T) {
	defer detect.ApplyTuning(3.5, 4.2, 50000)
	detect.ApplyTuning(2, 4.2, 50000)
	first := New(Options{Detector: detector(t)})
	detect.ApplyTuning(7.5, 4.2, 50000)
	second := New(Options{Detector: detector(t)})
	text := `The secret is "Xk9Zm2Qp7Lr4Ns8Tv1Wy6Bd3Fg5Hj0aQw"`
	count := func(p *Pipeline) int {
		n := 0
		for _, f := range p.Findings(t.Context(), model.Item{Source: "code", Path: "owned.env", Text: text}) {
			if f.Type == "generic_high_entropy" {
				n++
			}
		}
		return n
	}
	if count(first) == 0 || count(second) != 0 {
		t.Fatal("a later tuning update changed an existing pipeline", count(first), count(second))
	}
}

func TestVerificationUsesCandidateTuning(t *testing.T) {
	allowOrderFixture(t)
	defer detect.ApplyTuning(3.5, 4.2, 50000)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer server.Close()
	value := "sampleXk9Zm2Qp7Lr4Ns8Tv1Wy6Bd3Fg5Hj0aQw"
	for _, mode := range []string{"plain", "decoded", "jwt", "unbound", "structured"} {
		for _, threshold := range []float64{4.2, 8} {
			settings := detect.DefaultTuning().With(0, threshold, 0)
			// Change the legacy value to the opposite verdict before verification.
			legacyThreshold := 4.2
			if threshold == 4.2 {
				legacyThreshold = 8
			}
			detect.ApplyTuning(0, legacyThreshold, 0)
			candidate := verificationCandidate{typ: "aws_access_key_id", value: value, start: 0, end: len(value), tuning: &settings}
			var doc *literalDocument
			switch mode {
			case "decoded":
				candidate.decodedText = value
			case "jwt":
				candidate.jwtPayload = true
			case "unbound":
				candidate.unboundView = "derived mobile strings"
			case "structured":
				item := model.Item{Source: "code", Path: "owned.json", Text: `{"key":"` + value + `"}`}
				doc = parseLiterals(t.Context(), item, false)
				// Locate the decoded scalar, independently of physical source coordinates.
				candidate.start = strings.Index(doc.text, value)
				candidate.end = candidate.start + len(value)
			}
			set := orderVerifier(t, server.URL, "")
			before := calls.Load()
			var f model.Finding
			candidate.apply(t.Context(), set, doc, value, "owned.env", &f)
			if threshold == 4.2 {
				if calls.Load() != before+1 || f.Verified == nil || !*f.Verified {
					t.Fatalf("%s: selected permissive threshold was lost: %+v", mode, f.Verification)
				}
			} else if calls.Load() != before || f.Verification == nil || f.Verification.Status != "skipped" {
				t.Fatalf("%s: selected placeholder threshold was lost: %+v", mode, f.Verification)
			}
		}
	}
}

func TestTuningScopesRemainStableAndRejectCrossPolicyAbsence(t *testing.T) {
	defer detect.ApplyTuning(3.5, 4.2, 50000)
	detect.ApplyTuning(3.5, 4.2, 50000)
	first := New(Options{Detector: detector(t), IdentityKey: []byte(strings.Repeat("k", 32))})
	collect := func(p *Pipeline, text string) model.ScanResult {
		coverage := model.NewCoverage()
		coverage.RegisterScope("filesystem", "/owned", "selected")
		fs := p.Findings(model.WithCoverage(t.Context(), coverage), model.Item{Source: "code", Path: "owned.env", Text: text})
		return model.NewResult(fs, coverage)
	}
	before := collect(first, "AWS=AKIANAFGYOEYPXU1DSYP")
	detect.ApplyTuning(7.5, 8, 50000)
	other := New(Options{Detector: detector(t), IdentityKey: []byte(strings.Repeat("k", 32))})
	after := collect(first, "ordinary text")
	result, err := correlation.Compare(before, after)
	if err != nil || !result.Comparable || result.Items[0].Presence != "absent_in_scope" {
		t.Fatal("later globals changed an existing pipeline's comparison scope", result, err)
	}
	changed := collect(other, "ordinary text")
	result, err = correlation.Compare(before, changed)
	if err != nil || result.Comparable || result.Items[0].Presence != "inconclusive" {
		t.Fatal("different effective tuning certified absence", result, err)
	}
	if !reflect.DeepEqual(scopeOfKind(before.Scope, "detection_policy"), scopeOfKind(collect(first.WithRevealSecrets(false), "ordinary text").Scope, "detection_policy")) {
		t.Fatal("derived pipeline lost tuning snapshot")
	}
}

func TestMissingDetectorKeepsDefaultsAndFailsClosed(t *testing.T) {
	defer detect.ApplyTuning(3.5, 4.2, 50000)
	detect.ApplyTuning(2, 2, 1)
	p := New(Options{})
	if p.options.Detector.MaxScanMatches() != 50000 {
		t.Fatal("missing detector inherited legacy candidate cap")
	}
	collect := func(p *Pipeline) model.ScanResult {
		coverage := model.NewCoverage()
		fs := p.Findings(model.WithCoverage(t.Context(), coverage), model.Item{Source: "code", Path: "owned.env", Text: "ordinary text"})
		return model.NewResult(fs, coverage)
	}
	before := collect(p)
	detect.ApplyTuning(7.5, 8, 2)
	after := collect(p.WithRevealSecrets(false))
	if p.options.Detector.Tuning() != detect.DefaultTuning() || before.Complete || after.Complete || !reflect.DeepEqual(before.Scope, after.Scope) {
		t.Fatal("missing detector changed defaults or certified an incomplete scan")
	}
}
