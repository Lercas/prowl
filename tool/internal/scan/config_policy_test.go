package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/correlation"
	"github.com/Lercas/prowl/tool/internal/model"
)

func scanPolicyConfig(t *testing.T, text string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestConfigPolicyUsesFrozenEffectiveAllowlist(t *testing.T) {
	cfg := scanPolicyConfig(t, "allowlist: {values: [AKIANAFGYOEYPXU1DSYP]}\n")
	pipeline := New(Options{Detector: detector(t), Config: cfg})
	cfg.MergeAllowlist([]string{"AKIA4MNQ2RST7UVWX9YZ"}, nil, nil)
	for _, p := range []*Pipeline{pipeline, pipeline.WithRevealSecrets(true)} {
		coverage := model.NewCoverage()
		fs := p.Findings(model.WithCoverage(t.Context(), coverage), model.Item{Source: "code", Path: "owned.env", Text: "A=AKIANAFGYOEYPXU1DSYP\nB=AKIA4MNQ2RST7UVWX9YZ"})
		found := 0
		for _, f := range fs {
			if f.Type == "aws_access_key_id" {
				found++
			}
		}
		report := model.NewResult(fs, coverage)
		if found != 1 || !report.Complete || !report.Filtered || scopeOfKind(report.Scope, "detector_config").Kind == "" || scopeOfKind(report.Scope, "unversioned_policy").Kind != "" {
			t.Fatal("frozen configuration changed or lost policy", fs, report)
		}
	}
	if pipeline.options.Config != nil {
		t.Fatal("pipeline retained mutable original")
	}
}
func TestConfigPolicyCallbackCannotCertifyAbsence(t *testing.T) {
	for _, callback := range []bool{false, true} {
		opts := Options{Detector: detector(t), IdentityKey: []byte(strings.Repeat("k", 32)), Config: &config.Config{}}
		if callback {
			opts.Config = nil
			opts.Allow = func(string, string) bool { return false }
		}
		p := New(opts)
		collect := func(text string) model.ScanResult {
			coverage := model.NewCoverage()
			coverage.RegisterScope("filesystem", "/owned", "selected")
			fs := p.Findings(model.WithCoverage(context.Background(), coverage), model.Item{Source: "code", Path: "owned.env", Text: text})
			return model.NewResult(fs, coverage)
		}
		before, after := collect("AWS=AKIANAFGYOEYPXU1DSYP"), collect("ordinary text")
		result, err := correlation.Compare(before, after)
		if err != nil {
			t.Fatal(err)
		}
		if callback {
			if result.Comparable || result.Items[0].Presence != "inconclusive" || !after.Complete {
				t.Fatal("unidentified callback certified absence", result)
			}
		} else if !result.Comparable || result.Items[0].Presence != "absent_in_scope" {
			t.Fatal("known default policy lost comparable scope", result)
		}
	}
}
func TestConfigPolicyRejectedBeforeCallbacksAndOnEmptyStream(t *testing.T) {
	for _, cross := range []bool{false, true} {
		p := New(Options{Config: &config.Config{}, CrossFile: cross, Allow: func(string, string) bool { t.Fatal("ambiguous callback executed"); return false }})
		for _, stream := range []bool{false, true} {
			coverage := model.NewCoverage()
			ctx := model.WithCoverage(t.Context(), coverage)
			var fs []model.Finding
			if stream {
				fs = p.Run(ctx, feed())
			} else {
				fs = p.Findings(ctx, model.Item{Path: "owned.env", Text: "ordinary text"})
			}
			if len(fs) != 1 || !model.IsIncompleteFinding(fs[0]) || model.NewResult(fs, coverage).Complete {
				t.Fatal("invalid configuration certified empty input", cross, stream, fs)
			}
		}
	}
}
func TestConfigPolicyDeclaredSuppressionsAreFilteredWithoutMatches(t *testing.T) {
	cfg := scanPolicyConfig(t, "allowlist: {values: [unused-owned-value]}\n")
	coverage := model.NewCoverage()
	p := New(Options{Detector: detector(t), Config: cfg})
	fs := p.Run(model.WithCoverage(t.Context(), coverage), feed())
	report := model.NewResult(fs, coverage)
	if !report.Complete || !report.Filtered || scopeOfKind(report.Scope, "detector_config").Kind == "" {
		t.Fatal("empty input lost configured suppression")
	}
}
