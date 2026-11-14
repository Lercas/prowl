package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/mlfeatures"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
)

func writeSnapshotModel(t *testing.T, path string, baseline float64) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"baseline": baseline, "feature_names": mlfeatures.FeatureNames,
		"trees": []map[string]any{{"feature_idx": []int{-1}, "threshold": []int{0}, "left": []int{0}, "right": []int{0}, "value": []int{0}, "missing_left": []int{0}, "is_leaf": []int{1}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMLPreflightSnapshotSurvivesFileReplacement(t *testing.T) {
	if !mlfeatures.BuiltWithCgo() {
		t.Skip("in-process ML requires cgo")
	}
	for _, installed := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit", true: "installed"}[installed], func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("PROWL_HOME", home)
			path := filepath.Join(home, "model_binary.json")
			writeSnapshotModel(t, path, 0)
			c := commonFlags{mlEmbed: installed, mlThreshold: 0.3}
			if !installed {
				c.mlModel = path
			}
			if code := c.mlPreflight(); code != 0 {
				t.Fatalf("model preparation returned %d", code)
			}
			writeSnapshotModel(t, path, -100)
			// Configuration is applied after early preflight in most commands. Flag copies used by
			// workers must share the original model while using the finalized threshold.
			worker := c
			worker.mlThreshold = 0.8
			scorer, err := worker.mlScorer()
			if scorer == nil || err != nil {
				t.Fatalf("prepared ML scorer disappeared: %v", err)
			}
			results, err := scorer.Score(context.Background(), []mlscore.Record{{Value: "owned"}})
			if err != nil || len(results) != 1 || results[0].Score != 0.5 || scorer.Threshold() != 0.8 {
				t.Fatalf("model or configuration changed across preparation: results=%+v threshold=%v err=%v", results, scorer.Threshold(), err)
			}
			original, err := c.mlScorer()
			if err != nil || original.Threshold() != 0.3 {
				t.Fatalf("worker changed shared threshold: %v", err)
			}
			// Repeated preflight for the same invocation is idempotent, while a new command observes
			// the refreshed file. Snapshots are scoped to flags, not cached globally by filename.
			if code := c.mlPreflight(); code != 0 {
				t.Fatalf("repeated preflight returned %d", code)
			}
			fresh := commonFlags{mlEmbed: installed, mlModel: c.mlModel, mlThreshold: 0.3}
			if code := fresh.mlPreflight(); code != 0 {
				t.Fatalf("new command could not use refreshed model: %d", code)
			}
			updated, err := fresh.mlScorer()
			if err != nil {
				t.Fatal(err)
			}
			results, err = updated.Score(context.Background(), []mlscore.Record{{Value: "owned"}})
			if err != nil || len(results) != 1 || results[0].Score >= 0.3 {
				t.Fatalf("new command reused an old snapshot: %+v %v", results, err)
			}
		})
	}
}

func TestUnpreparedMLCannotProduceACompleteReportOrBaseline(t *testing.T) {
	c := commonFlags{mlEmbed: true, format: "json", workers: 1, maxPerFile: 0}
	if scorer, err := c.mlScorer(); err == nil || scorer != nil {
		t.Fatal("unprepared embedded ML was silently loaded or disabled")
	}
	cfg := &config.Config{}
	det, _, err := loadDetector(commonFlags{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	items := make(chan model.Item, 1)
	items <- model.Item{Text: `AWS="AKIANAFGYOEYPXU1DSYP"`, Source: "code", Path: "prod.env"}
	close(items)
	fs := collectFindings(context.Background(), c, cfg, det, nil, nil, items, false)
	found, incomplete := false, false
	for _, finding := range fs {
		found = found || finding.Type == "aws_access_key_id"
		incomplete = incomplete || model.IsIncompleteFinding(finding)
	}
	if !found || !incomplete {
		t.Fatalf("missing ML setup lost candidates or failure evidence: %+v", fs)
	}
	dir := t.TempDir()
	c.output, c.writeBaseline = filepath.Join(dir, "report.json"), filepath.Join(dir, "baseline.json")
	const previous = "owned previous baseline"
	if err := os.WriteFile(c.writeBaseline, []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := reportFindings(c, fs, time.Millisecond); code != 2 {
		t.Fatalf("unprepared ML returned %d", code)
	}
	raw, err := os.ReadFile(c.writeBaseline)
	if err != nil || string(raw) != previous {
		t.Fatalf("ML setup failure modified baseline: %q %v", raw, err)
	}
}
