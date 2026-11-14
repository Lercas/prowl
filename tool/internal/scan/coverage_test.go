package scan

import (
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
)

func TestCoverageCountsOriginalItemsInsteadOfTransformedViews(t *testing.T) {
	for _, c := range []struct {
		path, text  string
		reconstruct bool
	}{
		{"production.json", `{"key":"` + escapedJSON("AKIANAFGYOEYPXU1DSYP") + `"}`, false},
		{"production.yaml", "definition: &a AKIANAFGYOEYPXU1DSYP\none: {key: *a}\ntwo: {key: *a}\n", false},
		{"bundle.js", "const head='AKIA'; const key=head+'NAFGYOEYPXU1DSYP';", true},
	} {
		ledger := model.NewCoverage()
		fs := New(Options{Detector: detector(t), Reconstruct: c.reconstruct}).Findings(model.WithCoverage(t.Context(), ledger), model.Item{Path: c.path, Source: "code", Text: c.text})
		result := model.NewResult(fs, ledger)
		if !result.Complete || result.Stats.Processed != 1 || result.Stats.Bytes != int64(len(c.text)) {
			t.Fatal("normalized or reconstructed content inflated read statistics")
		}
	}
}

func TestCoverageTracksSuppressionsAndIntakeFailures(t *testing.T) {
	for _, options := range []Options{
		{Allow: func(string, string) bool { return true }},
		{ML: fixedMLScorer{results: []mlscore.Result{{Score: 0}}, threshold: .3}},
	} {
		options.Detector = detector(t)
		ledger := model.NewCoverage()
		fs := New(options).Findings(model.WithCoverage(t.Context(), ledger), model.Item{Path: "prod.env", Text: "AWS=AKIANAFGYOEYPXU1DSYP"})
		if result := model.NewResult(fs, ledger); len(fs) != 0 || !result.Filtered || !result.Complete {
			t.Fatal("intentional suppression was not distinguished from incomplete coverage")
		}
	}
	ledger := model.NewCoverage()
	fs := New(Options{Detector: detector(t)}).Findings(model.WithCoverage(t.Context(), ledger), model.Item{Path: "prod.json", Text: `{"key":"unfinished`})
	if result := model.NewResult(fs, ledger); result.Complete || len(result.Diagnostics) == 0 || result.Stats.Processed != 1 {
		t.Fatal("parser failure disappeared from the shared ledger")
	}
}
