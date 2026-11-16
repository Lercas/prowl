package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlfeatures"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	bundledrules "github.com/Lercas/prowl/tool/rules"
)

type noiseModelVector struct {
	Score    float64   `json:"score"`
	Features []float64 `json:"features"`
}

type noiseModelRecorder struct {
	mlscore.Scorer
	vectors []noiseModelVector
}

func (r *noiseModelRecorder) Score(ctx context.Context, records []mlscore.Record) ([]mlscore.Result, error) {
	results, err := r.Scorer.Score(ctx, records)
	if err != nil {
		return nil, err
	}
	for i, record := range records {
		features := mlfeatures.Extract(record.Value, mlfeatures.Context{
			Name: record.Context.Name, Line: record.Context.Line,
			Path: record.Context.Path, Source: record.Context.Source,
			ParserLiteralSensitive: record.Context.ParserLiteralSensitive,
			UINamespace:            record.Context.UINamespace,
		})
		r.vectors = append(r.vectors, noiseModelVector{results[i].Score, features})
	}
	return results, nil
}

// Diagnostic only: exported records contain numeric features and fixture IDs,
// never raw values, source lines, binding names or model-training labels inferred from scores.
func TestReleasedNoiseModelAudit(t *testing.T) {
	output := os.Getenv("PROWL_NOISE_MODEL_AUDIT")
	if output == "" {
		t.Skip("set PROWL_NOISE_MODEL_AUDIT for the optional model diagnostic")
	}
	scorer, err := mlscore.NewEmbedded(.3, filepath.Join("..", "mlmodel", "model_binary_go_literal_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := rules.LoadEmbedded(bundledrules.Files)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		ID      string             `json:"id"`
		Truth   string             `json:"truth"`
		Hit     bool               `json:"hit"`
		Types   []string           `json:"types"`
		Vectors []noiseModelVector `json:"vectors"`
	}
	var rows []row
	for _, name := range []string{"noise-1.4.0.json", "noise-deep-1.4.0.json"} {
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		var cases []struct {
			Name, Path, Text, Truth, Value string
			Types                          []string
		}
		if err := json.Unmarshal(data, &cases); err != nil {
			t.Fatal(err)
		}
		for _, c := range cases {
			recorder := &noiseModelRecorder{Scorer: scorer}
			findings := New(Options{Detector: detector(t), Rules: engine, ML: recorder}).Findings(t.Context(), model.Item{Text: c.Text, Path: c.Path, Source: "code"})
			current := row{ID: c.Name, Truth: c.Truth, Vectors: recorder.vectors}
			for _, finding := range findings {
				if model.IsIncompleteFinding(finding) {
					t.Fatal("model diagnostic encountered incomplete input")
				}
				current.Types = append(current.Types, finding.Type)
				if c.Value != "" && finding.Fingerprint == model.ComputeFingerprint(finding.Type, c.Path, c.Value) {
					for _, typ := range c.Types {
						current.Hit = current.Hit || typ == finding.Type || typ == "generic_high_entropy" && finding.Type == "generic_api_key"
					}
				}
			}
			rows = append(rows, current)
		}
	}
	data, err := json.MarshalIndent(struct {
		Features []string `json:"feature_names"`
		Rows     []row    `json:"rows"`
	}{mlfeatures.FeatureNames, rows}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
