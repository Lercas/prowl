package mlmodel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlfeatures"
)

// A clean checkout must test the actual release model and every feature, including zlib.
func TestReleasePythonFeatureAndPredictionParity(t *testing.T) {
	data, err := os.ReadFile("testdata/release_parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ModelSHA         string   `json:"model_sha256"`
		ComparisonPolicy string   `json:"comparison_policy"`
		Names            []string `json:"feature_names"`
		Rows             []struct {
			Value    string             `json:"value"`
			Context  mlfeatures.Context `json:"context"`
			Features []float64          `json:"features"`
			Score    float64            `json:"l2_prob"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	modelData, err := os.ReadFile("model_binary.json")
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(modelData)
	if fixture.ModelSHA != hex.EncodeToString(h[:]) || len(fixture.Rows) != 256 || fixture.ComparisonPolicy != "absolute_split_tolerance_1e-12" {
		t.Fatal("fixture does not match the release model")
	}
	m, err := LoadFile("model_binary.json")
	if err != nil {
		t.Fatal(err)
	}
	for i, row := range fixture.Rows {
		x := mlfeatures.Extract(row.Value, row.Context)
		if len(x) != len(row.Features) {
			t.Fatal("feature contract differs")
		}
		for j := range x {
			if fixture.Names[j] != mlfeatures.FeatureNames[j] || math.Abs(x[j]-row.Features[j]) > 1e-9 {
				t.Fatalf("row %d feature %s differs", i, fixture.Names[j])
			}
		}
		p, err := m.Predict(x)
		if err != nil || math.Abs(p-row.Score) > 1e-12 {
			t.Fatalf("row %d prediction %.17g expected %.17g err=%v features=%v expectedFeatures=%v", i, p, row.Score, err, x, row.Features)
		}
	}
}
