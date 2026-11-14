package mlmodel

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlfeatures"
)

func TestPortablePredictionParity(t *testing.T) {
	qualification, err := os.ReadFile("testdata/literal_calibration_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var qualified struct {
		ModelSHA256 string `json:"model_sha256"`
		Qualified   bool   `json:"calibration_gate"`
	}
	if err := json.Unmarshal(qualification, &qualified); err != nil {
		t.Fatal(err)
	}
	if !qualified.Qualified || fmt.Sprintf("%x", sha256.Sum256(embedded)) != qualified.ModelSHA256 {
		t.Fatal("embedded model does not match the qualified artifact")
	}
	raw, err := os.ReadFile("testdata/literal_prediction_golden_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []fixtureRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 768 {
		t.Fatalf("prediction fixture has %d rows", len(rows))
	}
	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range m.FeatureNames() {
		if name != mlfeatures.FeatureNames[i] {
			t.Fatal("embedded feature schema mismatch")
		}
	}
	for i, row := range rows {
		got, err := m.Predict(row.Features)
		if err != nil {
			t.Fatal(err)
		}
		if math.Abs(got-row.L2Prob) > 1e-12 {
			t.Fatalf("row %d: Go/Python score mismatch", i)
		}
	}
}
