package mlmodel

import (
	"encoding/json"
	"math"
	"os"
	"testing"
)

// This fixture is committed and mandatory, including on static release builds.
func TestPortablePythonPredictionParity(t *testing.T) {
	data, err := os.ReadFile("portable_prediction_fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Features [][]float64 `json:"features"`
		Scores   []float64   `json:"scores"`
	}
	if json.Unmarshal(data, &fixture) != nil {
		t.Fatal("invalid fixture")
	}
	m, err := LoadFile("model_portable.json")
	if err != nil {
		t.Fatal(err)
	}
	if !m.Portable() {
		t.Fatal("missing portable contract")
	}
	if len(fixture.Features) < 100 || len(fixture.Features) != len(fixture.Scores) {
		t.Fatal("insufficient parity coverage")
	}
	for i, row := range fixture.Features {
		got, err := m.Predict(row)
		if err != nil || math.Abs(got-fixture.Scores[i]) > 1e-12 {
			t.Fatalf("prediction differs from Python at row %d", i)
		}
		row[7] = 999
		if same, _ := m.Predict(row); same != got {
			t.Fatal("portable model depends on compression")
		}
	}
}
