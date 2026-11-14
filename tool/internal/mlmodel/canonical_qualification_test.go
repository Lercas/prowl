package mlmodel

import (
	"encoding/json"
	"io"
	"math"
	"os"
	"testing"
)

// Run explicitly against the retained numeric feature corpus; no raw values
// are needed to prove that parser-proof=false preserves every original score.
func TestCanonicalCompositionFullParity(t *testing.T) {
	basePath, candidatePath, featuresPath := os.Getenv("PROWL_BASE_REFERENCE"), os.Getenv("PROWL_COMPOSED_MODEL"), os.Getenv("PROWL_PARITY_FEATURES")
	if basePath == "" || candidatePath == "" || featuresPath == "" {
		t.Skip("explicit offline qualification artifacts required")
	}
	base, err := LoadFile(basePath)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := LoadFile(candidatePath)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(featuresPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	count := 0
	for {
		var x []float64
		if err := dec.Decode(&x); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if len(x) == NumFeatures-2 {
			x = append(x, 0, 0)
		}
		if len(x) != NumFeatures || x[NumFeatures-2] != 0 {
			t.Fatal("parity corpus does not identify the original proof-free feature space")
		}
		a, err := base.Predict(x)
		if err != nil {
			t.Fatal(err)
		}
		b, err := candidate.Predict(x)
		if err != nil {
			t.Fatal(err)
		}
		if math.Float64bits(a) != math.Float64bits(b) {
			t.Fatalf("off-scope prediction changed at row %d", count)
		}
		count++
	}
	if count == 0 {
		t.Fatal("empty qualification corpus")
	}
	t.Logf("identical predictions for %d original feature vectors", count)
}

func TestCanonicalCompositionGolden(t *testing.T) {
	path, golden := os.Getenv("PROWL_COMPOSED_MODEL"), os.Getenv("PROWL_COMPOSED_GOLDEN")
	if path == "" || golden == "" {
		t.Skip("explicit offline qualification artifacts required")
	}
	m, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Features    []float64 `json:"features"`
		Probability float64   `json:"l2_prob"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for i, row := range rows {
		p, err := m.Predict(row.Features)
		if err != nil {
			t.Fatal(err)
		}
		if math.Abs(p-row.Probability) > 1e-12 {
			t.Fatalf("Go/Python prediction mismatch at row %d", i)
		}
	}
	t.Logf("matched %d composed model predictions", len(rows))
}
