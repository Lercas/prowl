package mlfeatures

import (
	"bufio"
	"encoding/json"
	"math"
	"os"
	"testing"
)

func TestPortableExtractorParity(t *testing.T) {
	f, err := os.Open("testdata/portable_golden.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		var row struct {
			Value    string
			Context  Context
			Features []float64
		}
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		got := Extract(row.Value, row.Context)
		if len(got) != len(row.Features) {
			t.Fatal("incomplete portable feature fixture")
		}
		for i := range got {
			if math.Abs(got[i]-row.Features[i]) > 1e-12 {
				t.Fatalf("row %d: portable feature %s differs from training", count, FeatureNames[i])
			}
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count < 64 {
		t.Fatal("portable fixture is missing")
	}
}
