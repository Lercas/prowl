package mlfeatures

import (
	"bufio"
	"encoding/json"
	"math"
	"os"
	"testing"
)

// TestExtractorParity guards that the Go extractor stays byte-identical to the Python reference
// (src/features/extract.py): testdata/parity_golden.jsonl is generated from Python, so a feature added
// or computed differently in one language but not the other fails here. Regenerate the fixture from
// Python when the feature set changes on purpose.
func TestExtractorParity(t *testing.T) {
	f, err := os.Open("testdata/parity_golden.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc.Scan() {
		var r struct {
			Value, Name, Line, Path, Source string
			Feats                           []float64
		}
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		got := Extract(r.Value, Context{Name: r.Name, Line: r.Line, Path: r.Path, Source: r.Source})
		if len(got) != len(r.Feats) {
			t.Fatalf("%q: %d features, golden has %d", r.Value, len(got), len(r.Feats))
		}
		for i := range got {
			if math.Abs(got[i]-r.Feats[i]) > 1e-9 {
				t.Errorf("%q feature %s: go=%v python=%v", r.Value, FeatureNames[i], got[i], r.Feats[i])
			}
		}
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("empty golden fixture")
	}
}

// TestParityDump writes Go feature vectors for an external JSONL input set so the parity harness can
// diff or regenerate the golden fixture. Gated on PARITY_IN so it never runs in the normal suite.
func TestParityDump(t *testing.T) {
	in := os.Getenv("PARITY_IN")
	if in == "" {
		t.Skip("set PARITY_IN/PARITY_OUT to run the parity dump")
	}
	f, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out, err := os.Create(os.Getenv("PARITY_OUT"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var r struct{ Value, Name, Line, Path, Source string }
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			continue
		}
		feats := Extract(r.Value, Context{Name: r.Name, Line: r.Line, Path: r.Path, Source: r.Source})
		b, _ := json.Marshal(map[string]any{"value": r.Value, "feats": feats})
		out.Write(b)
		out.Write([]byte("\n"))
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
}
