package mlfeatures

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// fixtureRow mirrors one record in data/processed/models/fixture_feat.json.
type fixtureRow struct {
	Value   string `json:"value"`
	Context struct {
		Name   string `json:"name"`
		Line   string `json:"line"`
		Path   string `json:"path"`
		Source string `json:"source"`
	} `json:"context"`
	Features []float64 `json:"features"`
}

// fixturePath locates the parity fixture relative to the repo root. The test
// runs from tool/internal/mlfeatures, so the repo root is three levels up.
func fixturePath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// tool/internal/mlfeatures -> repo root is ../../../
	p := filepath.Join(wd, "..", "..", "..", "data", "processed", "models", "fixture_feat.json")
	if _, err := os.Stat(p); err != nil {
		// The Python-generated parity fixture lives under the gitignored data/ tree, so a clean checkout
		// (CI) has no copy. Skip the local-only parity check there rather than fail. Matches mlmodel.
		t.Skipf("parity fixture not found at %s (gitignored); skipping local-only parity check: %v", p, err)
	}
	return p
}

func loadFixture(t *testing.T) []fixtureRow {
	t.Helper()
	data, err := os.ReadFile(fixturePath(t))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var rows []fixtureRow
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("fixture is empty")
	}
	return rows
}

const tol = 1e-9

// compressionRatioIdx is the versioned Go feature replacing Python zlib.
const compressionRatioIdx = 7

// TestParity checks the unchanged features against the legacy Python fixture.
// Portable compression and model predictions have separate checked-in fixtures.
func TestParity(t *testing.T) {
	rows := loadFixture(t)

	for i, row := range rows {
		if len(row.Features) != len(FeatureNames)-2 {
			t.Fatalf("row %d: fixture has %d features, want %d", i, len(row.Features), len(FeatureNames))
		}
		ctx := Context{
			Name:   row.Context.Name,
			Line:   row.Context.Line,
			Path:   row.Context.Path,
			Source: row.Context.Source,
		}
		got := Extract(row.Value, ctx)
		if len(got) != len(FeatureNames) {
			t.Fatalf("row %d: Extract returned %d features, want %d", i, len(got), len(FeatureNames))
		}
		for j := range row.Features {
			if j == compressionRatioIdx {
				continue // legacy Python zlib fixture; portable compression has its own tests
			}
			want := row.Features[j]
			if diff := math.Abs(got[j] - want); diff > tol {
				t.Errorf("row %d value=%q feature[%d]=%s: got %.17g want %.17g (delta %.3g)",
					i, truncate(row.Value, 40), j, FeatureNames[j], got[j], want, diff)
			}
		}
	}
}

// TestCompressionRatioDivergence documents why old zlib model schemas must be rejected.
func TestCompressionRatioDivergence(t *testing.T) {
	rows := loadFixture(t)
	diverging := 0
	var maxDelta float64
	var maxDeltaVal string
	for _, row := range rows {
		ctx := Context{
			Name:   row.Context.Name,
			Line:   row.Context.Line,
			Path:   row.Context.Path,
			Source: row.Context.Source,
		}
		got := Extract(row.Value, ctx)[compressionRatioIdx]
		want := row.Features[compressionRatioIdx]
		if d := math.Abs(got - want); d > tol {
			diverging++
			if d > maxDelta {
				maxDelta = d
				maxDeltaVal = row.Value
			}
		}
	}
	t.Logf("legacy zlib versus portable DEFLATE: diverging=%d/%d maxDelta=%.6g (value=%q)",
		diverging, len(rows), maxDelta, truncate(maxDeltaVal, 40))
	if diverging == 0 {
		t.Fatal("legacy zlib fixture unexpectedly matches portable feature; check fixture provenance")
	}
}

// TestFeatureCount guards the feature count and name order.
func TestFeatureCount(t *testing.T) {
	if len(FeatureNames) != 51 {
		t.Fatalf("FeatureNames has %d entries, want 51", len(FeatureNames))
	}
	got := Extract("AKIAIOSFODNN7EXAMPLE", Context{Name: "key", Source: "code"})
	if len(got) != 51 {
		t.Fatalf("Extract returned %d features, want 49", len(got))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
