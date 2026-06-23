package mlmodel

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fixtureRow mirrors one entry of fixture_model.json.
type fixtureRow struct {
	Features []float64 `json:"features"`
	L2Prob   float64   `json:"l2_prob"`
}

// fixturePath locates data/processed/models/fixture_model.json relative to this
// package. The package lives at tool/internal/mlmodel and tool/ sits directly
// under the repo root, so the repo root is three directories up.
func fixturePath(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "..", "data", "processed", "models", "fixture_model.json")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("parity fixture not found at %s: %v", p, err)
	}
	return p
}

func loadFixture(t *testing.T) []fixtureRow {
	t.Helper()
	b, err := os.ReadFile(fixturePath(t))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var rows []fixtureRow
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("fixture is empty")
	}
	return rows
}

func TestLoad(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := len(m.FeatureNames()); got != NumFeatures {
		t.Fatalf("FeatureNames len = %d, want %d", got, NumFeatures)
	}
	if got := len(m.treeStart); got == 0 {
		t.Fatal("model has no trees")
	}
}

func TestPredictRejectsWrongLength(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, n := range []int{0, NumFeatures - 1, NumFeatures + 1} {
		if _, err := m.Predict(make([]float64, n)); err == nil {
			t.Errorf("Predict(len=%d) = nil error, want error", n)
		}
	}
}

// TestParity is the load-bearing check: Predict must match the Python reference
// (recorded in fixture_model.json) to within 1e-6 for every row.
func TestParity(t *testing.T) {
	const tol = 1e-6

	m, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rows := loadFixture(t)

	var maxErr float64
	var worst int
	for i, r := range rows {
		if len(r.Features) != NumFeatures {
			t.Fatalf("fixture row %d has %d features, want %d", i, len(r.Features), NumFeatures)
		}
		got, err := m.Predict(r.Features)
		if err != nil {
			t.Fatalf("Predict(row %d): %v", i, err)
		}
		e := math.Abs(got - r.L2Prob)
		if e > maxErr {
			maxErr, worst = e, i
		}
		if e > tol {
			t.Errorf("row %d: Predict = %.17g, want %.17g (abs err %.3g > %.0e)",
				i, got, r.L2Prob, e, tol)
		}
	}
	t.Logf("parity over %d rows: max abs err = %.3e (worst row %d), tol = %.0e",
		len(rows), maxErr, worst, tol)
}

// cyclicModelJSON builds a minimal, otherwise-valid model_binary.json whose one
// tree contains a cycle: node 0 (internal) routes to node 1 (internal) which
// routes back to node 0. parse accepts it (child indices are in range and the
// arrays aren't ragged), so the cycle only bites at Predict time — exactly the
// crafted/corrupt-model case the bound defends against.
func cyclicModelJSON(t *testing.T) []byte {
	t.Helper()
	names := make([]string, NumFeatures)
	for i := range names {
		names[i] = "f" + string(rune('a'+i%26))
	}
	// Two internal nodes, no leaf: 0 -> {left:1,right:1}, 1 -> {left:0,right:0}.
	// is_leaf is 0 for both, so the walk can never terminate without the bound.
	rm := map[string]any{
		"baseline":      0.0,
		"feature_names": names,
		"trees": []map[string]any{{
			"feature_idx":  []int{0, 0},
			"threshold":    []float64{0.5, 0.5},
			"left":         []int{1, 0},
			"right":        []int{1, 0},
			"value":        []float64{0.0, 0.0},
			"missing_left": []int{0, 0},
			"is_leaf":      []int{0, 0},
		}},
	}
	b, err := json.Marshal(rm)
	if err != nil {
		t.Fatalf("marshal cyclic model: %v", err)
	}
	return b
}

// TestPredictCyclicModelTerminates is the regression for the hang: a model with a
// node cycle must make Predict return ErrCyclicModel instead of looping forever.
// We run Predict on a watchdog goroutine and fail if it doesn't return promptly —
// before the fix this test would hit the timeout (the walk never reaches a leaf).
func TestPredictCyclicModelTerminates(t *testing.T) {
	m, err := parse(cyclicModelJSON(t))
	if err != nil {
		t.Fatalf("parse cyclic model (must pass parse, fail at predict): %v", err)
	}

	type res struct {
		p   float64
		err error
	}
	done := make(chan res, 1)
	go func() {
		p, err := m.Predict(make([]float64, NumFeatures))
		done <- res{p, err}
	}()

	select {
	case r := <-done:
		if !errors.Is(r.err, ErrCyclicModel) {
			t.Fatalf("Predict on cyclic model = (%v, %v), want ErrCyclicModel", r.p, r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Predict on a cyclic model hung (no acyclicity / iteration bound) — would loop forever")
	}
}

func BenchmarkPredict(b *testing.B) {
	m, err := Load()
	if err != nil {
		b.Fatalf("Load: %v", err)
	}
	rows := loadFixtureB(b)
	x := rows[0].Features

	b.ReportAllocs()
	b.ResetTimer()
	var sink float64
	for i := 0; i < b.N; i++ {
		sink, _ = m.predict(x)
	}
	_ = sink
}

// loadFixtureB is the *testing.B twin of loadFixture; if the fixture is missing
// it falls back to a zero vector so the benchmark still measures the hot path.
func loadFixtureB(b *testing.B) []fixtureRow {
	b.Helper()
	p := filepath.Join("..", "..", "..", "data", "processed", "models", "fixture_model.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		return []fixtureRow{{Features: make([]float64, NumFeatures)}}
	}
	var rows []fixtureRow
	if err := json.Unmarshal(raw, &rows); err != nil || len(rows) == 0 {
		return []fixtureRow{{Features: make([]float64, NumFeatures)}}
	}
	return rows
}
