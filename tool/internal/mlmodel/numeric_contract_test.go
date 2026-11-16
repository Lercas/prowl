package mlmodel

import (
	"encoding/json"
	"math"
	"testing"
)

// Canonical Go-trained features use the model's exact <= comparison. The old
// zlib/Python reconciliation margin must not move a neighboring float across a split.
func TestCanonicalSplitBoundaryContract(t *testing.T) {
	for _, threshold := range []float64{3.418295834054489, 1e9} {
		for _, missingLeft := range []int{0, 1} {
			owned := validOwnedModel(t)
			owned["trees"] = []any{map[string]any{
				"feature_idx": []int{0, -1, -1}, "threshold": []float64{threshold, 0, 0},
				"left": []int{1, 0, 0}, "right": []int{2, 0, 0},
				"value": []float64{0, 1, -1}, "missing_left": []int{missingLeft, 0, 0}, "is_leaf": []int{0, 1, 1},
			}}
			raw, err := json.Marshal(owned)
			if err != nil {
				t.Fatal(err)
			}
			model, err := parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range []struct {
				value float64
				left  bool
			}{
				{threshold, true}, {math.Nextafter(threshold, math.Inf(-1)), true},
				{math.Nextafter(threshold, math.Inf(1)), false},
				{threshold + 1e-4, false}, {math.NaN(), missingLeft == 1},
				{math.Inf(-1), true}, {math.Inf(1), false},
			} {
				x := make([]float64, NumFeatures)
				x[0] = c.value
				probability, err := model.Predict(x)
				if err != nil || (probability > .5) != c.left {
					t.Fatalf("split changed at threshold %.17g, value %.17g, missing-left=%d", threshold, c.value, missingLeft)
				}
			}
		}
	}
}
