package mlmodel

import (
	"math"
	"testing"
)

func TestSplitBoundaryContract(t *testing.T) {
	threshold := 3.418295834054489
	for _, value := range []float64{threshold, math.Nextafter(threshold, math.Inf(1)), threshold - 1e-8} {
		if !splitLeft(value, threshold) {
			t.Fatalf("value %.17g must follow the equality branch", value)
		}
	}
	for _, value := range []float64{threshold + 1e-8, math.NaN(), math.Inf(1)} {
		if splitLeft(value, threshold) {
			t.Fatalf("value %.17g incorrectly follows the equality branch", value)
		}
	}
	if splitLeft(1e9+1e-4, 1e9) {
		t.Fatal("the margin must not grow with the threshold")
	}
}
