package detect

import "testing"

// TestApplyTuning verifies config-driven thresholds actually change detection, and restores defaults.
func TestApplyTuning(t *testing.T) {
	defer ApplyTuning(3.5, 4.2, 50000) // restore defaults regardless of outcome
	d := newDetector(t)
	const val = `token_value = "Xk9Zm2Qp7Lr4Ns8Tv1Wy6Bd3Fg5Hj0aQw"`

	ApplyTuning(2.0, 4.2, 50000) // very low entropy floor -> the high-entropy token is reported
	if n := countType(d.Scan(val), "generic_high_entropy"); n == 0 {
		t.Fatalf("generic_entropy_min=2.0: expected a generic_high_entropy hit, got none")
	}
	ApplyTuning(7.5, 4.2, 50000) // floor above any real entropy -> nothing generic survives
	if n := countType(d.Scan(val), "generic_high_entropy"); n != 0 {
		t.Fatalf("generic_entropy_min=7.5: expected no generic_high_entropy hit, got %d", n)
	}
}

func countType(ms []Match, typ string) int {
	n := 0
	for _, m := range ms {
		if m.Type == typ {
			n++
		}
	}
	return n
}
