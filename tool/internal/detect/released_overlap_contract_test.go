package detect

import (
	"math/rand"
	"testing"
	"time"
)

func TestMixedConfidenceDedupeAvoidsInsertionShifts(t *testing.T) {
	const count = 50000
	ms := make([]Match, count)
	for i := range ms {
		// High-confidence spans appear after all low-confidence spans in source order. Processing
		// confidence first previously shifted most of the output for every later low-confidence hit.
		confidence := .55
		if i >= count/2 {
			confidence = .99
		}
		ms[i] = Match{Start: i * 10, End: i*10 + 8, Confidence: confidence}
	}
	started := time.Now()
	kept, truncated := dedupeOverlapsCap(ms, count+1)
	if len(kept) != count || truncated {
		t.Fatal("mixed-confidence disjoint source spans were lost")
	}
	for i, m := range kept {
		if m.Start != i*10 || m.End != i*10+8 {
			t.Fatal("deduplication changed source order or spans")
		}
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("mixed-confidence deduplication still incurs quadratic insertion cost")
	}
}

func TestDedupeConfidenceDominanceAcrossDenseOverlaps(t *testing.T) {
	rng := rand.New(rand.NewSource(1403)) // deterministic synthetic source intervals
	for range 12 {
		ms := make([]Match, 3000)
		for i := range ms {
			start := rng.Intn(5000)
			ms[i] = Match{Start: start, End: start + 1 + rng.Intn(100), Confidence: []float64{.55, .6, .9, .99}[rng.Intn(4)]}
		}
		kept, truncated := dedupeOverlapsCap(ms, -1)
		if truncated || len(kept) == 0 {
			t.Fatal("uncapped overlap resolution lost all evidence")
		}
		for i, m := range kept {
			if i > 0 && kept[i-1].End > m.Start {
				t.Fatal("literal source intervals still overlap")
			}
		}
		for _, m := range ms {
			dominated := false
			for _, winner := range kept {
				if winner.Start < m.End && m.Start < winner.End && winner.Confidence >= m.Confidence {
					dominated = true
					break
				}
			}
			if !dominated {
				t.Fatal("a discarded interval has no overlapping winner with equal/higher confidence")
			}
		}
	}
}
