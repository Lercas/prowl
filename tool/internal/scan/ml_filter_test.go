package scan

import (
	"context"
	"math"
	"reflect"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
)

type fixedMLScorer struct {
	results   []mlscore.Result
	threshold float64
}

func (s fixedMLScorer) Score(context.Context, []mlscore.Record) ([]mlscore.Result, error) {
	return s.results, nil
}
func (s fixedMLScorer) Threshold() float64 { return s.threshold }
func (s fixedMLScorer) Local() bool        { return true }

func TestMLCannotSuppressProviderConfirmedSecrets(t *testing.T) {
	yes, no := true, false
	fs := []model.Finding{
		{Type: "owned_token", Fingerprint: "live", Verified: &yes},
		{Type: "owned_token", Fingerprint: "dead", Verified: &no},
		{Type: "owned_token", Fingerprint: "unknown"},
	}
	scorer := fixedMLScorer{results: make([]mlscore.Result, len(fs)), threshold: 0.3}
	got := mlFilter(context.Background(), scorer, fs, make([]mlscore.Record, len(fs)))
	if len(got) != 1 || got[0].Fingerprint != "live" || got[0].Verified == nil || !*got[0].Verified {
		t.Fatalf("ML removed provider-confirmed evidence: %+v", got)
	}
}

func TestInvalidMLScoreOrThresholdKeepsEveryCandidateAtomically(t *testing.T) {
	for _, invalid := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -0.01, 1.01} {
		for _, threshold := range []bool{false, true} {
			fs := []model.Finding{{Type: "owned_token", Fingerprint: "first"}, {Type: "owned_token", Fingerprint: "second"}}
			want := append([]model.Finding(nil), fs...)
			scorer := fixedMLScorer{results: []mlscore.Result{{Score: 0}, {Score: invalid}}, threshold: 0.3}
			if threshold {
				scorer.results[1].Score, scorer.threshold = 0, invalid
			}
			got := mlFilter(context.Background(), scorer, fs, make([]mlscore.Record, len(fs)))
			if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(fs, want) {
				t.Fatalf("invalid ML batch partially suppressed/mutated findings: threshold=%v value=%v got=%+v", threshold, invalid, got)
			}
		}
	}
}
