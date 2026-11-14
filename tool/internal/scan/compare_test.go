package scan

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/semantic"
)

type compareTestScorer struct {
	action func([]mlscore.Record) ([]mlscore.Result, error)
	calls  atomic.Int32
}

func (s *compareTestScorer) Score(_ context.Context, r []mlscore.Record) ([]mlscore.Result, error) {
	s.calls.Add(1)
	return s.action(r)
}
func (*compareTestScorer) Local() bool        { return true }
func (*compareTestScorer) Threshold() float64 { return .5 }

func compareSemantic(t *testing.T, values []string, calls *atomic.Int32) *semantic.Engine {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		cs := []semantic.Candidate{}
		for _, value := range values {
			cs = append(cs, semantic.Candidate{Value: value})
		}
		raw, _ := json.Marshal(map[string]any{"candidates": cs})
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]string{"content": string(raw)}}}})
	}))
	t.Cleanup(server.Close)
	e, err := semantic.New(semantic.Config{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestComparisonAcquiresAndDiscoversOnceBeforeCompactingML(t *testing.T) {
	var discovery atomic.Int32
	e := compareSemantic(t, []string{"tulip-moon", "ember-finch"}, &discovery)
	scorer := &compareTestScorer{action: func(rows []mlscore.Record) ([]mlscore.Result, error) {
		if len(rows) != 2 || rows[0].Value != "tulip-moon" || rows[1].Value != "ember-finch" {
			t.Error("ML did not receive the discovered candidate pool")
		}
		return []mlscore.Result{{Score: 0}, {Score: 1}}, nil
	}}
	p := New(Options{Detector: detector(t), Semantic: true, SemanticEngine: e, ML: scorer, Workers: 2})
	factories := 0
	result, err := p.Compare(context.Background(), func(context.Context) (<-chan model.Item, error) {
		factories++
		return feed(model.Item{Source: "code", Path: "production.txt", Text: "Archive access words: tulip-moon and ember-finch"}), nil
	})
	if err != nil || factories != 1 || discovery.Load() != 1 || scorer.calls.Load() != 1 || len(result.Raw) != 2 || len(result.Kept) != 1 {
		t.Fatalf("comparison was not one pass: %+v %v", result, err)
	}
	if result.Raw[0].Redacted != model.Redact("tulip-moon") || result.Kept[0].Redacted != model.Redact("ember-finch") || result.Raw[0].Context != nil || result.Raw[0].Provenance != nil {
		t.Fatal("pre-L2 projection was overwritten or retained source context")
	}
}

func TestComparisonKeepsStructuredAndReconstructedSourceCoordinates(t *testing.T) {
	for _, test := range []struct {
		path, text  string
		reconstruct bool
		lexical     string
	}{
		{"production.json", `{"note":"tulip\u002dmoon"}`, false, `tulip\u002dmoon`},
		{"bundle.js", `const head='AKIA';const key=head+'NAFGYOEYPXU1DSYP';const note='tulip-moon';`, true, "tulip-moon"},
	} {
		var requests atomic.Int32
		e := compareSemantic(t, []string{"tulip-moon"}, &requests)
		scorer := &compareTestScorer{action: func(rows []mlscore.Record) ([]mlscore.Result, error) {
			out := make([]mlscore.Result, len(rows))
			for i := range out {
				out[i].Score = 1
			}
			return out, nil
		}}
		p := New(Options{Detector: detector(t), Semantic: true, SemanticEngine: e, ML: scorer, Reconstruct: test.reconstruct})
		result, err := p.Compare(context.Background(), func(context.Context) (<-chan model.Item, error) {
			return feed(model.Item{Source: "code", Path: test.path, Text: test.text}), nil
		})
		if err != nil || requests.Load() != 1 || len(result.Raw) != len(result.Kept) {
			t.Fatalf("source normalization/reconstruction diverged: %v", err)
		}
		found := false
		for _, f := range result.Raw {
			if f.Type == "generic_semantic_secret" {
				found = true
				if test.text[f.ByteStart:f.ByteEnd] != test.lexical {
					t.Fatal("comparison lost physical source coordinates")
				}
			}
		}
		if !found || test.reconstruct && len(result.Raw) != 2 {
			t.Fatal("discovery or reconstruction missing")
		}
	}
}

func TestComparisonScoringFailuresCannotLookLikeZeroSuppression(t *testing.T) {
	for _, mode := range []string{"error", "panic", "partial", "nan"} {
		var requests atomic.Int32
		e := compareSemantic(t, []string{"tulip-moon"}, &requests)
		scorer := &compareTestScorer{action: func([]mlscore.Record) ([]mlscore.Result, error) {
			switch mode {
			case "error":
				return nil, errors.New("owned-private-model-detail")
			case "panic":
				panic("owned-private-model-detail")
			case "partial":
				return nil, nil
			default:
				return []mlscore.Result{{Score: math.NaN()}}, nil
			}
		}}
		p := New(Options{Detector: detector(t), Semantic: true, SemanticEngine: e, ML: scorer})
		result, err := p.Compare(context.Background(), func(context.Context) (<-chan model.Item, error) {
			return feed(model.Item{Source: "code", Path: "production.txt", Text: "Archive access code: tulip-moon"}), nil
		})
		if err == nil || strings.Contains(err.Error(), "private") || len(result.Raw) != 0 || len(result.Kept) != 0 {
			t.Fatalf("invalid ML comparison escaped: %s %v", mode, err)
		}
	}
}

func TestComparisonBudgetsAndInputErrorsCancelAcquisition(t *testing.T) {
	for _, mode := range []string{"rows", "bytes", "source"} {
		scorer := &compareTestScorer{action: func(r []mlscore.Record) ([]mlscore.Result, error) {
			out := make([]mlscore.Result, len(r))
			for i := range out {
				out[i].Score = 1
			}
			return out, nil
		}}
		p := New(Options{Detector: detector(t), ML: scorer, Workers: 1})
		stopped := make(chan struct{})
		rows, bytes := 100, 1<<20
		if mode == "rows" {
			rows = 1
		}
		if mode == "bytes" {
			bytes = 1
		}
		_, err := p.compare(context.Background(), func(ctx context.Context) (<-chan model.Item, error) {
			ch := make(chan model.Item)
			go func() {
				defer close(stopped)
				defer close(ch)
				it := model.Item{Source: "code", Path: "production.env", Text: "AWS=AKIANAFGYOEYPXU1DSYP"}
				if mode == "source" {
					it.Error = errors.New("source unavailable")
				}
				select {
				case ch <- it:
				case <-ctx.Done():
				}
				<-ctx.Done()
			}()
			return ch, nil
		}, rows, bytes)
		if err == nil {
			t.Fatal("incomplete comparison accepted")
		}
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Fatal("comparison left acquisition running")
		}
	}
}

func TestComparisonPreflightRejectsInvalidScorersBeforeInput(t *testing.T) {
	for _, scorer := range []mlscore.Scorer{nil, fixedMLScorer{threshold: math.NaN()}, mlscore.New("http://127.0.0.1:9/score", .5)} {
		called := false
		_, err := New(Options{ML: scorer}).Compare(context.Background(), func(context.Context) (<-chan model.Item, error) { called = true; return feed(), nil })
		if err == nil || called {
			t.Fatal("comparison acquired input before valid local ML")
		}
	}
}

func TestComparisonProjectionRetainsReportFilterMetadata(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := comparisonPool{ctx: ctx, cancel: cancel, maxRows: 2, maxBytes: 8192}
	f := model.Finding{Type: "aws_access_key_id", Severity: "high", Confidence: .91, Stage: "l1"}
	if !pool.capture([]model.Finding{f}, true) || !pool.capture([]model.Finding{f}, false) {
		t.Fatal("capture failed")
	}
	for _, got := range []model.Finding{pool.result.Raw[0], pool.result.Kept[0]} {
		if got.Severity != f.Severity || got.Confidence != f.Confidence || got.Stage != f.Stage {
			t.Fatalf("filter metadata lost: %+v", got)
		}
	}
}
