package scan

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
)

const (
	compareMaxRows  = 100000
	compareMaxBytes = 32 << 20
)

// Comparison contains display projections of one candidate pass before and after local L2.
// It carries no raw scoring records, contexts, source bodies or provider verdicts.
type Comparison struct{ Raw, Kept []model.Finding }

type comparisonPool struct {
	mu                sync.Mutex
	result            Comparison
	bytes, rows       int
	maxRows, maxBytes int
	failed            bool
	ctx               context.Context
	cancel            context.CancelFunc
}

func (c *comparisonPool) fail() {
	if c.failed {
		return
	}
	c.failed = true
	model.Note(c.ctx, "comparison_incomplete", "compare", true)
	c.cancel()
}

func (c *comparisonPool) capture(batch []model.Finding, raw bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed {
		return false
	}
	for _, finding := range batch {
		if model.IsIncompleteFinding(finding) {
			c.fail()
			return false
		}
		// Include conservative struct/string-allocation overhead without marshaling large batches.
		n := 1024 + len(finding.Type) + len(finding.Source) + len(finding.Path) + len(finding.Redacted) + len(finding.Fingerprint) + len(finding.Severity) + len(finding.Stage)
		if c.rows >= c.maxRows || n > c.maxBytes-c.bytes {
			c.fail()
			return false
		}
		c.rows++
		c.bytes += n
		projected := model.Finding{Type: strings.Clone(finding.Type), Severity: strings.Clone(finding.Severity), Confidence: finding.Confidence, Stage: strings.Clone(finding.Stage), Source: strings.Clone(finding.Source), Path: strings.Clone(finding.Path), Redacted: strings.Clone(finding.Redacted), Fingerprint: strings.Clone(finding.Fingerprint), Line: finding.Line, Col: finding.Col, ByteStart: finding.ByteStart, ByteEnd: finding.ByteEnd}
		if raw {
			c.result.Raw = append(c.result.Raw, projected)
		} else {
			c.result.Kept = append(c.result.Kept, projected)
		}
	}
	return true
}

type comparisonScorer struct {
	scorer    mlscore.Scorer
	threshold float64
	pool      *comparisonPool
}

func (s comparisonScorer) PolicyID() string {
	if scorer, ok := s.scorer.(interface{ PolicyID() string }); ok {
		return scorer.PolicyID()
	}
	return ""
}

func (s comparisonScorer) Local() bool        { return true }
func (s comparisonScorer) Threshold() float64 { return s.threshold }
func (s comparisonScorer) Score(ctx context.Context, records []mlscore.Record) (results []mlscore.Result, err error) {
	defer func() {
		if recover() != nil {
			s.pool.mu.Lock()
			s.pool.fail()
			s.pool.mu.Unlock()
			results, err = nil, errors.New("comparison ML scoring failed")
		}
	}()
	results, err = s.scorer.Score(ctx, records)
	valid := err == nil && len(results) == len(records)
	for _, result := range results {
		valid = valid && mlscore.ValidScore(result.Score)
	}
	if !valid {
		s.pool.mu.Lock()
		s.pool.fail()
		s.pool.mu.Unlock()
		return nil, errors.New("comparison ML scoring failed")
	}
	return results, nil
}

// Compare acquires input exactly once and observes the candidate batch immediately before L2.
// The factory and workers share a cancellable context so limits/errors stop acquisition too.
// Callers must reject results when err is non-nil. Verification and index side effects are excluded.
func (p *Pipeline) Compare(ctx context.Context, input func(context.Context) (<-chan model.Item, error)) (Comparison, error) {
	return p.compare(ctx, input, compareMaxRows, compareMaxBytes)
}

func (p *Pipeline) compare(ctx context.Context, input func(context.Context) (<-chan model.Item, error), maxRows, maxBytes int) (Comparison, error) {
	if input == nil || p.options.ML == nil || !p.options.ML.Local() {
		return Comparison{}, errors.New("compare requires a local in-process ML model and an input source")
	}
	threshold := p.options.ML.Threshold()
	if !mlscore.ValidScore(threshold) {
		return Comparison{}, errors.New("compare requires a valid ML threshold")
	}
	if p.options.Verifiers != nil || p.options.ObserveVerification != nil || p.options.ValueFingerprint != nil || p.options.LocationFingerprint != nil {
		return Comparison{}, errors.New("compare does not support verification or index side effects")
	}
	if model.CoverageFrom(ctx) == nil {
		ctx = model.WithCoverage(ctx, model.NewCoverage())
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	pool := &comparisonPool{ctx: ctx, cancel: cancel, maxRows: maxRows, maxBytes: maxBytes}
	options := p.options
	options.beforeML = func(batch []model.Finding) bool { return pool.capture(batch, true) }
	options.resultSink = func(batch []model.Finding) { pool.capture(batch, false) }
	options.ML = comparisonScorer{p.options.ML, threshold, pool}
	items, err := input(ctx)
	if err != nil {
		return Comparison{}, err
	}
	if items == nil {
		return Comparison{}, errors.New("comparison source returned no stream")
	}
	New(options).Run(ctx, items)
	complete, _, _ := model.CoverageFrom(ctx).Snapshot()
	if ctx.Err() != nil || pool.failed || !complete {
		return Comparison{}, errors.New("comparison is incomplete; no suppression percentage is available")
	}
	return pool.result, nil
}
