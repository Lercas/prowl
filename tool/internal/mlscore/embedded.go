package mlscore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Lercas/prowl/tool/internal/localfile"
	"github.com/Lercas/prowl/tool/internal/mlfeatures"
	"github.com/Lercas/prowl/tool/internal/mlmodel"
)

// Scorer is the L2 secret/not-secret stage: it scores a batch of candidates. Two implementations
// exist — Embedded (the model compiled into this binary) and Client (an external sidecar). The
// scan pipeline depends on this interface so --ml and --ml-url are interchangeable.
type Scorer interface {
	Score(ctx context.Context, recs []Record) ([]Result, error)
	Threshold() float64
	Local() bool // in-process scoring (no sidecar cap needed)
}

// Embedded runs the dumped HGB model in-process via internal/mlmodel + internal/mlfeatures. No
// Python, no sidecar, no network — the candidate values never leave the process.
type Embedded struct {
	model     *mlmodel.Model
	threshold float64
}

func (e *Embedded) PolicyID() string { return e.model.Digest() }

// NewEmbedded builds an in-process scorer, resolving which model to load (see resolveModel).
// threshold is the score below which a non-checksum candidate is treated as not-a-secret.
//
// Static binaries use a bounded embedded zlib module for the legacy feature contract.
func NewEmbedded(threshold float64, modelPath string) (*Embedded, error) {

	m, err := resolveModel(modelPath)
	if err != nil {
		return nil, err
	}
	if names := m.FeatureNames(); len(names) != len(mlfeatures.FeatureNames) {
		return nil, errors.New("ml: model feature count does not match the extractor")
	} else {
		for i, name := range names {
			if name != mlfeatures.FeatureNames[i] {
				return nil, fmt.Errorf("ml: model feature order does not match the extractor at index %d", i)
			}
		}
	}
	return &Embedded{model: m, threshold: threshold}, nil
}

// resolveModel picks the model in order: an explicit --ml-model path; else one installed at
// $PROWL_HOME/model_binary.json (default ~/.prowl — where the flywheel drops fresh models, so a
// retrain takes effect without rebuilding); else the model baked into the binary (default build).
func resolveModel(modelPath string) (*mlmodel.Model, error) {
	if modelPath != "" {
		return mlmodel.LoadFile(modelPath)
	}
	if p := externalModelPath(); p != "" {
		selected, err := localfile.FirstExisting(p)
		if err != nil {
			return nil, err
		}
		if selected != "" {
			return mlmodel.LoadFile(selected)
		}
	}
	return mlmodel.Default()
}

func externalModelPath() string {
	home := os.Getenv("PROWL_HOME")
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		home = filepath.Join(h, ".prowl")
	}
	return filepath.Join(home, "model_binary.json")
}

func (e *Embedded) Threshold() float64 { return e.threshold }

// WithThreshold shares the immutable prepared model while applying the caller's finalized
// configuration. It neither reloads files nor changes a scorer shared by other workers.
func (e *Embedded) WithThreshold(threshold float64) *Embedded {
	return &Embedded{model: e.model, threshold: threshold}
}

func (e *Embedded) Local() bool { return true }

// Score returns one Result per record (same order), computing features + model probability inline.
func (e *Embedded) Score(ctx context.Context, recs []Record) ([]Result, error) {
	out := make([]Result, len(recs))
	for i, r := range recs {
		if i&1023 == 0 && ctx.Err() != nil { // a flood of candidates is scored uncapped; stay cancellable
			return nil, ctx.Err()
		}
		extract := mlfeatures.Extract
		if e.model.Portable() {
			extract = mlfeatures.ExtractPortable
		}
		f := extract(r.Value, mlfeatures.Context{
			Name: r.Context.Name, Line: r.Context.Line, Path: r.Context.Path, Source: r.Context.Source,
		})
		p, err := e.model.Predict(f)
		if err != nil {
			return nil, err
		}
		out[i] = Result{Score: p, IsSecret: p >= 0.5}
	}
	return out, nil
}

// compile-time checks that both scorers satisfy the interface.
var (
	_ Scorer = (*Embedded)(nil)
	_ Scorer = (*Client)(nil)
)
