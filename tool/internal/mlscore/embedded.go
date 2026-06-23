package mlscore

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/Lercas/prowl/tool/internal/mlfeatures"
	"github.com/Lercas/prowl/tool/internal/mlmodel"
)

// Scorer is the L2 secret/not-secret stage: it scores a batch of candidates. Two implementations
// exist — Embedded (the model compiled into this binary) and Client (an external sidecar). The
// scan pipeline depends on this interface so --ml and --ml-url are interchangeable.
type Scorer interface {
	Score(ctx context.Context, recs []Record) ([]Result, error)
	Threshold() float64
}

// Embedded runs the dumped HGB model in-process via internal/mlmodel + internal/mlfeatures. No
// Python, no sidecar, no network — the candidate values never leave the process.
type Embedded struct {
	model     *mlmodel.Model
	threshold float64
}

// NewEmbedded builds an in-process scorer, resolving which model to load (see resolveModel).
// threshold is the score below which a non-checksum candidate is treated as not-a-secret.
//
// It refuses on a nocgo build: the compression_ratio feature only matches the trained model under the
// cgo (system-zlib) path, so a nocgo binary would score secrets DIFFERENTLY from the validated model
// — fail closed with a clear message rather than ship a silently-divergent scorer. The cascade, rule
// templates, and live verification are unaffected; --ml-url (the sidecar) is the nocgo alternative.
func NewEmbedded(threshold float64, modelPath string) (*Embedded, error) {
	if !mlfeatures.BuiltWithCgo() {
		return nil, errors.New("--ml: the in-process model needs a cgo build for feature parity with " +
			"the trained model (compression_ratio uses the system zlib); this binary was built without " +
			"cgo. Rebuild with CGO_ENABLED=1 (the default for `go install`/`make build`), or use --ml-url")
	}
	m, err := resolveModel(modelPath)
	if err != nil {
		return nil, err
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
		if _, err := os.Stat(p); err == nil {
			return mlmodel.LoadFile(p)
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

// Score returns one Result per record (same order), computing features + model probability inline.
func (e *Embedded) Score(_ context.Context, recs []Record) ([]Result, error) {
	out := make([]Result, len(recs))
	for i, r := range recs {
		f := mlfeatures.Extract(r.Value, mlfeatures.Context{
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
