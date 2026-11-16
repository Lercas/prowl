package detect

import (
	"sync"
	"sync/atomic"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

// Tuning is one scan's immutable detection thresholds and combined candidate cap.
type Tuning struct {
	GenericEntropyMin         float64
	WeakPlaceholderMaxEntropy float64
	MaxMatches                int
}

func DefaultTuning() Tuning { return Tuning{3.5, 4.2, 50000} }

// With preserves zero/negative-as-unspecified compatibility without inheriting
// another caller's configuration when starting from DefaultTuning().
func (t Tuning) With(entropy, placeholder float64, maxMatches int) Tuning {
	if entropy > 0 {
		t.GenericEntropyMin = entropy
	}
	if placeholder > 0 {
		t.WeakPlaceholderMaxEntropy = placeholder
	}
	if maxMatches > 0 {
		t.MaxMatches = maxMatches
	}
	return t
}

var (
	tuningMu     sync.Mutex
	legacyTuning atomic.Pointer[Tuning]
)

func init()                 { t := DefaultTuning(); legacyTuning.Store(&t) }
func currentTuning() Tuning { return *legacyTuning.Load() }

// ApplyTuning updates only legacy direct-detector defaults. Existing snapshots
// and Pipelines remain unchanged. Production constructors use explicit Tuning.
func ApplyTuning(entropy, placeholder float64, maxMatches int) {
	tuningMu.Lock()
	defer tuningMu.Unlock()
	t := currentTuning().With(entropy, placeholder, maxMatches)
	legacyTuning.Store(&t)
}

// Tuning reports effective values; legacy direct Detector scans snapshot them on entry.
func (d *Detector) Tuning() Tuning {
	if d == nil {
		return DefaultTuning()
	}
	if d.frozen {
		return d.settings
	}
	return currentTuning()
}

// Snapshot shares only the immutable engine and concurrency-safe pools. No lock
// or process-wide swap is needed while another detector is scanning.
func (d *Detector) Snapshot() *Detector {
	if d == nil || d.frozen {
		return d
	}
	return &Detector{detectorCore: d.detectorCore, settings: d.Tuning(), frozen: true}
}
func NewWithTuning(tax *taxonomy.Taxonomy, t Tuning) *Detector {
	d := New(tax)
	return &Detector{detectorCore: d.detectorCore, settings: DefaultTuning().With(t.GenericEntropyMin, t.WeakPlaceholderMaxEntropy, t.MaxMatches), frozen: true}
}
func (d *Detector) MaxScanMatches() int { return d.Tuning().MaxMatches }
func (d *Detector) IsExampleOrPlaceholder(value string) bool {
	return d.Tuning().IsExampleOrPlaceholder(value)
}
