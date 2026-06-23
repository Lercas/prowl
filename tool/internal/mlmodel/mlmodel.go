// Package mlmodel is an in-process Go evaluator for the dumped sklearn
// HistGradientBoostingClassifier backing Prowl's L2 secret-detection stage. The
// model (a baseline plus an ordered list of regression trees) is exported from
// Python as model_binary.json and embedded via go:embed, so the same classifier
// runs inside the single Go binary with no external file.
//
// For a 49-element feature vector x, the raw score is baseline + sum of every
// tree's leaf value and the probability is logistic(raw); this matches the Python
// reference to ~4.4e-16 (validated row-for-row by the package test).
package mlmodel

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
)

// NumFeatures is the fixed feature-vector length Predict expects, matching
// len(feature_names) in the dumped model.
const NumFeatures = 49

// embedded holds the model baked into the binary (default build) or nil (lean
// -tags noml_embed build); declared in mlmodel_embed.go / mlmodel_noembed.go.

// rawModel mirrors the on-disk JSON layout, used only while loading.
type rawModel struct {
	Baseline     float64   `json:"baseline"`
	FeatureNames []string  `json:"feature_names"`
	Trees        []rawTree `json:"trees"`
}

// rawTree is one tree as parallel slices over a flat node array (index 0 = root).
type rawTree struct {
	FeatureIdx  []int     `json:"feature_idx"`
	Threshold   []float64 `json:"threshold"`
	Left        []int     `json:"left"`
	Right       []int     `json:"right"`
	Value       []float64 `json:"value"`
	MissingLeft []int     `json:"missing_left"`
	IsLeaf      []int     `json:"is_leaf"`
}

// Model is the parsed, inference-ready classifier. All trees are flattened into
// contiguous slices indexed by a global node id, so Predict walks cache-friendly
// arrays and allocates nothing.
type Model struct {
	baseline     float64
	featureNames []string

	// treeStart[t] is the global node index of tree t's root.
	treeStart []int32

	// Per-node parallel arrays, concatenated across all trees. left[i]/right[i]
	// are global child indices; for leaves they are unused and value[i] is the
	// leaf output. flags packs bit0 = is_leaf, bit1 = missing_left.
	featIdx []int32
	thresh  []float64
	left    []int32
	right   []int32
	value   []float64
	flags   []uint8
}

const (
	flagLeaf        uint8 = 1 << 0 // node is a leaf; value[i] is its output
	flagMissingLeft uint8 = 1 << 1 // on NaN feature, descend to the left child
)

// ErrNoEmbedded is returned by Load on a lean build (-tags noml_embed) with no
// embedded model.
var ErrNoEmbedded = errors.New("mlmodel: no model embedded in this build — pass --ml-model PATH or install ~/.prowl/model_binary.json")

// Load parses the embedded model into an inference-ready Model, or returns
// ErrNoEmbedded on a lean build (use LoadFile for an external model).
func Load() (*Model, error) {
	if len(embedded) == 0 {
		return nil, ErrNoEmbedded
	}
	return parse(embedded)
}

// LoadFile parses a dumped model_binary.json from disk, so the model can ship
// beside the binary and be refreshed without a rebuild.
func LoadFile(path string) (*Model, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mlmodel: read %s: %w", path, err)
	}
	return parse(data)
}

// parse turns the dumped JSON into an inference-ready Model. It is expensive
// (~1MB JSON + flattening 400 trees), so callers should cache the result (see Default).
func parse(data []byte) (*Model, error) {
	var rm rawModel
	if err := json.Unmarshal(data, &rm); err != nil {
		return nil, fmt.Errorf("mlmodel: parse model: %w", err)
	}
	if got := len(rm.FeatureNames); got != NumFeatures {
		return nil, fmt.Errorf("mlmodel: model has %d feature names, want %d", got, NumFeatures)
	}
	if len(rm.Trees) == 0 {
		return nil, fmt.Errorf("mlmodel: model has no trees")
	}

	// First pass: count nodes so the flat slices are allocated exactly once.
	total := 0
	for ti := range rm.Trees {
		t := &rm.Trees[ti]
		n := len(t.IsLeaf)
		if n == 0 {
			return nil, fmt.Errorf("mlmodel: tree %d has no nodes", ti)
		}
		// Every parallel slice must agree in length, else the dump is malformed.
		if len(t.FeatureIdx) != n || len(t.Threshold) != n || len(t.Left) != n ||
			len(t.Right) != n || len(t.Value) != n || len(t.MissingLeft) != n {
			return nil, fmt.Errorf("mlmodel: tree %d has ragged node arrays", ti)
		}
		total += n
	}

	m := &Model{
		baseline:     rm.Baseline,
		featureNames: rm.FeatureNames,
		treeStart:    make([]int32, len(rm.Trees)),
		featIdx:      make([]int32, total),
		thresh:       make([]float64, total),
		left:         make([]int32, total),
		right:        make([]int32, total),
		value:        make([]float64, total),
		flags:        make([]uint8, total),
	}

	// Second pass: flatten. Child indices in the dump are tree-local, so add the
	// tree's base offset to make them global node ids.
	base := int32(0)
	for ti := range rm.Trees {
		t := &rm.Trees[ti]
		m.treeStart[ti] = base
		for i := range t.IsLeaf {
			g := base + int32(i)
			if fi := t.FeatureIdx[i]; fi >= 0 && fi < NumFeatures {
				m.featIdx[g] = int32(fi)
			} else if t.IsLeaf[i] == 0 {
				// Only internal nodes index into x; leaves carry a dummy idx.
				return nil, fmt.Errorf("mlmodel: tree %d node %d feature_idx %d out of range", ti, i, fi)
			}
			m.thresh[g] = t.Threshold[i]
			m.value[g] = t.Value[i]

			var f uint8
			if t.IsLeaf[i] != 0 {
				f |= flagLeaf
			} else {
				// Validate child indices for internal nodes only.
				l, r := t.Left[i], t.Right[i]
				if l < 0 || l >= len(t.IsLeaf) || r < 0 || r >= len(t.IsLeaf) {
					return nil, fmt.Errorf("mlmodel: tree %d node %d child index out of range", ti, i)
				}
				m.left[g] = base + int32(l)
				m.right[g] = base + int32(r)
			}
			if t.MissingLeft[i] != 0 {
				f |= flagMissingLeft
			}
			m.flags[g] = f
		}
		base += int32(len(t.IsLeaf))
	}

	return m, nil
}

// FeatureNames returns the model's ordered feature names so callers can assert
// their extractor matches. The slice is shared; do not mutate it.
func (m *Model) FeatureNames() []string { return m.featureNames }

// ErrCyclicModel is returned by Predict when a tree walk exceeds the node-count
// bound, meaning a child index points back at an ancestor (a cycle a crafted or
// corrupt model can encode). The bounded walk fails closed instead of hanging.
var ErrCyclicModel = errors.New("mlmodel: cyclic tree (child index revisits an ancestor) — model is malformed")

// Predict returns the L2 probability for one feature vector: logistic(baseline +
// sum of every tree's leaf value). x must have exactly NumFeatures (49) elements
// in feature_names order; a NaN routes by each node's missing_left flag. It
// allocates nothing, is safe for concurrent use, and returns ErrCyclicModel on a
// malformed (cyclic) tree.
func (m *Model) Predict(x []float64) (float64, error) {
	if len(x) != NumFeatures {
		return 0, fmt.Errorf("mlmodel: feature vector has %d elements, want %d", len(x), NumFeatures)
	}
	return m.predict(x)
}

// predict is the unchecked-length, allocation-free hot path; callers guarantee
// len(x) == NumFeatures. Each descent is bounded by the total node count (an
// upper bound on any tree's depth) so a cyclic malformed model returns
// ErrCyclicModel instead of spinning forever.
func (m *Model) predict(x []float64) (float64, error) {
	// Bind slices to locals so the compiler can hoist bounds checks out of the loop.
	featIdx := m.featIdx
	thresh := m.thresh
	left := m.left
	right := m.right
	value := m.value
	flags := m.flags

	// maxSteps caps a single descent: total node count strictly exceeds any
	// acyclic tree's depth, so only a cyclic walk reaches it.
	maxSteps := len(flags)

	sum := m.baseline
	for _, root := range m.treeStart {
		i := root
		steps := 0
		for flags[i]&flagLeaf == 0 {
			if steps >= maxSteps {
				return 0, ErrCyclicModel
			}
			steps++
			xv := x[featIdx[i]]
			// Go left if xv <= threshold; for NaN (xv != xv) follow missing_left.
			if xv <= thresh[i] || (xv != xv && flags[i]&flagMissingLeft != 0) {
				i = left[i]
			} else {
				i = right[i]
			}
		}
		sum += value[i]
	}
	return 1.0 / (1.0 + math.Exp(-sum)), nil
}
