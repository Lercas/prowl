package model

import (
	"sync"
	"sync/atomic"
	"time"
)

// GitCommit describes provenance without copying commit messages or author email.
type GitCommit struct {
	Hash        string    `json:"hash"`
	Parents     []string  `json:"parents,omitempty"`
	Author      string    `json:"author"`
	AuthoredAt  time.Time `json:"authored_at"`
	CommittedAt time.Time `json:"committed_at"`
}

type GitRemoval struct {
	Commit          GitCommit `json:"commit"`
	IntroducedIn    string    `json:"introduced_in"`
	ExposureSeconds *int64    `json:"exposure_seconds,omitempty"`
}

// GitTimeline is detection history at one report path. Edges use the first
// parent; commits on all reachable branches are included, not sorted by dates.
type GitTimeline struct {
	Complete    bool         `json:"complete"`
	Basis       string       `json:"basis"`
	Head        string       `json:"head"`
	InHEAD      *bool        `json:"in_head,omitempty"`
	Appearances []GitCommit  `json:"appearances"`
	Removals    []GitRemoval `json:"removals"`
}

// GitHistoryGraph is immutable after acquisition except for the concurrent
// inspection set populated by scan workers. It never contains source content.
type GitHistoryGraph struct {
	ObservationCount   atomic.Int64
	ObservationLimited atomic.Bool
	Observations       sync.Map // GitObservation -> bool, before display/ML suppression
	Head               string
	Complete           bool
	Commits            []GitCommit                  // parents before children
	Changes            map[string]map[string]string // commit -> path -> new blob; empty blob means deletion
	Inspected          sync.Map                     // GitObject -> bool; only complete literal-text snapshots
}

type GitObject struct{ Path, Blob string }

type GitRecord struct {
	DisplayPath string // physical blob root in the caller's report namespace
	Graph       *GitHistoryGraph
	Object      GitObject
}

type GitObservation struct {
	Fingerprint string
	Object      GitObject
}
