package scan

import (
	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/verify"
)

// Options groups one scan's dependencies and privacy policy. Dependency objects
// and the allow callback must be safe for concurrent reads after construction.
type Options struct {
	Detector      *detect.Detector
	Rules         *rules.Engine
	Verifiers     *verify.Set
	ML            mlscore.Scorer
	Allow         func(value, path string) bool
	Workers       int
	RevealSecrets bool
	// IgnorePragmas is for untrusted in-flight payloads which cannot grant themselves exceptions.
	IgnorePragmas bool
	// ValueFingerprint is optional and must be safe for concurrent calls. It
	// receives a raw value in memory, before redaction, but must never retain it.
	ValueFingerprint    func(string) string
	LocationFingerprint func(source, path string, line, col int) string
	// ObserveVerification receives only sanitized keyed evidence, before ML can
	// suppress a provider-rejected credential. The callback must be concurrency-safe.
	ObserveVerification func(model.Finding)
}

// Pipeline is an immutable scan configuration. A pipeline can be shared between
// requests and worker pools; constructing another pipeline cannot change it.
type Pipeline struct{ options Options }

// New takes a value snapshot of options, including the disclosure policy.
func New(options Options) *Pipeline { return &Pipeline{options: options} }

// WithRevealSecrets returns a separate configuration sharing only the read-only
// dependencies. It never changes an existing or currently running scan.
func (p *Pipeline) WithRevealSecrets(reveal bool) *Pipeline {
	options := p.options
	options.RevealSecrets = reveal
	return New(options)
}
