package scan

import (
	"context"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/semantic"
	"github.com/Lercas/prowl/tool/internal/verify"
)

// PublicAuditor accepts already-bound values; implementations must be safe for concurrent calls.
// A nil result denotes an inapplicable provider/configuration, never a successful audit.
type PublicAuditor interface {
	Audit(context.Context, string, string, map[string]string) *model.PublicKeyAudit
}

// Options groups one scan's dependencies and privacy policy. Dependency objects
// and the allow callback must be safe for concurrent reads after construction.
type Options struct {
	Semantic       bool
	SemanticEngine *semantic.Engine
	Detector       *detect.Detector
	Rules          *rules.Engine
	PublicAuditor  PublicAuditor
	Verifiers      *verify.Set
	VerifyAll      bool // verify before ML; observers also retain this mode for index evidence
	CrossFile      bool // opt-in bounded current-acquisition component assembly
	ML             mlscore.Scorer
	Allow          func(value, path string) bool
	Workers        int
	RevealSecrets  bool
	// IdentityKey scopes the released report identities; it is independent of the local index.
	IdentityKey []byte
	// Reconstruct enables bounded static string reconstruction for JS/TS sources.
	Reconstruct bool
	// AllOccurrences retains distinct spans of repeated values for editor diagnostics.
	AllOccurrences bool
	// reconstruction maps a child scan to its original expression before observers.
	publicBindings  *publicBindings
	reconstruction  *reconstructionOrigin
	matchLimit      int
	beforeML        func([]model.Finding) bool
	resultSink      func([]model.Finding)
	candidateBudget *int
	components      *componentBatch
	// IgnorePragmas is for untrusted in-flight payloads which cannot grant themselves exceptions.
	IgnorePragmas bool
	// ValueFingerprint is optional and must be safe for concurrent calls. It
	// receives a raw value in memory, before redaction, but must never retain it.
	ValueFingerprint    func(string) string
	LocationFingerprint func(source, path string, line, col int) string
	// ComponentLocationFingerprint maps a raw keyed location into an optional
	// persistent acquisition namespace, without changing ordinary index inputs.
	ComponentLocationFingerprint func(string) string
	// ObserveVerification receives only sanitized keyed evidence, before ML can
	// suppress a provider-rejected credential. The callback must be concurrency-safe.
	ObserveVerification func(model.Finding)
}

// Pipeline is an immutable scan configuration. A pipeline can be shared between
// requests and worker pools; constructing another pipeline cannot change it.
type Pipeline struct{ options Options }

// New takes a value snapshot of options, including the disclosure policy.
func New(options Options) *Pipeline {
	options.IdentityKey = append([]byte(nil), options.IdentityKey...)
	return &Pipeline{options: options}
}

// WithRevealSecrets returns a separate configuration sharing only the read-only
// dependencies. It never changes an existing or currently running scan.
func (p *Pipeline) WithRevealSecrets(reveal bool) *Pipeline {
	options := p.options
	options.RevealSecrets = reveal
	return New(options)
}
