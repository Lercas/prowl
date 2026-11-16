package main

import (
	"context"
	"time"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/publicaudit"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/secretindex"
)

// preparedScan keeps the immutable execution pipeline together with one CLI
// invocation's reporting policy. Copies can safely serve separate source streams.
type preparedScan struct {
	flags      commonFlags
	pipeline   *scan.Pipeline
	mlError    error
	auditError error
	indexError error
	dedupe     bool
	finalizers []func([]model.Finding) []model.Finding
}

func prepareScan(flags commonFlags, options scan.Options) preparedScan {
	flags.coverage.SetIdentityScope(flags.identityKey)
	if flags.showSecrets {
		flags.coverage.RevealSecrets()
	}
	flags.coverage.RegisterScope("pipeline", "1.5", map[string]any{"version": version, "detection_revision": scan.DetectionRevision, "ml": flags.mlEmbed || flags.mlURL != "", "ml_model": flags.mlModel,
		"ml_url": flags.mlURL, "ml_threshold": flags.mlThreshold, "verify": flags.verify, "verify_all": flags.verifyAll || flags.failOnVerified,
		"index": flags.indexDir != "", "reconstruct": flags.reconstruct, "semantic": flags.semantic, "disable": flags.disable, "rules_only": flags.rulesOnly, "bundled": flags.bundled, "max_per_file": flags.maxPerFile})
	ml, err := flags.mlScorer()
	options.ML, options.Workers, options.RevealSecrets = ml, flags.workers, flags.showSecrets
	options.IgnorePragmas = flags.noAutoPolicy
	options.IdentityKey = flags.identityKey
	options.Reconstruct = flags.reconstruct
	options.Semantic, options.SemanticEngine = flags.semantic, flags.semanticEngine
	options.VerifyAll = flags.verifyAll || flags.failOnVerified
	options.CrossFile = flags.crossFile
	if flags.crossFile {
		flags.coverage.RegisterScope("components", "local-filesystem", map[string]any{"revision": "cross-file-namespaces-v2", "max_items": 10000, "max_bytes": 32 << 20, "max_literals": 100000})
	}
	var auditErr error
	if flags.auditPublic {
		// Parsing has already validated the immutable collection selection.
		options.PublicAuditor, auditErr = publicaudit.NewWithTargets(flags.timeout, flags.auditCollections, flags.auditTables)
	}
	var indexErr error
	if flags.indexDir != "" {
		indexErr = validateIndexOutputs(flags)
	}
	if flags.indexDir != "" && indexErr == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		store, openErr := secretindex.Open(ctx, flags.indexDir, false)
		if openErr != nil {
			indexErr = openErr
		} else {
			options.ValueFingerprint = store.Identity().Fingerprint
			options.LocationFingerprint = store.Identity().Location
			if flags.crossFile {
				identity := store.Identity()
				options.ComponentLocationFingerprint = func(raw string) string { return identity.Location("prowl:scope:"+flags.indexScope, raw, 0, 0) }
			}
			if flags.indexEvidence == nil {
				flags.indexEvidence = &indexEvidence{}
			}
			options.ObserveVerification = flags.indexEvidence.add
			indexErr = store.Close()
		}
		cancel()
	}
	return preparedScan{flags: flags, pipeline: scan.New(options), mlError: err, auditError: auditErr, indexError: indexErr, dedupe: flags.dedupe}
}

func (p preparedScan) WithFinalizer(finalize func([]model.Finding) []model.Finding) preparedScan {
	p.finalizers = append(append([]func([]model.Finding) []model.Finding(nil), p.finalizers...), finalize)
	return p
}

// Collect preserves diagnostics when ML setup failed: a partial L1 scan must not
// look like a complete ML-filtered scan to reports, gates or baseline writers.
func (p preparedScan) Collect(ctx context.Context, items <-chan model.Item) []model.Finding {
	if p.auditError != nil {
		logx.Error("public audit setup failed", "err", p.auditError)
		return []model.Finding{{Detector: "scan", Type: "response_truncated", Severity: "info", Path: "scan", Stage: "public audit setup", Rationale: "the requested public audit was not prepared; scan did not run"}}
	}
	if p.indexError != nil {
		logx.Error("index setup failed", "err", p.indexError)
		return []model.Finding{{Detector: "scan", Type: "response_truncated", Severity: "info", Path: "index", Stage: "index setup", Rationale: "the local index is unavailable; the scan did not run"}}
	}
	items, done := scanProgress(ctx, p.flags, items)
	findings := p.pipeline.Run(ctx, items)
	done()
	if p.mlError != nil {
		logx.Error("ML setup failed; scan results are incomplete", "err", p.mlError)
		findings = append(findings, model.Finding{Detector: "scan", Type: "response_truncated", Severity: "info",
			Path: "scan", Stage: "ML setup", Rationale: "requested ML model was not prepared; scan results are incomplete"})
	}
	if p.flags.gitTimeline {
		findings = scan.FinalizeGitTimeline(findings)
	}
	if p.flags.verifiedOnly && p.flags.indexDir == "" {
		findings = keepVerifiedWithCoverage(p.flags, findings)
	}
	if p.dedupe && p.flags.indexDir == "" {
		findings = dedupeFingerprints(findings)
	}
	if p.flags.indexDir != "" {
		return findings
	}
	return capWithCoverage(p.flags, findings)
}

func (p preparedScan) Run(ctx context.Context, items <-chan model.Item) int {
	start := time.Now()
	collect := p
	if len(p.finalizers) > 0 {
		// Image provenance must be known before choosing duplicates and occurrence caps.
		collect.flags.maxPerFile = 0
		collect.dedupe = false
	}
	findings := collect.Collect(ctx, items)
	for _, finalize := range p.finalizers {
		findings = finalize(findings)
	}
	if len(p.finalizers) > 0 && p.flags.indexDir == "" {
		if p.dedupe {
			findings = dedupeFingerprints(findings)
		}
		findings = capWithCoverage(p.flags, findings)
	}
	return reportScan(ctx, p.flags, findings, time.Since(start))
}
