package main

import (
	"context"
	"time"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/secretindex"
)

// preparedScan keeps the immutable execution pipeline together with one CLI
// invocation's reporting policy. Copies can safely serve separate source streams.
type preparedScan struct {
	flags      commonFlags
	pipeline   *scan.Pipeline
	mlError    error
	indexError error
	dedupe     bool
	finalizers []func([]model.Finding) []model.Finding
}

func prepareScan(flags commonFlags, options scan.Options) preparedScan {
	ml, err := flags.mlScorer()
	options.ML, options.Workers, options.RevealSecrets = ml, flags.workers, flags.showSecrets
	options.IgnorePragmas = flags.noAutoPolicy
	options.IdentityKey = flags.identityKey
	options.Reconstruct = flags.reconstruct
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
			if flags.indexEvidence == nil {
				flags.indexEvidence = &indexEvidence{}
			}
			options.ObserveVerification = flags.indexEvidence.add
			indexErr = store.Close()
		}
		cancel()
	}
	return preparedScan{flags: flags, pipeline: scan.New(options), mlError: err, indexError: indexErr, dedupe: flags.dedupe}
}

func (p preparedScan) WithFinalizer(finalize func([]model.Finding) []model.Finding) preparedScan {
	p.finalizers = append(append([]func([]model.Finding) []model.Finding(nil), p.finalizers...), finalize)
	return p
}

// Collect preserves diagnostics when ML setup failed: a partial L1 scan must not
// look like a complete ML-filtered scan to reports, gates or baseline writers.
func (p preparedScan) Collect(ctx context.Context, items <-chan model.Item) []model.Finding {
	if p.indexError != nil {
		logx.Error("подготовка индекса не удалась", "err", p.indexError)
		return []model.Finding{{Detector: "scan", Type: "response_truncated", Severity: "info", Path: "index", Stage: "index setup", Rationale: "локальный индекс недоступен; скан не выполнен"}}
	}
	findings := p.pipeline.Run(ctx, items)
	if p.mlError != nil {
		logx.Error("ML setup failed; scan results are incomplete", "err", p.mlError)
		findings = append(findings, model.Finding{Detector: "scan", Type: "response_truncated", Severity: "info",
			Path: "scan", Stage: "ML setup", Rationale: "requested ML model was not prepared; scan results are incomplete"})
	}
	if p.flags.gitTimeline {
		findings = scan.FinalizeGitTimeline(findings)
	}
	if p.flags.verifiedOnly && p.flags.indexDir == "" {
		findings = keepVerified(findings)
	}
	if p.dedupe && p.flags.indexDir == "" {
		findings = dedupeFingerprints(findings)
	}
	if p.flags.indexDir != "" {
		return findings
	}
	return capGenericPerFile(findings, p.flags.maxPerFile)
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
		findings = capGenericPerFile(findings, p.flags.maxPerFile)
	}
	return reportScan(ctx, p.flags, findings, time.Since(start))
}
