package main

import (
	"context"
	"io"
	"math"
	"os"
	"strings"
	"time"

	"github.com/Lercas/prowl/tool/internal/localfile"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/post"
	"github.com/Lercas/prowl/tool/internal/report"
)

// keepVerified drops findings that were not confirmed live (--verified-only).
func keepVerified(fs []model.Finding) []model.Finding {
	out := fs[:0]
	inconclusive, unverifiable := 0, 0
	for _, f := range fs {
		switch {
		case model.IsIncompleteFinding(f):
			out = append(out, f)
		case f.Verified != nil && *f.Verified: // provider-confirmed live
			out = append(out, f)
		case f.Verified == nil && strings.HasPrefix(f.Rationale, "verification inconclusive"):
			// the verifier errored (timeout/rate-limit/WAF) — keep a possibly-live secret rather than
			// turn a transient failure into a false-negative.
			inconclusive++
			out = append(out, f)
		case f.Verified == nil && model.SeverityOrder[f.Severity] >= model.SeverityOrder["high"]:
			// no verifier for this type — "couldn't check" is not "confirmed dead", so keep high/critical
			// (with a warning); low/medium unverifiable findings are still dropped for precision.
			unverifiable++
			out = append(out, f)
		}
		// else: provider-confirmed dead, or a low/medium finding with no verifier — dropped
	}
	if inconclusive > 0 {
		logx.Warn("verified-only kept findings whose verification was inconclusive (verifier errored, not confirmed dead)", "count", inconclusive)
	}
	if unverifiable > 0 {
		logx.Warn("verified-only kept high/critical findings with no verifier (could not be checked, not confirmed dead)", "count", unverifiable)
	}
	return out
}

// writeReport sends findings to the --output file or stdout. A write failure exits non-zero rather
// than leave an empty report CI would read as "clean".
func writeReport(c commonFlags, findings []model.Finding) error {
	if c.output != "" {
		if err := writeReportFile(c.output, findings, c.format); err != nil {
			logx.Error("cannot write output file", "path", c.output, "err", err)
			return err
		}
		logx.Info("report written", "findings", len(findings), "path", c.output)
		return nil
	}
	if c.silence && c.format == "pretty" {
		return nil // --silence suppresses the human report; an explicit --format json/sarif still writes for CI
	}
	color := !c.noColor && os.Getenv("NO_COLOR") == "" && isTTY(os.Stdout)
	if err := report.Write(os.Stdout, findings, c.format, color); err != nil {
		logx.Error("cannot write report to stdout", "err", err)
		return err
	}
	return nil
}

// writeReportFile commits a complete report without changing the previous inode on failure.
// Every report is private because --show-secrets can put full credential values into its output.
func writeReportFile(path string, findings []model.Finding, format string) error {
	return localfile.WriteAtomic(path, 0o600, func(w io.Writer) error {
		return report.Write(w, findings, format, false)
	})
}

// summarize logs a one-line scan summary grouped by severity (suppressed by --silence).
func summarize(findings []model.Finding, dur time.Duration) {
	bySev := map[string]int{}
	live, rejected, attempted := 0, 0, 0
	for _, f := range findings {
		bySev[f.Severity]++
		if f.Verified != nil {
			attempted++
			if *f.Verified {
				live++
			} else {
				rejected++
			}
		}
	}
	args := []any{
		"findings", len(findings), "critical", bySev["critical"], "high", bySev["high"],
		"medium", bySev["medium"], "low", bySev["low"], "took", dur.Round(time.Millisecond),
	}
	if attempted > 0 {
		args = append(args, "verified_live", live, "rejected", rejected)
	}
	logx.Info("scan complete", args...)
}

// capGenericPerFile bounds how many shape-only generic findings (generic_high_entropy /
// generic_password) one file may contribute — that many is a data/artifact file, not that many leaks.
// Specific detectors cap only at a much higher bound. The drop is logged; max<=0 disables it.
func capGenericPerFile(fs []model.Finding, max int) []model.Finding {
	if max <= 0 {
		return fs
	}
	const specificMult = 8 // specific detectors cap at max*mult to clip only an extreme flood
	specificLimit := math.MaxInt
	if max <= math.MaxInt/specificMult {
		specificLimit = max * specificMult
	}
	type key struct{ path, typ string }
	seen := map[key]int{}
	dropped := map[string]int{}
	out := fs[:0]
	for _, f := range fs {
		if model.IsIncompleteFinding(f) {
			out = append(out, f)
			continue
		}
		limit := specificLimit
		if f.Type == "generic_high_entropy" || f.Type == "generic_password" {
			limit = max
		}
		k := key{f.Path, f.Type}
		seen[k]++
		if seen[k] > limit {
			dropped[f.Path]++
			continue
		}
		out = append(out, f)
	}
	for path, n := range dropped {
		logx.Warn("capped findings per file — looks like a data/test/artifact file, not leaks",
			"path", path, "dropped", n, "flag", "--max-per-file")
	}
	return out
}

// reportFindings is the report stage: it logs the summary, writes/updates a baseline,
// emits the report, and returns the --fail-on exit code. Shared by scan/repo/image and org.
func reportFindings(c commonFlags, findings []model.Finding, elapsed time.Duration) int {
	return reportFindingsContext(context.Background(), c, findings, elapsed)
}

// reportScan carries lifecycle cancellation through suppression, baseline commit and the gate.
func reportScan(ctx context.Context, c commonFlags, findings []model.Finding, elapsed time.Duration) int {
	if c.indexDir != "" {
		if err := recordIndexedScan(ctx, c, findings); err != nil {
			logx.Error("запись индекса не удалась", "err", err)
			_ = writeReport(c, markInterrupted(ctx, findings))
			return 2
		}
		if c.verifiedOnly {
			findings = keepVerified(findings)
		}
		if c.dedupe {
			findings = dedupeFingerprints(findings)
		}
		findings = capGenericPerFile(findings, c.maxPerFile)
	}
	return failClosedIfIncomplete(ctx, reportFindingsContext(ctx, c, findings, elapsed))
}

func markInterrupted(ctx context.Context, findings []model.Finding) []model.Finding {
	if ctx.Err() == nil {
		return findings
	}
	for _, f := range findings {
		if model.IsIncompleteFinding(f) {
			return findings
		}
	}
	return append(findings, model.Finding{Detector: "scan", Type: "response_truncated", Severity: "info",
		Path: "scan", Stage: "post-processing", Rationale: "scan interrupted; results are incomplete"})
}

func reportFindingsContext(ctx context.Context, c commonFlags, findings []model.Finding, elapsed time.Duration) int {
	findings = markInterrupted(ctx, findings)
	findings = applyReportFilters(c, findings)
	summarize(findings, elapsed)

	if c.writeBaseline != "" {
		for _, f := range findings {
			if model.IsIncompleteFinding(f) {
				logx.Error("cannot write a baseline from an incomplete scan")
				_ = writeReport(c, findings) // the incomplete result already requires exit 2
				return 2
			}
		}
		if err := post.WriteBaselineContext(ctx, c.writeBaseline, findings); err != nil {
			logx.Error("baseline write failed", "err", err)
			if ctx.Err() != nil {
				_ = writeReport(c, markInterrupted(ctx, findings))
			}
			return 2
		}
		logx.Info("baseline written", "findings", len(findings), "path", c.writeBaseline)
		return 0
	}
	blPath := c.baseline
	if blPath == "" {
		var err error
		blPath, err = localfile.FirstExisting(".prowl-baseline.json")
		if err != nil {
			logx.Error("baseline discovery failed", "err", err)
			return 2
		}
	}
	var baseline *post.Baseline
	if blPath != "" {
		var err error
		baseline, err = post.LoadBaseline(blPath)
		if err != nil {
			logx.Error("baseline load failed", "path", blPath, "err", err)
			return 2
		}
	}
	ignorePath, err := localfile.FirstExisting(".gitleaksignore")
	if err != nil {
		logx.Error("gitleaksignore discovery failed", "err", err)
		return 2
	}
	var ignore *post.GitleaksIgnore
	if ignorePath != "" {
		ignore, err = post.LoadGitleaksIgnore(ignorePath)
		if err != nil {
			logx.Error("gitleaksignore load failed", "path", ignorePath, "err", err)
			return 2
		}
	}
	// Under --fail-on-verified, snapshot confirmed-live findings so an in-tree (possibly attacker-shipped)
	// baseline/.gitleaksignore can't suppress them past the gate; restore any that suppression drops.
	var liveGuard []model.Finding
	if c.failOnVerified {
		for _, f := range findings {
			if f.Verified != nil && *f.Verified {
				liveGuard = append(liveGuard, f)
			}
		}
	}
	if blPath != "" {
		before := len(findings)
		findings = baseline.Suppress(findings)
		if n := before - len(findings); n > 0 {
			logx.Warn("baseline suppressed findings", "count", n, "baseline", blPath)
		}
	}

	// Honor a gitleaks .gitleaksignore in the working dir, so a repo already triaged with gitleaks
	// keeps those exact findings suppressed under Prowl — zero-friction migration off gitleaks.
	if ignore != nil {
		before := len(findings)
		findings = ignore.Suppress(findings)
		if n := before - len(findings); n > 0 {
			logx.Warn("gitleaksignore suppressed findings", "count", n, "path", ".gitleaksignore")
		}
	}

	if c.failOnVerified {
		findings = restoreMissingLive(findings, liveGuard)
		escalateLive(findings)
	}
	findings = markInterrupted(ctx, findings)
	if err := writeReport(c, findings); err != nil {
		return 2
	}
	return gate(findings, c.failOn, c.failOnVerified)
}

// applyReportFilters drops findings hidden at report time: below --min-confidence, below
// --min-severity (built-ins included, unlike --rule-severity), or of a --disable'd detector type.
func applyReportFilters(c commonFlags, fs []model.Finding) []model.Finding {
	disabled := map[string]bool{}
	for _, t := range splitCSV(c.disable) {
		disabled[t] = true
	}
	minSev := -1
	if c.minSeverity != "" {
		minSev = model.SeverityOrder[c.minSeverity]
	}
	if c.minConfidence <= 0 && minSev < 0 && len(disabled) == 0 {
		return fs
	}
	out := fs[:0]
	for _, f := range fs {
		if model.IsIncompleteFinding(f) {
			out = append(out, f)
			continue
		}
		if c.minConfidence > 0 && f.Confidence < c.minConfidence {
			continue
		}
		if minSev >= 0 && model.SeverityOrder[f.Severity] < minSev {
			continue
		}
		if disabled[f.Type] {
			continue
		}
		out = append(out, f)
	}
	return out
}

// dedupeFingerprints drops findings whose Fingerprint was already emitted, collapsing the same secret
// across occurrences. A surviving image entry wins over its overwritten copy. Findings without a
// fingerprint are always kept (no stable identity to dedupe).
func dedupeFingerprints(fs []model.Finding) []model.Finding {
	seen := make(map[string]int, len(fs))
	out := fs[:0]
	for _, f := range fs {
		if f.Fingerprint != "" {
			if idx, exists := seen[f.Fingerprint]; exists {
				if f.InFinalImage != nil && *f.InFinalImage && (out[idx].InFinalImage == nil || !*out[idx].InFinalImage) {
					out[idx] = f
				}
				continue
			}
			seen[f.Fingerprint] = len(out)
		}
		out = append(out, f)
	}
	return out
}

// restoreMissingLive re-adds (by fingerprint) any confirmed-live finding that baseline/.gitleaksignore
// suppression dropped, so an attacker-shipped allowlist can't hide a live secret from the gate.
func restoreMissingLive(findings, live []model.Finding) []model.Finding {
	if len(live) == 0 {
		return findings
	}
	present := make(map[string]bool, len(findings))
	for _, f := range findings {
		present[f.Fingerprint] = true
	}
	for _, f := range live {
		if !present[f.Fingerprint] {
			findings = append(findings, f)
		}
	}
	return findings
}

// escalateLive bumps a provider-confirmed-live finding to critical so it stands out and trips any
// severity gate. Opt-in via --fail-on-verified; a plain --verify scan keeps its severities.
func escalateLive(fs []model.Finding) {
	for i := range fs {
		if fs[i].Verified != nil && *fs[i].Verified {
			fs[i].Severity = "critical"
		}
	}
}

func gate(fs []model.Finding, failOn string, failOnVerified bool) int {
	for _, f := range fs {
		if model.IsIncompleteFinding(f) {
			logx.Error("scan results are incomplete — failing closed")
			return 2
		}
	}
	if failOnVerified {
		// Fail only on a provider-confirmed-live secret (the near-zero-FP gate); a firewalled CI that
		// can't verify should combine this with --fail-on.
		for _, f := range fs {
			if f.Verified != nil && *f.Verified {
				return 1
			}
		}
	}
	if failOn == "" {
		return 0
	}
	min, ok := model.SeverityOrder[failOn]
	if !ok {
		// An unrecognized fail_on (a config typo) must fail closed, not silently disable the gate.
		logx.Error("fail_on is not a valid severity — failing the gate closed", "value", failOn,
			"valid", "info|low|medium|high|critical")
		return 1
	}
	for _, f := range fs {
		if model.SeverityOrder[f.Severity] >= min {
			return 1
		}
	}
	return 0
}

// matchesAny reports whether s contains any of the (non-empty) substrings.
func matchesAny(s string, subs []string) bool {
	for _, sub := range subs {
		if sub != "" && strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
