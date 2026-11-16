// Package report renders findings in pretty / JSON / SARIF formats.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
)

// sanitizeTerminal strips terminal-escape bytes from an attacker-controlled string (a path, redacted
// value, or imported rule ID) before it reaches the operator's terminal in the pretty report. A thin
// alias over logx.SanitizeTerminal; prowl's own colour codes are added by paint() afterward.
func sanitizeTerminal(s string) string { return logx.SanitizeTerminal(s) }

// Write dispatches by format. color enables ANSI styling in the pretty format.
func Write(w io.Writer, findings []model.Finding, format string, color bool) error {
	return WriteWithCoverage(w, findings, format, color, nil)
}

// WriteWithCoverage preserves the released machine envelope for one scan ledger.
func WriteWithCoverage(w io.Writer, findings []model.Finding, format string, color bool, coverage *model.Coverage) (err error) {
	output := &reportWriter{w: w}
	w = output
	defer func() {
		if err == nil {
			err = output.err
		}
	}()
	switch format {
	case "json":
		return writeJSON(w, findings, coverage)
	case "sarif":
		return writeSARIF(w, findings, coverage)
	case "defectdojo", "dojo":
		return writeDefectDojo(w, findings)
	case "pretty", "":
		return writePretty(w, findings, PrettyOptions{Color: color, Coverage: coverage})
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
}

func sortFindings(fs []model.Finding) {
	sort.Slice(fs, func(i, j int) bool {
		si, sj := model.SeverityOrder[fs[i].Severity], model.SeverityOrder[fs[j].Severity]
		if si != sj {
			return si > sj
		}
		if fs[i].Path != fs[j].Path {
			return fs[i].Path < fs[j].Path
		}
		return fs[i].Line < fs[j].Line
	})
}

const (
	cReset = "\x1b[0m"
	cDim   = "\x1b[2m"
	cBold  = "\x1b[1m"
)

// sevStyle returns the marker and ANSI colour for a severity.
func sevStyle(sev string) (icon, color string) {
	switch sev {
	case "critical":
		return "✖", "\x1b[1;31m"
	case "high":
		return "✖", "\x1b[31m"
	case "medium":
		return "⚠", "\x1b[33m"
	case "low":
		return "•", "\x1b[2m"
	default:
		return "·", "\x1b[2m"
	}
}

func paint(on bool, code, s string) string {
	if !on || code == "" {
		return s
	}
	return code + s + cReset
}

// reportWriter retains the first failure so a report with many formatted writes can return it.
type reportWriter struct {
	w   io.Writer
	err error
}

func (w *reportWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	n, err := w.w.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	w.err = err
	return n, err
}

// PrettyOptions tunes the human report.
type PrettyOptions struct {
	Color bool
	// Coverage distinguishes a completed clean scan from empty, filtered and incomplete inputs.
	Coverage *model.Coverage
	// Snippet returns the source line of a finding with its secrets already masked, or "".
	// The caller owns the masking; the report only strips terminal escapes and prints it.
	Snippet func(model.Finding) string
}

// WritePretty renders the human report with options the format-dispatching Write does not carry.
func WritePretty(w io.Writer, findings []model.Finding, options PrettyOptions) error {
	return writePretty(w, findings, options)
}

// writePretty renders secrets grouped by file, worst-file first, with a summary footer. Scan
// diagnostics (an unreadable source, a capped result) are not secrets: they are listed in their own
// block so a missing path never reads as "1 finding" and a partial scan never reads as clean.
func writePretty(w io.Writer, all []model.Finding, options PrettyOptions) (err error) {
	color := options.Color
	output := &reportWriter{w: w}
	w = output
	defer func() { err = output.err }()
	var fs, gaps []model.Finding
	for _, f := range all {
		if model.IsIncompleteFinding(f) {
			gaps = append(gaps, f)
		} else {
			fs = append(fs, f)
		}
	}
	result := model.NewResult(all, options.Coverage)
	if len(fs) == 0 {
		if !result.Complete {
			if len(gaps) > 0 {
				fmt.Fprintln(w)
				writeGaps(w, gaps, color)
			}
			writeCoverageDiagnostics(w, result, gaps, color)
			return nil
		}
		switch {
		case result.Filtered:
			fmt.Fprintln(w, "no findings after filters and suppressions")
		case options.Coverage != nil && result.Stats.Processed == 0:
			fmt.Fprintln(w, "no objects to scan")
		default:
			fmt.Fprintln(w, paint(color, "\x1b[32m", "✓ no secrets found"))
		}
		return nil
	}
	byFile := map[string][]model.Finding{}
	worst := map[string]int{}
	var files []string
	maxType := 0
	for _, f := range fs {
		if _, ok := byFile[f.Path]; !ok {
			files = append(files, f.Path)
		}
		byFile[f.Path] = append(byFile[f.Path], f)
		if s := model.SeverityOrder[f.Severity]; s > worst[f.Path] {
			worst[f.Path] = s
		}
		// An imported external rule's Type is attacker-controlled, so measure the column width on the
		// sanitized type to keep row alignment after the strip below.
		if n := len(sanitizeTerminal(f.Type)); n > maxType {
			maxType = n
		}
	}
	sort.Slice(files, func(i, j int) bool {
		if worst[files[i]] != worst[files[j]] {
			return worst[files[i]] > worst[files[j]]
		}
		return files[i] < files[j]
	})

	count := map[string]int{}
	fmt.Fprintln(w)
	for _, path := range files {
		// path is attacker-controlled — strip terminal-escape bytes before printing it.
		fmt.Fprintln(w, "  "+paint(color, cBold, sanitizeTerminal(path)))
		ff := byFile[path]
		sort.Slice(ff, func(i, j int) bool {
			si, sj := model.SeverityOrder[ff[i].Severity], model.SeverityOrder[ff[j].Severity]
			if si != sj {
				return si > sj
			}
			return ff[i].Line < ff[j].Line
		})
		for _, f := range ff {
			count[f.Severity]++
			icon, col := sevStyle(f.Severity)
			badge := paint(color, col, fmt.Sprintf("%s %-8s", icon, f.Severity))
			loc := fmt.Sprintf("%d", f.Line)
			if f.Col > 0 {
				loc = fmt.Sprintf("%d:%d", f.Line, f.Col)
			}
			tag := confidenceTag(f, color)
			// A Jira/Confluence finding carries a direct browse/page URL — show it so the secret is
			// locatable (its Path is a key/title and Line is an offset into a synthetic blob).
			locator := ""
			if f.URL != "" {
				locator = "  " + paint(color, cDim, sanitizeTerminal(f.URL))
			}
			// Imported rule IDs and redacted values can carry terminal escapes.
			fmt.Fprintf(w, "    %s  %-*s  %s  %s%s%s\n",
				badge, maxType, sanitizeTerminal(f.Type),
				paint(color, cDim, fmt.Sprintf("%-7s", loc)),
				paint(color, cDim, sanitizeTerminal(displayRedaction(f))), tag, locator)
			if a := f.PublicKeyAudit; a != nil {
				fmt.Fprintf(w, "        public key audit: %s — %s\n", sanitizeTerminal(a.Status), sanitizeTerminal(a.Reason))
				for _, check := range a.Checks {
					scope := []rune(sanitizeTerminal(check.Scope))
					if len(scope) > 12 {
						scope = scope[:12]
					}
					data := ""
					if check.DataState != "" {
						data = "; data " + sanitizeTerminal(check.DataState)
					}
					fmt.Fprintf(w, "          %s: %s [%s]%s\n", sanitizeTerminal(check.Service), sanitizeTerminal(check.Status), string(scope), data)
				}
			}
			if options.Snippet != nil {
				if line := sanitizeTerminal(options.Snippet(f)); line != "" {
					fmt.Fprintf(w, "        %s\n", paint(color, cDim, line))
				}
			}
		}
		fmt.Fprintln(w)
	}

	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count[sev] > 0 {
			_, col := sevStyle(sev)
			parts = append(parts, paint(color, col, fmt.Sprintf("%d %s", count[sev], sev)))
		}
	}
	if len(gaps) > 0 {
		writeGaps(w, gaps, color)
	}
	if !result.Complete {
		writeCoverageDiagnostics(w, result, gaps, color)
	}
	fmt.Fprintf(w, "  %s  %s  %s\n",
		paint(color, cBold, fmt.Sprintf("%d finding%s", len(fs), plural(len(fs)))),
		strings.Join(parts, paint(color, cDim, " · ")),
		paint(color, cDim, fmt.Sprintf("in %d file%s", len(files), plural(len(files)))))
	if line := bbSummary(fs, color); line != "" {
		fmt.Fprintln(w, line)
	}
	for _, f := range fs {
		if f.Verified == nil {
			fmt.Fprintln(w, "  "+paint(color, cDim, "Candidates without a provider verdict are unconfirmed."))
			break
		}
	}
	return nil
}

// Coverage diagnostics may exist without synthetic findings. Keep their output
// bounded and prioritize incomplete checks over informational policy skips.
func writeCoverageDiagnostics(w io.Writer, result model.ScanResult, gaps []model.Finding, color bool) {
	if len(gaps) == 0 {
		fmt.Fprintln(w, "  "+paint(color, "\x1b[33m", "! scan incomplete — coverage diagnostics"))
	}
	type location struct{ code, path string }
	represented := make(map[location]bool, len(gaps))
	for _, gap := range gaps {
		represented[location{gap.Type, gap.Path}] = true
	}
	diagnostics := make([]model.Diagnostic, 0, len(result.Diagnostics))
	omitted := int64(0)
	for _, diagnostic := range result.Diagnostics {
		if represented[location{diagnostic.Code, diagnostic.Path}] {
			omitted++
			continue
		}
		diagnostics = append(diagnostics, diagnostic)
	}
	if len(diagnostics) == 0 && result.Stats.DiagnosticCount <= omitted {
		return
	}
	if len(gaps) > 0 {
		fmt.Fprintln(w, "  coverage diagnostics:")
	}
	sort.SliceStable(diagnostics, func(i, j int) bool { return diagnostics[i].Incomplete && !diagnostics[j].Incomplete })
	const maxRows = 5
	for _, d := range diagnostics[:min(len(diagnostics), maxRows)] {
		where := sanitizeTerminal(d.Path)
		if where == "" {
			where = "scan"
		}
		fmt.Fprintf(w, "    %s: %s\n", sanitizeTerminal(d.Code), where)
	}
	if remaining := result.Stats.DiagnosticCount - omitted - int64(min(len(diagnostics), maxRows)); remaining > 0 {
		fmt.Fprintf(w, "    … and %d more (use --format json for coverage metadata)\n", remaining)
	}
}

// maxGapRows bounds the diagnostics block: past it the remaining inputs are only counted.
const maxGapRows = 10

// writeGaps lists what the scan could not fully cover, one input per row with a plain reason.
func writeGaps(w io.Writer, gaps []model.Finding, color bool) {
	const warn = "\x1b[33m"
	summary := fmt.Sprintf("%d input%s not fully checked", len(gaps), plural(len(gaps)))
	for _, f := range gaps {
		if f.Stage == "occurrence aggregation" {
			summary = fmt.Sprintf("%d completeness issue%s", len(gaps), plural(len(gaps)))
			break
		}
	}
	fmt.Fprintln(w, "  "+paint(color, warn, "! scan incomplete — "+summary))
	for i, f := range gaps {
		if i == maxGapRows {
			fmt.Fprintln(w, "    "+paint(color, cDim, fmt.Sprintf("… and %d more (use --format json for the full list)", len(gaps)-i)))
			break
		}
		where := sanitizeTerminal(f.Path)
		if where == "" {
			where = "scan"
		}
		fmt.Fprintf(w, "    %s  %s\n", where, paint(color, cDim, gapReason(f)))
	}
	fmt.Fprintln(w)
}

// gapReason says in plain words why an input is not fully covered and what changes that.
func gapReason(f model.Finding) string {
	switch f.Type {
	case "source_error":
		return "could not be read (see the warning above)"
	case "item_too_large":
		return "larger than --max-size, skipped"
	case "results_truncated":
		return "too many candidates, results capped"
	}
	if f.Rationale != "" {
		return sanitizeTerminal(f.Rationale)
	}
	return "results are incomplete"
}

// bbSummary is the one-line live/dead/unverified verdict appended after a verification run; empty when
// no finding was verified, so non-`--verify` output is unchanged.
func bbSummary(fs []model.Finding, color bool) string {
	live, dead, unverified := 0, 0, 0
	var top model.Finding
	for _, f := range fs {
		switch {
		case f.Verified == nil:
			unverified++
		case *f.Verified:
			live++
			if top.Verified == nil || model.SeverityOrder[f.Severity] > model.SeverityOrder[top.Severity] {
				top = f
			}
		default:
			dead++
		}
	}
	if live == 0 && dead == 0 {
		return ""
	}
	liveCol := "\x1b[32m"
	head := fmt.Sprintf("%d LIVE", live)
	if live > 0 {
		liveCol = "\x1b[31m"
		head += fmt.Sprintf(" (%s %s)", top.Severity, sanitizeTerminal(top.Type))
	}
	return "  " + paint(color, cBold, "BB: ") + paint(color, liveCol, head) +
		paint(color, cDim, fmt.Sprintf("; %d dead; %d unverified", dead, unverified))
}

// displayRedaction is the masked value shown in a pretty row. For a PEM private-key finding (whose
// redaction is identical for two keys of the same type) it appends a short fingerprint prefix so two
// distinct keys are told apart, without revealing key material.
func displayRedaction(f model.Finding) string {
	if model.IsPEMKey(f.Redacted) && f.Fingerprint != "" {
		return f.Redacted + " #" + f.Fingerprint[:8]
	}
	return f.Redacted
}

// confidenceTag is the trailing marker on a pretty row:
//   - live/dead  — a verifier probed the credential (strongest signal).
//   - ✓ checksum — passed a structural checksum (L1-checksum): a well-formed key, not a regex guess.
//   - NN%        — only for low-confidence (<0.7) guesses, so weak hits stand out.
//
// High-confidence regex matches (0.7–0.98) carry no tag — a bare row already means that.
func confidenceTag(f model.Finding, color bool) string {
	if f.Verified != nil {
		if *f.Verified {
			return paint(color, "\x1b[1;31m", "  live")
		}
		return paint(color, cDim, "  dead")
	}
	if f.Stage == "L1-checksum" {
		return paint(color, "\x1b[32m", "  ✓ checksum")
	}
	if f.Confidence < 0.7 {
		return paint(color, cDim, fmt.Sprintf("  %.0f%%", f.Confidence*100))
	}
	return ""
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func writeJSON(w io.Writer, fs []model.Finding, coverage *model.Coverage) error {
	sortFindings(fs)
	// Coerce nil to an empty slice so the field is always `[]`, never `null` (a null breaks consumers
	// that iterate findings).
	if fs == nil {
		fs = []model.Finding{}
	}
	// encoding/json rejects NaN/Inf. Clamp confidence so a non-finite model score still yields a
	// valid report instead of refusing its serialization.
	for i := range fs {
		fs[i].Confidence = safeConfidence(fs[i].Confidence)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// Don't HTML-escape so paths like <stdin> aren't mangled to <stdin>.
	enc.SetEscapeHTML(false)
	// `truncated` surfaces the global match cap so a CI consumer knows results are incomplete.
	return enc.Encode(model.NewResult(fs, coverage))
}

// writeSARIF emits SARIF 2.1.0 for GitHub/GitLab code-scanning tabs, with a rule per secret type.
func writeSARIF(w io.Writer, fs []model.Finding, coverage *model.Coverage) error {
	sortFindings(fs)
	ruleIndex := map[string]int{}
	rules := make([]map[string]any, 0)
	results := make([]map[string]any, 0, len(fs))
	for _, f := range fs {
		idx, ok := ruleIndex[f.Type]
		if !ok {
			idx = len(rules)
			ruleIndex[f.Type] = idx
			rules = append(rules, map[string]any{
				"id":               f.Type,
				"name":             f.Type,
				"shortDescription": map[string]any{"text": f.Type + " secret"},
				// security-severity lets the GitHub Security tab rank/filter (on
				// defaultConfiguration.properties per SARIF 2.1.0).
				"defaultConfiguration": map[string]any{
					"level":      sarifLevel(f.Severity),
					"properties": map[string]any{"security-severity": sarifSecuritySeverity(f.Severity)},
				},
			})
		}
		column := f.UTF16Col
		if column == 0 {
			column = f.Col // legacy/constructed findings do not carry scanned text metadata
		}
		res := map[string]any{
			"ruleId":    f.Type,
			"ruleIndex": idx,
			"level":     sarifLevel(f.Severity),
			"message": map[string]any{
				"text": fmt.Sprintf("%s secret (%s, conf %.2f, %s): %s", f.Type, f.Severity, safeConfidence(f.Confidence), f.Stage, f.Redacted),
			},
			"locations": []map[string]any{{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{"uri": sarifURI(f)},
					// SARIF 2.1.0 requires startLine/startColumn >= 1; a Line/Col-0 hit is clamped
					// (see sarifPos) so it doesn't fail schema validation.
					"region": map[string]any{"startLine": sarifPos(f.Line), "startColumn": sarifPos(column)},
				},
			}},
			// Mirror confidence/stage for downstream tooling that reads result properties.
			"properties": map[string]any{"confidence": safeConfidence(f.Confidence), "stage": f.Stage},
		}
		if f.Agent != nil {
			res["properties"].(map[string]any)["agent"] = f.Agent
		}
		addIdentityProperties(res["properties"].(map[string]any), f)
		if f.Git != nil {
			res["properties"].(map[string]any)["git"] = f.Git
		}
		if f.ValueFingerprint != "" {
			res["properties"].(map[string]any)["value_fingerprint"] = f.ValueFingerprint
		}
		// partialFingerprints drives alert identity so a finding that moves lines isn't resurrected as a
		// new alert. Skip it when there's no stable identity.
		if f.Fingerprint != "" {
			res["partialFingerprints"] = map[string]any{"prowl/v1": f.Fingerprint}
		}
		results = append(results, res)
	}
	run := map[string]any{
		"tool":       map[string]any{"driver": map[string]any{"name": "prowl", "informationUri": "https://github.com/Lercas/prowl", "rules": rules}},
		"results":    results,
		"columnKind": "utf16CodeUnits",
	}
	// Surface the global match cap, mirroring the JSON envelope's `truncated` field (run-level
	// properties is the SARIF-valid place for tool-specific metadata).
	result := model.NewResult(fs, coverage)
	run["properties"] = map[string]any{"schema_version": result.SchemaVersion, "truncated": result.Truncated,
		"complete": result.Complete, "completion_reason": result.CompletionReason, "diagnostics": result.Diagnostics,
		"scope": result.Scope, "stats": result.Stats, "filtered": result.Filtered,
		"identity_scope": result.IdentityScope, "secrets_revealed": result.SecretsRevealed}
	run["invocations"] = []map[string]any{{"executionSuccessful": result.Complete}}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs":    []map[string]any{run},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

// writeDefectDojo emits findings in DefectDojo's "Generic Findings Import" JSON format (a top-level
// "findings" array) for direct import. Each finding carries CWE-798 and the redacted value only — a
// raw secret is never written.
func writeDefectDojo(w io.Writer, fs []model.Finding) error {
	sortFindings(fs)
	findings := make([]map[string]any, 0, len(fs))
	for _, f := range fs {
		// Description carries safe-to-share evidence only: the redacted value, the path:line, and the
		// rationale if present.
		desc := fmt.Sprintf("%s at %s:%d", f.Redacted, f.Path, f.Line)
		if f.Rationale != "" {
			desc += " — " + f.Rationale
		}
		// vuln_id_from_tool is the rule/detector that fired; prefer the rule Type, fall back to Detector.
		vulnID := f.Type
		if vulnID == "" {
			vulnID = f.Detector
		}
		finding := map[string]any{
			"title":               fmt.Sprintf("%s secret detected", f.Type),
			"description":         desc,
			"severity":            dojoSeverity(f.Severity),
			"file_path":           f.Path,
			"line":                f.Line,
			"cwe":                 798, // CWE-798 Use of Hard-coded Credentials
			"vuln_id_from_tool":   vulnID,
			"unique_id_from_tool": f.Fingerprint, // drives DefectDojo dedup across scans
			"active":              true,
			// verified is true ONLY when prowl actually live-verified the credential.
			"verified": f.Verified != nil && *f.Verified,
		}
		findings = append(findings, finding)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// Don't HTML-escape so paths/values like <stdin> aren't mangled (JSON already escapes control bytes
	// safely — no terminal-strip needed for machine output).
	enc.SetEscapeHTML(false)
	return enc.Encode(map[string]any{"findings": findings})
}

// dojoSeverity maps prowl's lowercase severity to DefectDojo's Title-case scale; unknown/empty maps to
// "Info" so a valid value is always emitted.
func dojoSeverity(sev string) string {
	switch sev {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default: // "info" and any unknown value
		return "Info"
	}
}

// sarifPos clamps a 1-based SARIF position to >= 1 (a column-less or whole-file hit carries 0, which
// SARIF 2.1.0 rejects).
func sarifPos(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// safeConfidence clamps a confidence to [0,1] and maps NaN to 0. A non-finite value (e.g. from a buggy
// ML scorer) would make encoding/json fail and truncate the report, so it is coerced here.
func safeConfidence(c float64) float64 {
	switch {
	case math.IsNaN(c) || c < 0: // NaN and -Inf (-Inf < 0) floor to 0
		return 0
	case c > 1: // +Inf (+Inf > 1) and any over-range value cap at 1
		return 1
	default:
		return c
	}
}

func sarifLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// sarifSecuritySeverity maps a severity to the 0-10 CVSS-style score the GitHub Security tab uses to
// rank alerts (a string per the SARIF convention).
func sarifSecuritySeverity(sev string) string {
	switch sev {
	case "critical":
		return "9.0"
	case "high":
		return "8.0"
	case "medium":
		return "5.0"
	case "low":
		return "3.0"
	default:
		return "2.0"
	}
}
