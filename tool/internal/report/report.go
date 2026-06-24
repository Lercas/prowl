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
	switch format {
	case "json":
		return writeJSON(w, findings)
	case "sarif":
		return writeSARIF(w, findings)
	case "defectdojo", "dojo":
		return writeDefectDojo(w, findings)
	default:
		return writePretty(w, findings, color)
	}
}

// truncationTypes are the synthetic finding Types marking a capped/incomplete result. Their presence
// sets the report envelope's `truncated` flag so a JSON/SARIF consumer knows results are incomplete.
var truncationTypes = map[string]bool{
	"results_truncated":  true,
	"response_truncated": true,
	"item_too_large":     true,
}

// anyTruncated reports whether the findings include a truncation marker (some results were capped).
func anyTruncated(fs []model.Finding) bool {
	for _, f := range fs {
		if truncationTypes[f.Type] {
			return true
		}
	}
	return false
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

// writePretty renders findings grouped by file, worst-file first, with a summary footer.
func writePretty(w io.Writer, fs []model.Finding, color bool) error {
	if len(fs) == 0 {
		fmt.Fprintln(w, paint(color, "\x1b[32m", "✓ no secrets found"))
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
			// The redacted value can carry attacker bytes — strip them before painting. f.Type is from
			// prowl's own rule set, so it needs no sanitizing.
			fmt.Fprintf(w, "    %s  %-*s  %s  %s%s%s\n",
				badge, maxType, f.Type,
				paint(color, cDim, fmt.Sprintf("%-7s", loc)),
				paint(color, cDim, sanitizeTerminal(displayRedaction(f))), tag, locator)
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
	fmt.Fprintf(w, "  %s  %s  %s\n",
		paint(color, cBold, fmt.Sprintf("%d findings", len(fs))),
		strings.Join(parts, paint(color, cDim, " · ")),
		paint(color, cDim, fmt.Sprintf("in %d file%s", len(files), plural(len(files)))))
	return nil
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

func writeJSON(w io.Writer, fs []model.Finding) error {
	sortFindings(fs)
	// Coerce nil to an empty slice so the field is always `[]`, never `null` (a null breaks consumers
	// that iterate findings).
	if fs == nil {
		fs = []model.Finding{}
	}
	// encoding/json errors on a NaN/Inf float, which would leave the --output file truncated-but-empty;
	// clamp any non-finite Confidence to [0,1] so a valid report is always produced.
	for i := range fs {
		fs[i].Confidence = safeConfidence(fs[i].Confidence)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// Don't HTML-escape so paths like <stdin> aren't mangled to <stdin>.
	enc.SetEscapeHTML(false)
	// `truncated` surfaces the global match cap so a CI consumer knows results are incomplete.
	return enc.Encode(map[string]any{"findings": fs, "count": len(fs), "truncated": anyTruncated(fs)})
}

// writeSARIF emits SARIF 2.1.0 for GitHub/GitLab code-scanning tabs, with a rule per secret type.
func writeSARIF(w io.Writer, fs []model.Finding) error {
	sortFindings(fs)
	ruleIndex := map[string]int{}
	var rules []map[string]any
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
					"region": map[string]any{"startLine": sarifPos(f.Line), "startColumn": sarifPos(f.Col)},
				},
			}},
			// Mirror confidence/stage for downstream tooling that reads result properties.
			"properties": map[string]any{"confidence": safeConfidence(f.Confidence), "stage": f.Stage},
		}
		// partialFingerprints drives alert identity so a finding that moves lines isn't resurrected as a
		// new alert. Skip it when there's no stable identity.
		if f.Fingerprint != "" {
			res["partialFingerprints"] = map[string]any{"prowl/v1": f.Fingerprint}
		}
		results = append(results, res)
	}
	run := map[string]any{
		"tool":    map[string]any{"driver": map[string]any{"name": "prowl", "informationUri": "https://github.com/Lercas/prowl", "rules": rules}},
		"results": results,
	}
	// Surface the global match cap, mirroring the JSON envelope's `truncated` field (run-level
	// properties is the SARIF-valid place for tool-specific metadata).
	if anyTruncated(fs) {
		run["properties"] = map[string]any{"truncated": true}
	}
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

// sarifURI is the artifactLocation uri: a finding's direct URL when it has one (Jira/Confluence),
// else its Path (a code finding's file path — a valid relative URI).
func sarifURI(f model.Finding) string {
	if f.URL != "" {
		return f.URL
	}
	return f.Path
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
