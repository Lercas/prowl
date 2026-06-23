package report

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

var sample = []model.Finding{
	{Detector: "aws_access_key_id", Type: "aws_access_key_id", Severity: "critical",
		Path: "a.py", Line: 3, Col: 5, Redacted: "AKIA****1234", Confidence: 0.99, Stage: "L1-checksum"},
	{Detector: "generic_password", Type: "generic_password", Severity: "medium",
		Path: "b.py", Line: 9, Col: 1, Redacted: "****", Confidence: 0.6, Stage: "L1-regex"},
}

func TestSARIFValid(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sample, "sarif", false); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("sarif version = %v", doc["version"])
	}
	runs := doc["runs"].([]any)
	results := runs[0].(map[string]any)["results"].([]any)
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
	// critical must sort before medium
	if results[0].(map[string]any)["ruleId"] != "aws_access_key_id" {
		t.Error("results not severity-sorted")
	}
	if results[0].(map[string]any)["level"] != "error" {
		t.Error("critical should map to SARIF error")
	}
}

func TestJSONCount(t *testing.T) {
	var buf bytes.Buffer
	Write(&buf, sample, "json", false)
	var doc struct {
		Count    int `json:"count"`
		Findings []model.Finding
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Count != 2 || len(doc.Findings) != 2 {
		t.Errorf("count=%d findings=%d", doc.Count, len(doc.Findings))
	}
}

// TestJSONTruncatedField proves a results_truncated marker surfaces as a top-level `truncated:true` in
// the JSON envelope (and a normal report is truncated:false).
func TestJSONTruncatedField(t *testing.T) {
	// Normal report: no marker -> truncated:false.
	var buf bytes.Buffer
	if err := Write(&buf, sample, "json", false); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Count     int  `json:"count"`
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Truncated {
		t.Errorf("normal report should have truncated:false")
	}

	// With a results_truncated marker -> truncated:true.
	withMarker := append([]model.Finding{}, sample...)
	withMarker = append(withMarker, model.Finding{Type: "results_truncated", Severity: "info", Stage: "intake"})
	var buf2 bytes.Buffer
	if err := Write(&buf2, withMarker, "json", false); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(buf2.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Truncated {
		t.Errorf("report with a results_truncated marker must surface truncated:true")
	}
}

// TestSARIFTruncatedProperty proves the SARIF run carries a truncated property when results were capped.
func TestSARIFTruncatedProperty(t *testing.T) {
	withMarker := append([]model.Finding{}, sample...)
	withMarker = append(withMarker, model.Finding{Type: "response_truncated", Severity: "info", Stage: "intake"})
	var buf bytes.Buffer
	if err := Write(&buf, withMarker, "sarif", false); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	run := doc["runs"].([]any)[0].(map[string]any)
	props, ok := run["properties"].(map[string]any)
	if !ok || props["truncated"] != true {
		t.Errorf("SARIF run should carry properties.truncated=true when results were capped, got %v", run["properties"])
	}
}

func TestPrettyContainsTypeAndRedaction(t *testing.T) {
	var buf bytes.Buffer
	Write(&buf, sample, "pretty", false)
	out := buf.String()
	if !strings.Contains(out, "aws_access_key_id") || !strings.Contains(out, "AKIA****1234") {
		t.Error("pretty output missing type/redaction")
	}
	if strings.Contains(out, "AKIANAFGYOEYPXU1DSYP") {
		t.Error("pretty output leaked a raw secret")
	}
}

// TestPrettyStripsTerminalEscapes proves a hostile path/redacted value can't inject terminal escapes
// into the pretty report: no raw ESC or C0 control byte reaches the terminal, but the finding is still
// reported. Covers color=false and color=true (prowl's own styling adds 0x1B).
func TestPrettyStripsTerminalEscapes(t *testing.T) {
	hostile := []model.Finding{{
		Detector: "generic_secret", Type: "generic_secret", Severity: "high",
		// path with a CSI colour escape and an OSC set-title sequence terminated by BEL (0x07).
		Path: "evil\x1b[31m\"name.py\x1b]0;pwned\x07",
		Line: 1, Col: 1,
		Redacted: "se\x1b[2Jcret\x1b]0;title\x07****", Confidence: 0.95, Stage: "L1-regex",
	}}

	var buf bytes.Buffer
	if err := Write(&buf, hostile, "pretty", false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// No raw ESC byte (the start of every CSI/OSC sequence) may survive into pretty output.
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("pretty output contains a raw ESC (0x1b) byte from attacker input:\n%q", out)
	}
	// No other C0 control byte (e.g. the BEL 0x07 that terminates an OSC) may survive either.
	for _, r := range out {
		if (r < 0x20 && r != '\t' && r != '\n') || r == 0x7f {
			t.Errorf("pretty output contains a control byte 0x%02x from attacker input:\n%q", r, out)
		}
	}
	// The finding must still be reported: its type and the printable parts of path/value remain.
	if !strings.Contains(out, "generic_secret") {
		t.Error("sanitizing dropped the finding entirely (type missing)")
	}
	if !strings.Contains(out, "name.py") || !strings.Contains(out, "evil") {
		t.Errorf("printable parts of the hostile path were lost:\n%q", out)
	}
	if !strings.Contains(out, "secret") {
		t.Errorf("printable parts of the redacted value were lost:\n%q", out)
	}

	// With prowl's colouring on, the output legitimately contains 0x1b (prowl's codes), but the
	// attacker's exact injected sequence "\x1b[31m\"name" must be absent.
	var cbuf bytes.Buffer
	if err := Write(&cbuf, hostile, "pretty", true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cbuf.String(), "\x1b[31m\"name") {
		t.Error("attacker's raw escape sequence survived in coloured pretty output")
	}
}

// TestSARIFStartColumnClamped proves a Col=0/Line=0 finding emits SARIF positions >= 1 (as the 2.1.0
// schema requires) and still parses as JSON.
func TestSARIFStartColumnClamped(t *testing.T) {
	fs := []model.Finding{{
		Detector: "x", Type: "x", Severity: "high",
		Path: "f.py", Line: 0, Col: 0, Redacted: "****", Confidence: 0.9, Stage: "L1-regex",
	}}
	var buf bytes.Buffer
	if err := Write(&buf, fs, "sarif", false); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF with Col=0 is not valid JSON: %v", err)
	}
	region := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["region"].(map[string]any)
	if sc := region["startColumn"].(float64); sc < 1 {
		t.Errorf("startColumn = %v, must be >= 1 per SARIF schema", sc)
	}
	if sl := region["startLine"].(float64); sl < 1 {
		t.Errorf("startLine = %v, must be >= 1 per SARIF schema", sl)
	}
}

// TestNaNInfConfidenceProducesValidJSON proves a NaN/Inf Confidence no longer makes encoding/json fail:
// Write succeeds, the JSON parses, and the finding has a clamped [0,1] confidence.
func TestNaNInfConfidenceProducesValidJSON(t *testing.T) {
	for name, conf := range map[string]float64{
		"NaN":      math.NaN(),
		"+Inf":     math.Inf(1),
		"-Inf":     math.Inf(-1),
		"over1":    42.0,
		"negative": -5.0,
	} {
		t.Run(name, func(t *testing.T) {
			fs := []model.Finding{{
				Detector: "x", Type: "x", Severity: "high",
				Path: "f.py", Line: 1, Col: 1, Redacted: "****", Confidence: conf, Stage: "L1-regex",
			}}
			var buf bytes.Buffer
			if err := Write(&buf, fs, "json", false); err != nil {
				t.Fatalf("Write errored on %s confidence (report would be silently empty): %v", name, err)
			}
			if buf.Len() == 0 {
				t.Fatalf("%s confidence produced an empty report", name)
			}
			var doc struct {
				Count    int             `json:"count"`
				Findings []model.Finding `json:"findings"`
			}
			if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
				t.Fatalf("%s confidence: JSON does not parse: %v\n%s", name, err, buf.String())
			}
			if doc.Count != 1 || len(doc.Findings) != 1 {
				t.Fatalf("%s confidence: finding lost (count=%d)", name, doc.Count)
			}
			if c := doc.Findings[0].Confidence; c < 0 || c > 1 {
				t.Errorf("%s confidence not clamped to [0,1]: got %v", name, c)
			}
		})
	}
}

// TestJSONControlCharPathParses proves a finding whose path contains control bytes still produces JSON
// that parses (JSON escaping handles control chars; only pretty strips).
func TestJSONControlCharPathParses(t *testing.T) {
	fs := []model.Finding{{
		Detector: "x", Type: "x", Severity: "high",
		Path: "evil\x1b[31m\x00name.py", Line: 1, Col: 1, Redacted: "****", Confidence: 0.9, Stage: "L1-regex",
	}}
	var buf bytes.Buffer
	if err := Write(&buf, fs, "json", false); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("JSON with a control-char path does not parse: %v", err)
	}
}

// TestDefectDojoValid proves `--format defectdojo` emits valid "Generic Findings Import" JSON: a
// top-level "findings" array, Title-case severities, cwe=798, verified=true for a live finding, and
// never the raw secret.
func TestDefectDojoValid(t *testing.T) {
	verified := true
	const rawSecret = "AKIANAFGYOEYPXU1DSYP" // the real value behind the "AKIA****1234" redaction
	fs := []model.Finding{
		{Detector: "aws_access_key_id", Type: "aws_access_key_id", Severity: "high",
			Path: "a.py", Line: 3, Col: 5, Redacted: "AKIA****1234", Confidence: 0.99, Stage: "L1-checksum",
			Fingerprint: "fp-aws-1", Verified: &verified, Rationale: "matched live AWS STS probe"},
		{Detector: "generic_password", Type: "generic_password", Severity: "weird-severity",
			Path: "b.py", Line: 9, Col: 1, Redacted: "****", Confidence: 0.6, Stage: "L1-regex",
			Fingerprint: "fp-pw-1"},
	}

	// Exercise both the writer directly and the Write dispatch (json/defectdojo/dojo alias).
	for _, format := range []string{"defectdojo", "dojo"} {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			if err := Write(&buf, fs, format, false); err != nil {
				t.Fatal(err)
			}

			// 1) Must be valid JSON.
			var doc struct {
				Findings []map[string]any `json:"findings"`
			}
			if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
				t.Fatalf("defectdojo output is not valid JSON: %v\n%s", err, buf.String())
			}
			// 2) Top-level "findings" array with both findings (severity-sorted: high before info-ish).
			if len(doc.Findings) != 2 {
				t.Fatalf("expected 2 findings, got %d", len(doc.Findings))
			}

			// 3) The raw secret must NEVER appear; the redacted form MUST.
			out := buf.String()
			if strings.Contains(out, rawSecret) {
				t.Errorf("defectdojo output leaked a raw secret %q", rawSecret)
			}
			if !strings.Contains(out, "AKIA****1234") {
				t.Error("defectdojo output is missing the redacted value")
			}

			first := doc.Findings[0]
			// 4) Severity Title-cased: high -> "High".
			if first["severity"] != "High" {
				t.Errorf("severity not Title-cased: got %v, want High", first["severity"])
			}
			// 5) Unknown severity -> "Info".
			if second := doc.Findings[1]; second["severity"] != "Info" {
				t.Errorf("unknown severity should map to Info, got %v", second["severity"])
			}
			// 6) cwe fixed at 798.
			if cwe := first["cwe"].(float64); cwe != 798 {
				t.Errorf("cwe = %v, want 798", cwe)
			}
			// 7) Live-verified finding -> verified true; unverified -> false.
			if first["verified"] != true {
				t.Errorf("live-verified finding should have verified=true, got %v", first["verified"])
			}
			if doc.Findings[1]["verified"] != false {
				t.Errorf("unverified finding should have verified=false, got %v", doc.Findings[1]["verified"])
			}
			// 8) Title, file_path, line, dedup id, and active are populated.
			if first["title"] != "aws_access_key_id secret detected" {
				t.Errorf("title = %v", first["title"])
			}
			if first["file_path"] != "a.py" {
				t.Errorf("file_path = %v", first["file_path"])
			}
			if first["line"].(float64) != 3 {
				t.Errorf("line = %v, want 3", first["line"])
			}
			if first["unique_id_from_tool"] != "fp-aws-1" {
				t.Errorf("unique_id_from_tool = %v", first["unique_id_from_tool"])
			}
			if first["vuln_id_from_tool"] != "aws_access_key_id" {
				t.Errorf("vuln_id_from_tool = %v", first["vuln_id_from_tool"])
			}
			if first["active"] != true {
				t.Errorf("active = %v, want true", first["active"])
			}
			// 9) Rationale folded into the description alongside path:line.
			if !strings.Contains(first["description"].(string), "matched live AWS STS probe") {
				t.Errorf("description missing rationale: %v", first["description"])
			}
		})
	}
}

// TestDefectDojoEmptyFindings proves an empty scan emits {"findings": []} (an array, never null) so a
// DefectDojo import / jq '.findings[]' consumer doesn't choke.
func TestDefectDojoEmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, nil, "defectdojo", false); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("empty defectdojo output is not valid JSON: %v", err)
	}
	if doc.Findings == nil {
		t.Error("findings must be [] not null")
	}
	if len(doc.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(doc.Findings))
	}
	if !strings.Contains(buf.String(), `"findings": []`) {
		t.Errorf("expected literal \"findings\": [], got %s", buf.String())
	}
}
