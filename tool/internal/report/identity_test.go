package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestSARIFPreservesJSONIdentityAndOccurrenceEvidence(t *testing.T) {
	f := model.Finding{Type: "owned", Path: "prod.js", Line: 4, Col: 9, UTF16Col: 7, Severity: "high", Confidence: .9, Stage: "reconstructed/L1-regex", Redacted: "AKIA********DSYP", Fingerprint: "report-fingerprint", SecretID: "secret", IdentityScope: "scope", OccurrenceID: "first", Provenance: map[string]string{"blob": "immutable"}, Evidence: []model.Evidence{{Path: "prod.js", Start: 3, End: 12, Line: 4, Col: 9, Transform: "concat"}}, Verification: &model.Verification{Status: "verified"}}
	f.Occurrences = []model.Occurrence{f.Occurrence(), {ID: "second", Source: "code", Path: "prod.js", Line: 8, Col: 9, Provenance: map[string]string{"blob": "other"}}}
	var jsonOut, sarifOut bytes.Buffer
	if err := Write(&jsonOut, []model.Finding{f}, "json", false); err != nil {
		t.Fatal(err)
	}
	if err := Write(&sarifOut, []model.Finding{f}, "sarif", false); err != nil {
		t.Fatal(err)
	}
	var jsonDoc, sarifDoc map[string]any
	if err := json.Unmarshal(jsonOut.Bytes(), &jsonDoc); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(sarifOut.Bytes(), &sarifDoc); err != nil {
		t.Fatal(err)
	}
	jsonFinding := jsonDoc["findings"].([]any)[0].(map[string]any)
	result := sarifDoc["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)
	properties := result["properties"].(map[string]any)
	for _, key := range []string{"secret_id", "identity_scope", "occurrence_id", "occurrences", "evidence", "provenance", "verification"} {
		if !reflect.DeepEqual(jsonFinding[key], properties[key]) {
			t.Fatalf("SARIF dropped or changed %s", key)
		}
	}
	if result["partialFingerprints"].(map[string]any)["prowl/v1"] != f.Fingerprint {
		t.Fatal("SARIF alert identity changed")
	}
	location := result["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["region"].(map[string]any)
	if location["startColumn"] != float64(7) {
		t.Fatal("identity metadata changed SARIF UTF16 columns")
	}
}

func TestSARIFOptionalKeyedValueIdentityPreservesAlertFingerprint(t *testing.T) {
	f := model.Finding{Type: "owned", Severity: "high", Source: "code", Path: "prod.env", Line: 1, Col: 1, Redacted: "****", Fingerprint: "path-specific", ValueFingerprint: "local-keyed-value"}
	var b bytes.Buffer
	if err := Write(&b, []model.Finding{f}, "sarif", false); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Runs []struct {
			Results []struct {
				Properties   map[string]any    `json:"properties"`
				Fingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	r := result.Runs[0].Results[0]
	if r.Properties["value_fingerprint"] != f.ValueFingerprint || r.Fingerprints["prowl/v1"] != f.Fingerprint {
		t.Fatal("keyed value identity replaced path-specific alert identity")
	}
	f.ValueFingerprint = ""
	b.Reset()
	if err := Write(&b, []model.Finding{f}, "sarif", false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "value_fingerprint") {
		t.Fatal("keyed identity emitted without opt-in")
	}
}
