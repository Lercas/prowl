package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

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
