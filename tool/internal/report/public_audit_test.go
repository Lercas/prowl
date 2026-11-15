package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestPublicAuditReportsRemainSeparateFromLiveVerdicts(t *testing.T) {
	audit := &model.PublicKeyAudit{Provider: "algolia", Status: "excess_permissions", Capabilities: []string{"addObject", "search"}, Reason: "ACL grants permissions beyond public search"}
	f := model.Finding{Type: "algolia-api-key", Path: "prod.json", Source: "code", Severity: "high", Line: 1, Col: 3, Redacted: "13ad********60f2", PublicKeyAudit: audit}
	f.Occurrences = []model.Occurrence{f.Occurrence()}
	var j, s, p bytes.Buffer
	if err := Write(&j, []model.Finding{f}, "json", false); err != nil {
		t.Fatal(err)
	}
	if err := Write(&s, []model.Finding{f}, "sarif", false); err != nil {
		t.Fatal(err)
	}
	if err := Write(&p, []model.Finding{f}, "pretty", false); err != nil {
		t.Fatal(err)
	}
	var jd, sd map[string]any
	if err := json.Unmarshal(j.Bytes(), &jd); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(s.Bytes(), &sd); err != nil {
		t.Fatal(err)
	}
	jf := jd["findings"].([]any)[0].(map[string]any)
	props := sd["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)["properties"].(map[string]any)
	if _, ok := jf["verified"]; ok {
		t.Fatal("public audit claimed live verification")
	}
	for _, key := range []string{"public_key_audit", "occurrences"} {
		if !reflect.DeepEqual(jf[key], props[key]) {
			t.Fatal("SARIF lost public audit", key)
		}
	}
	if !strings.Contains(p.String(), "public key audit: excess_permissions") || strings.Contains(p.String(), "LIVE") {
		t.Fatal("pretty audit missing or conflated with liveness")
	}
}
