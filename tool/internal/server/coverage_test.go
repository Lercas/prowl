package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func TestHTTPScanLedgerCountsStructuredInputOnce(t *testing.T) {
	s := newSrv(t)
	content := `{"key":"\u0041KIANAFGYOEYPXU1DSYP"}`
	for _, endpoint := range []string{"/scan", "/scan/batch"} {
		body := `{"content":` + mustJSON(t, content) + `,"path":"production.json"}`
		if endpoint == "/scan/batch" {
			body = "[" + body + "]"
		}
		r := do(s, http.MethodPost, endpoint, body)
		var result model.ScanResult
		if err := json.Unmarshal(r.Body.Bytes(), &result); err != nil || !result.Complete || result.Count != 1 || result.Stats.Processed != 1 || result.Stats.Bytes != int64(len(content)) || len(result.Scope) != 3 {
			t.Fatalf("structured HTTP ledger lost: %+v err=%v", result, err)
		}
	}
}

func TestHTTPParserAndAllowlistLedgerIsolation(t *testing.T) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	s := New(scan.New(scan.Options{Detector: detect.New(tax), Allow: func(string, string) bool { return true }}), 2)
	for _, row := range []struct {
		content, path      string
		complete, filtered bool
	}{
		{"AWS=AKIANAFGYOEYPXU1DSYP", "production.env", true, true},
		{`{"key":"bad\q"}`, "production.json", false, false},
		{"ordinary text", "production.env", true, false},
	} {
		r := do(s, http.MethodPost, "/scan", `{"content":`+mustJSON(t, row.content)+`,"path":`+mustJSON(t, row.path)+`}`)
		var result model.ScanResult
		if err := json.Unmarshal(r.Body.Bytes(), &result); err != nil || result.Complete != row.complete || result.Filtered != row.filtered || result.Stats.Processed != 1 {
			t.Fatalf("request ledger crossed requests or lost parser failure: %+v err=%v", result, err)
		}
		if !row.complete && len(result.Diagnostics) == 0 {
			t.Fatal("parser failure missing diagnostic")
		}
	}
}

func TestHTTPBatchCapRejectsBeforeMaterializingOverflow(t *testing.T) {
	r := do(newSrv(t), http.MethodPost, "/scan/batch", "["+strings.Repeat(`{"content":""},`, maxBatchItems)+`{"content":""}]`)
	if r.Code != http.StatusRequestEntityTooLarge {
		t.Fatal("batch item cap was not enforced")
	}
}

func TestHTTPCapabilitiesReflectConfiguredPipeline(t *testing.T) {
	base := newSrv(t)
	revealed := New(base.pipeline.WithRevealSecrets(true), 1)
	for _, s := range []*Server{base, revealed} {
		r := do(s, http.MethodGet, "/capabilities", "")
		var c struct {
			Redacted bool
			Stages   map[string]bool
		}
		if err := json.Unmarshal(r.Body.Bytes(), &c); err != nil || c.Redacted != (s == base) || !c.Stages["l1"] || c.Stages["ml"] || c.Stages["verification"] {
			t.Fatal("capabilities differ from pipeline")
		}
	}
}

func TestHTTPPolicyScopeChangesWithActiveTaxonomy(t *testing.T) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	full := New(scan.New(scan.Options{Detector: detect.New(tax)}), 1)
	tax.Types = nil
	empty := New(scan.New(scan.Options{Detector: detect.New(tax)}), 1)
	var policies []string
	for _, s := range []*Server{full, empty} {
		r := do(s, http.MethodPost, "/scan/batch", `[]`)
		var result model.ScanResult
		if err := json.Unmarshal(r.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		for _, scope := range result.Scope {
			if scope.Kind == "detection_policy" {
				policies = append(policies, scope.Policy)
			}
		}
	}
	if len(policies) != 2 || policies[0] == policies[1] {
		t.Fatal("different active taxonomies share a policy")
	}
}
