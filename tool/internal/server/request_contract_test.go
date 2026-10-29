package server

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestIntakeRejectsAmbiguousMissingAndUnsupportedFields(t *testing.T) {
	s := newSrv(t)
	for _, body := range []string{
		`null`, `{}`, `{"path":"production.json"}`,
		`{"content":null}`, `{"content":"clean","verify":true}`,
		`{"content":"AWS=AKIANAFGYOEYPXU1DSYP","content":"clean"}`,
		`{"content":"AWS=AKIANAFGYOEYPXU1DSYP","cont\u0065nt":"clean"}`,
		`{"content":"clean"} {"content":"AWS=AKIANAFGYOEYPXU1DSYP"}`,
		`{"content":"clean","source":"code","source":"file"}`,
		`{"content":"password=\ud800Winter42"}`,
		`{"content":"password=\udc00Winter42"}`,
		`{"content":"clean","path":"\ud800"}`,
		"{\"content\":\"password=\xffWinter42\"}",
	} {
		if r := do(s, http.MethodPost, "/scan", body); r.Code != http.StatusBadRequest {
			t.Fatalf("ambiguous/unsupported input certified as a scan: %q status=%d", body, r.Code)
		}
		if r := do(s, http.MethodPost, "/scan/batch", "["+body+"]"); r.Code != http.StatusBadRequest {
			t.Fatalf("batch accepted ambiguous input: %q status=%d", body, r.Code)
		}
	}
	for _, body := range []string{`null`, `[] []`, `[null]`} {
		if r := do(s, http.MethodPost, "/scan/batch", body); r.Code != http.StatusBadRequest {
			t.Fatal("batch accepted null/trailing intake")
		}
	}
	if r := do(s, http.MethodPost, "/scan", `{"content":""}`); r.Code != http.StatusOK {
		t.Fatal("explicit empty content was rejected")
	}
	if r := do(s, http.MethodPost, "/scan/batch", `[]`); r.Code != http.StatusOK {
		t.Fatal("explicit empty batch was rejected")
	}
}

func TestWorkerCapabilitiesAndEmptyBatchPolicy(t *testing.T) {
	s := newSrv(t)
	r := do(s, http.MethodGet, "/capabilities", "")
	var caps struct {
		Redacted bool            `json:"redacted"`
		Stages   map[string]bool `json:"stages"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &caps); err != nil || !caps.Redacted || !caps.Stages["l1"] || caps.Stages["verification"] || caps.Stages["ml"] {
		t.Fatal("worker advertised unsupported stages or raw output")
	}
	r = do(s, http.MethodPost, "/scan/batch", `[]`)
	var result scanResult
	if err := json.Unmarshal(r.Body.Bytes(), &result); err != nil || !result.Complete || len(result.Scope) < 2 {
		t.Fatal("empty worker report lost rule/detection policy")
	}
}
