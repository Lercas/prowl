package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestJSONPreservesValidUnicode(t *testing.T) {
	for _, body := range []string{
		`{"content":"Пароль 🔑 \\ud800 \ufffd","path":"Конфиг.env","future":{"content":123}}`,
		`{"CONTENT":"Пароль \ud83d\udd11 \\ud800 \ufffd","PATH":"Конфиг.env"}`,
	} {
		r := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(body))
		var item scanItem
		if err := decode(httptest.NewRecorder(), r, &item, 1024); err != nil {
			t.Fatal(err)
		}
		if item.Content != "Пароль 🔑 \\ud800 �" || item.Path != "Конфиг.env" {
			t.Fatalf("valid input was normalized or damaged: %+v", item)
		}
	}
}

func TestRequestShapeMustDescribeScanContent(t *testing.T) {
	for endpoint, bodies := range map[string][]string{
		"/scan":       {`null`, `{}`, `{"content":null}`, `{"content":1}`, `{"content":"x","path":null}`},
		"/scan/batch": {`null`, `{}`, `[null]`, `[{}]`, `[{"content":null}]`},
	} {
		for _, body := range bodies {
			if rr := do(newSrv(t), http.MethodPost, endpoint, body); rr.Code != http.StatusBadRequest {
				t.Errorf("%s accepted %s, status=%d", endpoint, body, rr.Code)
			}
		}
	}
}

func TestDecodeCapsWholeBodyAfterValidPrefix(t *testing.T) {
	for _, body := range []string{`{"content":""}` + strings.Repeat(" ", 64), `{"content":""}` + strings.Repeat("x", 64)} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(body))
		var item scanItem
		err := decode(rr, req, &item, 32)
		writeDecodeError(rr, err)
		if err == nil || rr.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("valid prefix bypassed whole-body cap: status=%d err=%v", rr.Code, err)
		}
	}
}

func TestIncompleteResponseIncludesEnvelopeAndMetrics(t *testing.T) {
	s := newSrv(t)
	large := mustJSON(t, strings.Repeat("x", maxItemBytes+1))
	rr := do(s, http.MethodPost, "/scan/batch", `[{"content":`+large+`},{"content":"AWS = \"AKIANAFGYOEYPXU1DSYP\""}]`)
	var result scanResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil || !result.Truncated || result.Count != 2 {
		t.Fatalf("incomplete batch envelope: status=%d result=%+v err=%v", rr.Code, result, err)
	}
	var metrics map[string]int64
	if err := json.Unmarshal(do(s, http.MethodGet, "/metrics", "").Body.Bytes(), &metrics); err != nil {
		t.Fatal(err)
	}
	if metrics["scanned"] != 1 || metrics["truncated"] != 1 || metrics["errors"] != 1 {
		t.Fatalf("skipped item counted as scanned or incomplete response missed: %v", metrics)
	}
}

func TestBatchExactlyAtResponseCapStaysBounded(t *testing.T) {
	s := newSrv(t)
	content := strings.Repeat("AWS = \"AKIANAFGYOEYPXU1DSYP\"\n", maxRespFindings)
	rr := do(s, http.MethodPost, "/scan/batch", `[{"content":`+mustJSON(t, content)+`},{"content":"clean"}]`)
	var result scanResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil || !result.Truncated || result.Count != maxRespFindings {
		t.Fatalf("response cap violated: count=%d truncated=%v err=%v", result.Count, result.Truncated, err)
	}
	var metrics map[string]int64
	if err := json.Unmarshal(do(s, http.MethodGet, "/metrics", "").Body.Bytes(), &metrics); err != nil {
		t.Fatal(err)
	}
	if metrics["scanned"] != 1 || metrics["truncated"] != 1 {
		t.Fatalf("unprocessed item counted as scanned: %v", metrics)
	}
}

func FuzzValidateRequestJSON(f *testing.F) {
	for _, seed := range []string{`{"content":""}`, `{"content":"\ud83d\udd11"}`, `{"content":"\ud800"}`, `{"content":"\\ud800"}`, `[]`, "\xff"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			return
		}
		if err := validateRequestJSON(raw); err == nil && !json.Valid(raw) {
			t.Fatal("invalid JSON accepted")
		}
	})
}
