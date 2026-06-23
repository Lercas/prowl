package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func newSrv(t *testing.T) *Server {
	t.Helper()
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	return New(detect.New(tax), nil, nil, 4)
}

func do(s *Server, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

func TestScanEndpoint(t *testing.T) {
	s := newSrv(t)
	rr := do(s, http.MethodPost, "/scan", `{"content":"AWS = \"AKIANAFGYOEYPXU1DSYP\"","source":"code","path":"a.py"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var res scanResult
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Count != 1 || res.Findings[0].Type != "aws_access_key_id" {
		t.Errorf("unexpected result: %+v", res)
	}
	if res.Findings[0].Redacted == "AKIANAFGYOEYPXU1DSYP" {
		t.Error("server leaked the raw secret")
	}
}

func TestBatchEndpoint(t *testing.T) {
	s := newSrv(t)
	rr := do(s, http.MethodPost, "/scan/batch",
		`[{"content":"AWS=\"AKIANAFGYOEYPXU1DSYP\""},{"content":"nothing here"}]`)
	var res scanResult
	json.Unmarshal(rr.Body.Bytes(), &res)
	if res.Count != 1 {
		t.Errorf("batch expected 1 finding across 2 items, got %d", res.Count)
	}
}

func TestHealthAndMetrics(t *testing.T) {
	s := newSrv(t)
	if rr := do(s, http.MethodGet, "/healthz", ""); rr.Code != http.StatusOK {
		t.Errorf("healthz = %d", rr.Code)
	}
	do(s, http.MethodPost, "/scan", `{"content":"AWS=\"AKIANAFGYOEYPXU1DSYP\""}`)
	rr := do(s, http.MethodGet, "/metrics", "")
	var m map[string]int64
	json.Unmarshal(rr.Body.Bytes(), &m)
	if m["scanned"] != 1 || m["findings"] != 1 || m["capacity"] != 4 {
		t.Errorf("metrics wrong: %v", m)
	}
}

func TestBadJSONIsClientError(t *testing.T) {
	s := newSrv(t)
	if rr := do(s, http.MethodPost, "/scan", `{not json`); rr.Code != http.StatusBadRequest {
		t.Errorf("bad json status = %d, want 400", rr.Code)
	}
	rr := do(s, http.MethodGet, "/metrics", "")
	var m map[string]int64
	json.Unmarshal(rr.Body.Bytes(), &m)
	if m["errors"] != 1 {
		t.Errorf("error counter not incremented: %v", m)
	}
}

// TestServeUsesRuleTemplates proves the HTTP worker runs the rule-template engine, not just the
// embedded taxonomy. A custom template fires on a token the taxonomy does not recognise, so a hit can
// only come from the engine being wired through New -> handleScan/handleBatch.
func TestServeUsesRuleTemplates(t *testing.T) {
	dir := t.TempDir()
	tmpl := `id: acme-widget-token
info:
  name: Acme Widget Token
  severity: high
matchers-condition: and
matchers:
  - type: word
    words: [acme_widget_token]
  - type: regex
    regex: ['acme_widget_token["'' :=]{1,5}["'']?(wdgt_[a-zA-Z0-9]{16})']
extractors:
  - type: regex
    regex: ['acme_widget_token["'' :=]{1,5}["'']?(wdgt_[a-zA-Z0-9]{16})']
    group: 1
`
	if err := os.WriteFile(filepath.Join(dir, "acme.yaml"), []byte(tmpl), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := rules.Load(dir)
	if err != nil {
		t.Fatalf("load template: %v", err)
	}
	if eng.Len() == 0 {
		t.Fatal("template engine empty")
	}

	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	det := detect.New(tax)
	const body = `{"content":"acme_widget_token = \"wdgt_abcd1234EFGH5678\"","path":"a.py"}`

	// Without the engine (the old behavior) the template-only token is missed.
	bare := New(det, nil, nil, 4)
	if rr := do(bare, http.MethodPost, "/scan", body); rr.Code == http.StatusOK {
		var res scanResult
		json.Unmarshal(rr.Body.Bytes(), &res)
		if res.Count != 0 {
			t.Fatalf("taxonomy-only server should NOT know the template detector, got %d findings", res.Count)
		}
	}

	// With the engine wired through, the worker finds it — same coverage as `prowl scan`.
	srv := New(det, eng, nil, 4)
	rr := do(srv, http.MethodPost, "/scan", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var res scanResult
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Count != 1 || res.Findings[0].Type != "acme-widget-token" {
		t.Fatalf("server with engine should find the template detector, got %+v", res)
	}
	if strings.Contains(res.Findings[0].Redacted, "abcd1234EFGH5678") {
		t.Error("server leaked the raw template-detector secret")
	}

	// The batch path runs the engine too.
	br := do(srv, http.MethodPost, "/scan/batch", `[`+body+`]`)
	var bres scanResult
	json.Unmarshal(br.Body.Bytes(), &bres)
	if bres.Count != 1 || bres.Findings[0].Type != "acme-widget-token" {
		t.Fatalf("batch with engine should find the template detector, got %+v", bres)
	}
}

func TestBackpressure(t *testing.T) {
	s := newSrv(t)
	// exhaust the concurrency budget, then a fresh request must be rejected with 503
	for i := 0; i < cap(s.sem); i++ {
		s.sem <- struct{}{}
	}
	rr := do(s, http.MethodPost, "/scan", `{"content":"x"}`)
	if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" {
		t.Errorf("saturated server should 503 with Retry-After, got %d", rr.Code)
	}
}

// denseCueItem builds an allowed-size (< maxItemBytes) block of password-cue lines that fans out to
// many findings — the DoS payload the per-request output cap defends against.
func denseCueItem() string {
	line := "user password is hunter2abc99 here\n"
	var b strings.Builder
	for b.Len() < (4<<20)-(1<<16) { // ~3.9 MB: under the 4MB per-item cap so the item is accepted
		b.WriteString(line)
	}
	return b.String()
}

// TestScanResponseBoundedOnDenseInput: a single allowed-size POST of dense cue lines is bounded to
// maxRespFindings findings (rather than tens of thousands) and carries a truncation note.
func TestScanResponseBoundedOnDenseInput(t *testing.T) {
	s := newSrv(t)
	content, err := json.Marshal(denseCueItem())
	if err != nil {
		t.Fatal(err)
	}
	rr := do(s, http.MethodPost, "/scan", `{"content":`+string(content)+`}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var res scanResult
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Count > maxRespFindings {
		t.Fatalf("response not bounded: %d findings, cap is %d", res.Count, maxRespFindings)
	}
	// The findings array must equal the cap (the input is far denser than the cap), and the last
	// finding must be the truncation note so truncation is not silent.
	if len(res.Findings) != maxRespFindings {
		t.Fatalf("expected exactly %d findings on a dense input, got %d", maxRespFindings, len(res.Findings))
	}
	last := res.Findings[len(res.Findings)-1]
	if last.Type != "response_truncated" {
		t.Fatalf("expected a response_truncated note as the last finding, got %q", last.Type)
	}
	// The capped body must stay small: maxRespFindings findings is single-digit MB at most.
	if rr.Body.Len() > 4<<20 {
		t.Fatalf("response body still too large: %d bytes", rr.Body.Len())
	}
	// The truncation must be counted in metrics.
	mr := do(s, http.MethodGet, "/metrics", "")
	var m map[string]int64
	json.Unmarshal(mr.Body.Bytes(), &m)
	if m["truncated"] != 1 {
		t.Errorf("expected truncated metric = 1, got %v", m["truncated"])
	}
}

// TestBatchResponseBoundedOnDenseInput: the batch path bounds its aggregate output too — many dense
// items can't sum to a multi-GB slice; the aggregate is capped and annotated.
func TestBatchResponseBoundedOnDenseInput(t *testing.T) {
	s := newSrv(t)
	// Smaller-but-still-dense items so the batch body stays under maxBatchReqBytes (8MB). Even a
	// ~1.5MB block of cue lines fans out well past the 5000 cap, so two of them exercise the
	// aggregate bound without tripping the request-size guard.
	line := "user password is hunter2abc99 here\n"
	var sb strings.Builder
	for sb.Len() < 1500*1024 {
		sb.WriteString(line)
	}
	item, err := json.Marshal(sb.String())
	if err != nil {
		t.Fatal(err)
	}
	one := `{"content":` + string(item) + `}`
	body := `[` + one + `,` + one + `]`
	rr := do(s, http.MethodPost, "/scan/batch", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var res scanResult
	json.Unmarshal(rr.Body.Bytes(), &res)
	if res.Count > maxRespFindings+1 { // +1 for the appended note when we stop at exactly the cap
		t.Fatalf("batch response not bounded: %d findings, cap is %d", res.Count, maxRespFindings)
	}
	gotNote := false
	for _, f := range res.Findings {
		if f.Type == "response_truncated" {
			gotNote = true
		}
	}
	if !gotNote {
		t.Fatalf("expected a response_truncated note in the truncated batch response")
	}
}

// TestConcurrentDenseLoadBounded: with the scan path itself capped, N concurrent dense POSTs each
// produce a bounded, annotated response, so the aggregate in-flight peak is bounded too.
func TestConcurrentDenseLoadBounded(t *testing.T) {
	s := newSrv(t)
	body := `{"content":` + mustJSON(t, denseCueItem()) + `}`
	const concurrency = 24
	type res struct {
		count int
		trunc bool
	}
	results := make(chan res, concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			rr := do(s, http.MethodPost, "/scan", body)
			var r scanResult
			_ = json.Unmarshal(rr.Body.Bytes(), &r)
			truncated := false
			for _, f := range r.Findings {
				if f.Type == "response_truncated" {
					truncated = true
				}
			}
			results <- res{count: r.Count, trunc: truncated}
		}()
	}
	for i := 0; i < concurrency; i++ {
		r := <-results
		// Each response is bounded to the per-request cap (some 503 under backpressure -> count 0).
		if r.count > maxRespFindings {
			t.Fatalf("a concurrent dense response was NOT bounded: %d findings, cap %d", r.count, maxRespFindings)
		}
		// A non-empty dense response must carry the truncation marker (not silently dropped).
		if r.count == maxRespFindings && !r.trunc {
			t.Fatalf("a capped dense response is missing its response_truncated marker")
		}
	}
}

func mustJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestNormalScanResponseUnchanged: an ordinary request with a handful of findings stays under the
// cap, returns them verbatim, and adds no truncation note.
func TestNormalScanResponseUnchanged(t *testing.T) {
	s := newSrv(t)
	rr := do(s, http.MethodPost, "/scan",
		`{"content":"db_password = \"S3cr3tP4ssw0rd!\"\napi_key = \"AKIANAFGYOEYPXU1DSYP\"","path":"a.py"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var res scanResult
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Count == 0 || res.Count > maxRespFindings {
		t.Fatalf("normal scan unexpected count: %d", res.Count)
	}
	for _, f := range res.Findings {
		if f.Type == "response_truncated" {
			t.Fatalf("normal scan must NOT be truncated, but got a truncation note")
		}
	}
	// The real secrets are still reported.
	var sawAWS bool
	for _, f := range res.Findings {
		if f.Type == "aws_access_key_id" {
			sawAWS = true
		}
	}
	if !sawAWS {
		t.Errorf("normal scan lost the real AWS key finding: %+v", res.Findings)
	}
	// No truncation recorded in metrics.
	mr := do(s, http.MethodGet, "/metrics", "")
	var m map[string]int64
	json.Unmarshal(mr.Body.Bytes(), &m)
	if m["truncated"] != 0 {
		t.Errorf("normal scan must not increment truncated, got %v", m["truncated"])
	}
}
