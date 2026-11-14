package scan

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"github.com/Lercas/prowl/tool/internal/verify"
)

func TestVerificationMetadataPreservesStatusTimeAndOwnsCapabilities(t *testing.T) {
	at := time.Date(2001, 2, 3, 4, 5, 6, 123, time.UTC)
	for _, status := range []verify.Status{verify.Verified, verify.Invalid, verify.Errored, verify.Unsupported, verify.Skipped} {
		r := verify.Result{Status: status, Verifier: "owned", CheckedAt: at, Access: []string{"read"}, Note: "timeout"}
		legacy, _, detail := verificationResult(r)
		if detail.Status != string(status) || detail.Verifier != "owned" || detail.CheckedAt != at.Format(time.RFC3339Nano) || (status == verify.Verified) != (legacy != nil && *legacy) || (status == verify.Invalid) != (legacy != nil && !*legacy) {
			t.Fatal("typed verdict diverged from its source or legacy tri-state")
		}
		detail.Capabilities[0] = "changed"
		if r.Access[0] != "read" || (status == verify.Errored) != (detail.Reason != "") {
			t.Fatal("verdict metadata aliases capabilities or mislabels the reason")
		}
	}
}

func TestProviderErrorMetadataIsPrivateAndFailsClosed(t *testing.T) {
	previous := safehttp.AllowPrivate.Load()
	safehttp.AllowPrivate.Store(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(previous) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTooManyRequests) }))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "owned.yaml")
	rule := "id: owned\nmatch: [aws_access_key_id]\nrequests:\n  - url: " + srv.URL + "/\n    headers:\n      Authorization: 'Bearer {{secret}}'\n    matchers:\n      - type: status\n        status: [200]\n"
	if err := os.WriteFile(path, []byte(rule), 0600); err != nil {
		t.Fatal(err)
	}
	set, err := verify.Load(100*time.Millisecond, path)
	if err != nil {
		t.Fatal(err)
	}
	locator := "https://user:private-password@example.invalid/prod.env?token=private-query"
	fs := New(Options{Detector: detector(t), Verifiers: set}).Findings(t.Context(), model.Item{Path: locator, ArtifactURI: locator, Text: "AWS=AKIANAFGYOEYPXU1DSYP"})
	if len(fs) != 2 || fs[0].Verified != nil || fs[0].Verification == nil || fs[0].Verification.Status != "error" || fs[0].Verification.CheckedAt == "" || !model.IsIncompleteFinding(fs[1]) {
		t.Fatal("provider failure was presented as a complete or confirmed check")
	}
	data, _ := json.Marshal(fs)
	if strings.Contains(string(data), "AKIANAFGYOEYPXU1DSYP") || strings.Contains(fs[0].Verification.Reason, "token=") {
		t.Fatal("provider error metadata exposed request credentials")
	}
	if strings.Contains(fs[1].Path, "private-") {
		t.Fatal("incompleteness marker exposed locator credentials")
	}
}
