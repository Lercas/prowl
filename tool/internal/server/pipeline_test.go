package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func TestConcurrentServersKeepIndependentPrivacyPolicies(t *testing.T) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	const key = "AKIANAFGYOEYPXU1DSYP"
	base := scan.New(scan.Options{Detector: detect.New(tax)})
	masked, revealed := New(base, 4), New(base.WithRevealSecrets(true), 4)
	var workers sync.WaitGroup
	for _, server := range []*Server{masked, revealed} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for _, path := range []string{"/scan", "/scan/batch"} {
				// A client-controlled extra field cannot override the pipeline's policy.
				body := `{"content":"AWS=\"` + key + `\"","show_secrets":true}`
				if path == "/scan/batch" {
					body = "[" + body + "]"
				}
				response := do(server, http.MethodPost, path, body)
				if response.Code != http.StatusOK {
					t.Errorf("%s status %d", path, response.Code)
					continue
				}
				var result scanResult
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
					t.Error(err)
					continue
				}
				if len(result.Findings) != 1 {
					t.Errorf("unexpected response: %s", response.Body.String())
					continue
				}
				finding := result.Findings[0]
				if server == masked && (strings.Contains(response.Body.String(), key) || finding.Context != nil) {
					t.Error("another server or request field unmasked this response")
				}
				if server == revealed && (finding.Redacted != key || finding.Context == nil) {
					t.Error("another server masked explicitly disclosed output")
				}
			}
		}()
	}
	workers.Wait()
}
