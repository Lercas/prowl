package publicaudit_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/publicaudit"
	"github.com/Lercas/prowl/tool/internal/report"
)

func TestGoogleMetadataAndFirebaseThroughOwnedHTTPPipelineAndReports(t *testing.T) {
	const name = "projects/12345678/locations/global/keys/owned-key"
	const token = "owned-operator-token"
	for _, mode := range []string{"unrestricted", "configured", "denied"} {
		for _, ml := range []bool{false, true} {
			t.Run(fmt.Sprint(mode, ml), func(t *testing.T) {
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.Method != "GET" {
						t.Error("non-read operation")
					}
					switch r.URL.Path {
					case "/.json":
						if r.Header.Get("Authorization") != "" || r.URL.RawQuery != "shallow=true" {
							t.Error("operator credential reached Firebase")
						}
						fmt.Fprint(w, `{"private-response":true}`)
					case "/v2/keys:lookupKey":
						if r.Header.Get("Authorization") != "Bearer "+token || r.URL.Query().Get("keyString") != googleFixtureKey {
							t.Error("wrong Google ownership request")
						}
						if mode == "denied" {
							w.WriteHeader(403)
							fmt.Fprint(w, "private-response")
							return
						}
						fmt.Fprintf(w, `{"parent":"projects/12345678/locations/global","name":%q}`, name)
					case "/v2/" + name:
						if r.Header.Get("Authorization") != "Bearer "+token || r.URL.RawQuery != "" {
							t.Error("wrong Google metadata request")
						}
						if mode == "configured" {
							fmt.Fprintf(w, `{"name":%q,"restrictions":{"browserKeyRestrictions":{"allowedReferrers":["https://private-response.invalid/*"]},"apiTargets":[{"service":"maps.googleapis.com"}]}}`, name)
						} else {
							fmt.Fprintf(w, `{"name":%q}`, name)
						}
					default:
						t.Error("unexpected provider endpoint")
						w.WriteHeader(500)
					}
				}))
				defer server.Close()
				local, _ := url.Parse(server.URL)
				auditor, setupErr := publicaudit.NewWithOwnedGoogleRestrictions(fixtureTransport(func(r *http.Request) (*http.Response, error) {
					if r.URL.Scheme != "https" || r.Body != nil || (r.URL.Host != "apikeys.googleapis.com" && r.URL.Host != "owned-project.firebaseio.com") {
						t.Error("unapproved provider authority or pre-ML request")
					}
					clone := r.Clone(r.Context())
					u := *r.URL
					u.Scheme, u.Host = local.Scheme, local.Host
					clone.URL = &u
					return http.DefaultTransport.RoundTrip(clone)
				}), token)
				if setupErr != nil {
					t.Fatal(setupErr)
				}
				object := `{"apiKey":"` + googleFixtureKey + `","databaseURL":"https://owned-project.firebaseio.com"}`
				source := object
				if ml {
					source = `{"one":{"apiKey":"` + googleFixtureKey + `","databaseURL":"https://other-project.firebaseio.com"},"two":` + object + `}`
				}
				coverage := model.NewCoverage()
				ctx := model.WithCoverage(t.Context(), coverage)
				fs := firebasePipeline(t, auditor, ml).Findings(ctx, model.Item{Source: "code", Path: "prod.json", Text: source})
				complete, _, _ := coverage.Snapshot()
				var finding *model.Finding
				for i := range fs {
					if fs[i].Type == "gcp_api_key" || fs[i].Type == "gcp-api-key" {
						finding = &fs[i]
					}
				}
				if finding == nil || finding.PublicKeyAudit == nil || finding.Verified != nil || finding.Verification != nil {
					t.Fatal("restriction audit lost or became a live-verification claim")
				}
				want, requests, checks := "unrestricted", int32(3), 3
				if mode == "configured" {
					want = "public_read_allowed"
				}
				if mode == "denied" {
					want, requests, checks = "inconclusive", 2, 2
				}
				if finding.PublicKeyAudit.Status != want || calls.Load() != requests || len(finding.PublicKeyAudit.Checks) != checks || complete != (mode != "denied") {
					t.Fatal("combined audit or coverage failed", finding.PublicKeyAudit, calls.Load(), complete)
				}
				if !finding.PublicKeyAudit.HasAccessObservation() {
					t.Fatal("Firebase access disappeared behind Google metadata status")
				}
				finding.Occurrences = []model.Occurrence{finding.Occurrence()}
				for _, format := range []string{"json", "sarif", "pretty"} {
					var out bytes.Buffer
					if err := report.WriteWithCoverage(&out, fs, format, false, coverage); err != nil {
						t.Fatal(err)
					}
					text := out.String()
					for _, hidden := range []string{googleFixtureKey, token, name, "private-response"} {
						if strings.Contains(text, hidden) {
							t.Fatal("private provider metadata reached report", format)
						}
					}
					if !strings.Contains(text, want) || strings.Contains(text, "LIVE") {
						t.Fatal("public audit report contract changed", format)
					}
					if format != "pretty" {
						var value any
						if json.Unmarshal(out.Bytes(), &value) != nil || !strings.Contains(text, "google_api_restrictions") {
							t.Fatal("metadata check absent from structured report")
						}
					}
				}
			})
		}
	}
}
