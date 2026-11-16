package publicaudit_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/publicaudit"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func TestAlgoliaXMLThroughOwnedHTTP(t *testing.T) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := rules.Load("../../rules/saas/algolia-api-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	resources := `<resources><string name="algolia_app_id">ABCDEF1234</string><string name="algolia_api_key">` + pipelineKey + `</string></resources>`
	plist := `<plist version="1.0"><dict><key>algolia_app_id</key><string>ABCDEF1234</string><key>algolia_api_key</key><string>` + pipelineKey + `</string></dict></plist>`
	for _, tc := range []struct {
		path, text string
		valid      bool
	}{
		{"strings.xml", resources, true}, {"Info.plist", plist, true},
		{"strings.xml", strings.Replace(resources, pipelineKey, strings.Replace(pipelineKey, "1", "&#49;", 1), 1), true},
		{"Info.plist", strings.Replace(plist, pipelineKey, "<![CDATA["+pipelineKey+"]]>", 1), true},
		{"strings.xml", strings.Replace(resources, pipelineKey, pipelineKey[:8]+"<!-- ignored -->"+pipelineKey[8:], 1), true},
		{"strings.xml", strings.Replace(resources, "</resources>", `<string name="algolia_app_id">ZZZZZZ9999</string></resources>`, 1), false},
		{"strings.xml", strings.Replace(resources, "</resources>", `<string name="algolia_application_id">ZZZZZZ9999</string></resources>`, 1), false},
		{"strings.xml", strings.Replace(resources, "ABCDEF1234", "@string/app", 1), false},
		{"strings.xml", strings.Replace(resources, "algolia_app_id", "app_id", 1), false},
		{"Info.plist", strings.Replace(plist, "</dict>", `<key>algolia_application_id</key><integer>123</integer></dict>`, 1), false},
		{"Info.plist", strings.Replace(plist, "</dict>", `<key>algolia_app_id</key><string>ZZZZZZ9999</string></dict>`, 1), false},
	} {
		for _, acl := range []string{`["search"]`, `["search","addObject"]`} {
			t.Run(fmt.Sprint(tc.path, tc.valid, acl), func(t *testing.T) {
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.Method != "GET" || r.URL.Path != "/1/keys/"+pipelineKey || r.Header.Get("X-Algolia-Application-Id") != "ABCDEF1234" || r.Header.Get("X-Algolia-API-Key") != pipelineKey || r.ContentLength > 0 {
						t.Error("wrong read-only request")
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = fmt.Fprintf(w, `{"value":%q,"acl":%s}`, pipelineKey, acl)
				}))
				defer server.Close()
				local, _ := url.Parse(server.URL)
				auditor := publicaudit.NewWithOwnedTransport(fixtureTransport(func(r *http.Request) (*http.Response, error) {
					if !tc.valid {
						t.Fatal("unsafe XML reached transport")
					}
					if r.URL.Scheme != "https" || r.URL.Host != "abcdef1234.algolia.net" {
						t.Fatal("wrong production authority")
					}
					request := r.Clone(r.Context())
					u := *r.URL
					u.Scheme, u.Host = local.Scheme, local.Host
					request.URL = &u
					return http.DefaultTransport.RoundTrip(request)
				}))
				coverage := model.NewCoverage()
				fs := scan.New(scan.Options{Detector: detect.New(tax), Rules: engine, PublicAuditor: auditor}).Findings(model.WithCoverage(t.Context(), coverage), model.Item{Source: "mobile", Path: tc.path, Text: tc.text})
				found := 0
				for _, f := range fs {
					if f.Type != "algolia-api-key" {
						continue
					}
					found++
					want := "inconclusive"
					if tc.valid {
						want = "search_only"
						if strings.Contains(acl, "addObject") {
							want = "excess_permissions"
						}
					}
					if f.PublicKeyAudit == nil || f.PublicKeyAudit.Status != want || f.Verified != nil || f.Verification != nil {
						t.Fatal("wrong audit", f.PublicKeyAudit)
					}
				}
				complete, _, _ := coverage.Snapshot()
				wantCalls := int32(0)
				if tc.valid {
					wantCalls = 1
				}
				if found != 1 || calls.Load() != wantCalls || complete != tc.valid {
					t.Fatal("wrong coverage or transport", found, calls.Load(), complete)
				}
				encoded, _ := json.Marshal(fs)
				if strings.Contains(string(encoded), pipelineKey) {
					t.Fatal("disclosed key")
				}
			})
		}
	}
}
