package publicaudit_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/domain"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/publicaudit"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func TestWebStateBindingOwnershipThroughOwnedProvider(t *testing.T) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := rules.Load("../../rules/saas/algolia-api-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	config := `const config={app_id:'ABCDEF1234',algolia_api_key:'` + pipelineKey + `'};`
	for _, tc := range []struct {
		name, text string
		requests   int
	}{
		{"unaltered-script", config, 1},
		{"decoded-string", `const data="\u0022; ` + config + ` //";`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			auditor := publicaudit.NewWithOwnedTransport(fixtureTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.Host != "abcdef1234.algolia.net" || r.URL.Path != "/1/keys/"+pipelineKey {
					t.Fatal("unexpected provider request")
				}
				body := `{"value":"` + pipelineKey + `","acl":["search"]}`
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			}))
			coverage := model.NewCoverage()
			ctx := model.WithCoverage(t.Context(), coverage)
			p := scan.New(scan.Options{Detector: detect.New(tax), Rules: engine, PublicAuditor: auditor})
			items := domain.ExtractStateBlobs("<script>"+tc.text+"</script>", "https://owned.invalid/app.js?sig=private-selection")
			found := 0
			for _, it := range items {
				for _, f := range p.Findings(ctx, it) {
					if f.Type != "algolia-api-key" {
						continue
					}
					found++
					want := "inconclusive"
					if tc.requests > 0 {
						want = "search_only"
					}
					if f.PublicKeyAudit == nil || f.PublicKeyAudit.Status != want || f.Verified != nil || f.Verification != nil {
						t.Fatal("web state lost audit/liveness separation")
					}
				}
			}
			complete, _, _ := coverage.Snapshot()
			if found != 1 || calls != tc.requests || complete != (tc.requests > 0) {
				t.Fatalf("findings=%d requests=%d complete=%v", found, calls, complete)
			}
		})
	}
}
