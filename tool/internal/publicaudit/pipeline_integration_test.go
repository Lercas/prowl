package publicaudit_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/publicaudit"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

const pipelineKey = "13ad45b4d0a2f6ea65ecbddf6aa260f2"

type fixtureTransport func(*http.Request) (*http.Response, error)

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type survivorScorer struct{}

func (survivorScorer) Score(_ context.Context, rows []mlscore.Record) ([]mlscore.Result, error) {
	result := make([]mlscore.Result, len(rows))
	for i := range result {
		if i > 0 {
			result[i].Score = 1
		}
	}
	return result, nil
}
func (survivorScorer) Threshold() float64 { return .3 }
func (survivorScorer) Local() bool        { return true }

func TestStaticJSBindingsThroughOwnedProviderFixture(t *testing.T) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := rules.Load("../../rules/saas/algolia-api-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"prod.js", "prod.mjs", "prod.ts", "https://owned.invalid/bundle.js?revision=owned"} {
		for _, acl := range []string{`["search"]`, `["search","addObject"]`} {
			t.Run(path+acl, func(t *testing.T) {
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.Method != "GET" || r.URL.Path != "/1/keys/"+pipelineKey || r.Header.Get("X-Algolia-API-Key") != pipelineKey || r.Header.Get("X-Algolia-Application-Id") != "ZZZZZZ9999" {
						t.Error("wrong exact post-ML provider binding")
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = fmt.Fprintf(w, `{"value":%q,"acl":%s}`, pipelineKey, acl)
				}))
				defer server.Close()
				local, _ := url.Parse(server.URL)
				auditor := publicaudit.NewWithOwnedTransport(fixtureTransport(func(r *http.Request) (*http.Response, error) {
					if r.URL.Host != "zzzzzz9999.algolia.net" || r.URL.Scheme != "https" {
						t.Error("unexpected production authority")
					}
					request := r.Clone(r.Context())
					u := *r.URL
					u.Scheme, u.Host = local.Scheme, local.Host
					request.URL = &u
					return http.DefaultTransport.RoundTrip(request)
				}))
				source := `const one={app_id:"ABCDEF1234",algolia_api_key:"` + pipelineKey + `"},two={app_id:"ZZZZZZ9999",algolia_api_key:"` + pipelineKey + `"};`
				coverage := model.NewCoverage()
				ctx := model.WithCoverage(t.Context(), coverage)
				fs := scan.New(scan.Options{Detector: detect.New(tax), Rules: engine, PublicAuditor: auditor, ML: survivorScorer{}, AllOccurrences: true}).Findings(ctx, model.Item{Source: "code", Path: path, Text: source})
				if len(fs) != 1 || calls.Load() != 1 || fs[0].PublicKeyAudit == nil || fs[0].Verified != nil || fs[0].Verification != nil {
					t.Fatal("pipeline audit failed or changed liveness", len(fs), calls.Load())
				}
				wanted := "search_only"
				if strings.Contains(acl, "addObject") {
					wanted = "excess_permissions"
				}
				complete, _, _ := coverage.Snapshot()
				if fs[0].PublicKeyAudit.Status != wanted || !complete {
					t.Fatal("incorrect ACL/coverage result", fs[0].PublicKeyAudit)
				}
				encoded, _ := json.Marshal(fs)
				if strings.Contains(string(encoded), pipelineKey) {
					t.Fatal("key leaked into report")
				}
			})
		}
	}
}

func TestUnsafeJSBindingsNeverReachTransport(t *testing.T) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := rules.Load("../../rules/saas/algolia-api-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{
		`const a={app_id:"ABCDEF1234"},b={algolia_api_key:"KEY"};`,
		`const a={app_id:"ABCDEF1234",child:{algolia_api_key:"KEY"}};`,
		`const a={app_id:unknown,application_id:"ABCDEF1234",algolia_api_key:"KEY"};`,
		`const a={app_id:"ABCDEF1234",algolia_api_key:"KEY",...unknown};`,
		`const a={app_id:"ABCDEF1234",algolia_api_key:"KEY",[unknown]:1};`,
		`const a={app_id:"ABCDEF1234",algolia_api_key:"KEY",get other(){return 1;}};`,
		`const a={app_id:"ABCDEF1234",app_id:"ZZZZZZ9999",algolia_api_key:"KEY"};`,
		`const a={app_id:"ABCDEF1234",algolia_api_key:"KEY"}; malformed source`,
	} {
		source = strings.ReplaceAll(source, "KEY", pipelineKey)
		auditor := publicaudit.NewWithOwnedTransport(fixtureTransport(func(*http.Request) (*http.Response, error) {
			t.Fatal("unsafe source reached network transport")
			return nil, nil
		}))
		coverage := model.NewCoverage()
		ctx := model.WithCoverage(t.Context(), coverage)
		fs := scan.New(scan.Options{Detector: detect.New(tax), Rules: engine, PublicAuditor: auditor}).Findings(ctx, model.Item{Source: "code", Path: "prod.js", Text: source})
		found := false
		for _, f := range fs {
			if f.Type == "algolia-api-key" {
				found = true
				if f.PublicKeyAudit == nil || f.PublicKeyAudit.Status != "inconclusive" {
					t.Fatal("unsafe binding lost inconclusive verdict")
				}
			}
		}
		complete, _, _ := coverage.Snapshot()
		if !found || complete {
			t.Fatal("unsafe binding was skipped or reported complete")
		}
	}
}
