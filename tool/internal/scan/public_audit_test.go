package scan

import (
	"context"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/publicaudit"
	"github.com/Lercas/prowl/tool/internal/rules"
)

const auditTestKey = "13ad45b4d0a2f6ea65ecbddf6aa260f2"

type auditFunc func(context.Context, string, string, map[string]string) *model.PublicKeyAudit

func (f auditFunc) Audit(ctx context.Context, typ, key string, bindings map[string]string) *model.PublicKeyAudit {
	return f(ctx, typ, key, bindings)
}

func TestPublicAuditAfterMLKeepsExactObject(t *testing.T) {
	engine, err := rules.Load("../../rules/saas/algolia-api-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, text string }{
		{"prod.json", `{"one":{"app_id":"ABCDEF1234","algolia_api_key":"` + auditTestKey + `"},"two":{"app_id":"ZZZZZZ9999","algolia_api_key":"` + auditTestKey + `"}}`},
		{"prod.yaml", "one: {app_id: ABCDEF1234, algolia_api_key: " + auditTestKey + "}\ntwo: {app_id: ZZZZZZ9999, algolia_api_key: " + auditTestKey + "}\n"},
		{"prod.toml", "[one]\napp_id='ABCDEF1234'\nalgolia_api_key='" + auditTestKey + "'\n[two]\napp_id='ZZZZZZ9999'\nalgolia_api_key='" + auditTestKey + "'\n"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			scored, calls := false, 0
			audit := auditFunc(func(_ context.Context, typ, key string, b map[string]string) *model.PublicKeyAudit {
				calls++
				if !scored || typ != "algolia-api-key" || key != auditTestKey || b["app_id"] != "ZZZZZZ9999" {
					t.Fatal("audit used pre-ML position or foreign companion", b)
				}
				return &model.PublicKeyAudit{Provider: "algolia", Status: "excess_permissions", Capabilities: []string{"addObject", "search"}}
			})
			opts := Options{Detector: detector(t), Rules: engine, AllOccurrences: true, PublicAuditor: audit, ML: orderScorer{fixedMLScorer: fixedMLScorer{results: []mlscore.Result{{Score: 0}, {Score: 1}}, threshold: .3}, before: func() { scored = true }}}
			fs := New(opts).Findings(t.Context(), model.Item{Source: "code", Path: tc.path, Text: tc.text})
			if calls != 1 || len(fs) != 1 || fs[0].PublicKeyAudit == nil || fs[0].Verified != nil || fs[0].Verification != nil || fs[0].Col == 0 {
				t.Fatal("audit changed liveness, mapping or ML retention", fs)
			}
		})
	}
}

func TestPublicAuditUnsafeAndUnsupportedInputs(t *testing.T) {
	engine, err := rules.Load("../../rules/saas/algolia-api-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, text string }{
		{"prod.json", `{"app_id":"ABCDEF1234","algolia_api_key":"` + auditTestKey + `","app_id":"ZZZZZZ9999"}`},
		{"prod.json", `{"app_id":"ABCDEF1234","nested":{"algolia_api_key":"` + auditTestKey + `"}}`},
		{"prod.js", `const algolia_api_key="` + auditTestKey + `",app_id="ABCDEF1234";`},
	} {
		t.Run(tc.text[:12], func(t *testing.T) {
			coverage := model.NewCoverage()
			ctx := model.WithCoverage(t.Context(), coverage)
			fs := New(Options{Detector: detector(t), Rules: engine, PublicAuditor: publicaudit.New(0)}).Findings(ctx, model.Item{Source: "code", Path: tc.path, Text: tc.text})
			if len(fs) == 0 {
				t.Fatal("fixture did not detect Algolia key")
			}
			found := false
			for _, f := range fs {
				if f.Type == "algolia-api-key" {
					found = true
				}
				if f.Type == "algolia-api-key" && (f.PublicKeyAudit == nil || f.PublicKeyAudit.Status != "inconclusive") {
					t.Fatal("unsafe binding was accepted", f)
				}
			}
			if !found {
				t.Fatal("fixture did not detect an Algolia key", fs)
			}
			complete, _, _ := coverage.Snapshot()
			if complete {
				t.Fatal("missing audit coverage was reported complete")
			}
		})
	}
	// An unsupported key never invokes an audit and does not make coverage incomplete.
	coverage := model.NewCoverage()
	ctx := model.WithCoverage(t.Context(), coverage)
	fs := New(Options{Detector: detector(t), PublicAuditor: auditFunc(func(context.Context, string, string, map[string]string) *model.PublicKeyAudit {
		t.Fatal("unsupported provider audited")
		return nil
	})}).Findings(ctx, model.Item{Source: "code", Path: "prod.env", Text: "AWS=AKIANAFGYOEYPXU1DSYP"})
	complete, _, _ := coverage.Snapshot()
	if len(fs) != 1 || !complete || fs[0].PublicKeyAudit != nil {
		t.Fatal("unsupported audit changed coverage")
	}
}
