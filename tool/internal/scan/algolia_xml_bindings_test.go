package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/publicaudit"
	"github.com/Lercas/prowl/tool/internal/rules"
)

func algoliaResource(key string) string {
	return `<resources><string name="algolia_app_id">ABCDEF1234</string><string name="algolia_api_key" translatable="false">` + key + `</string></resources>`
}
func algoliaPlist(key string) string {
	return `<plist version="1.0"><dict><key>algolia_application_id</key><string>ABCDEF1234</string><key>algolia_search_api_key</key><string>` + key + `</string><key>other</key><true/></dict></plist>`
}
func TestAlgoliaXMLLiteralOwnership(t *testing.T) {
	for _, kind := range []string{"resources", "plist"} {
		for _, spelling := range []string{auditTestKey, "<![CDATA[" + auditTestKey + "]]>", strings.Replace(auditTestKey, "1", "&#49;", 1), auditTestKey[:8] + "<!-- ignored -->" + auditTestKey[8:], auditTestKey[:8] + "<![CDATA[" + auditTestKey[8:] + "]]>"} {
			text := algoliaResource(spelling)
			if kind == "plist" {
				text = algoliaPlist(spelling)
			}
			root := parsePublicXMLRoot(t.Context(), text, kind)
			if root == nil {
				t.Fatal("parse")
			}
			b := parseAlgoliaXML(root, kind, text)
			if len(b.keys) != 1 || b.keys[0].value != auditTestKey {
				t.Fatal("lost decoded value", kind)
			}
			k := b.keys[0]
			got := b.forSpan(k.start, k.end, k.value)
			if len(got) != 1 {
				t.Fatal("lost app", kind, got)
			}
			for name := range got {
				got[name] = "mutated"
			}
			if reflect.DeepEqual(got, b.forSpan(k.start, k.end, k.value)) {
				t.Fatal("mutable fields escaped")
			}
			if b.forSpan(k.start+1, k.end, k.value) != nil || b.forSpan(k.start, k.end, "other") != nil {
				t.Fatal("foreign span owned")
			}
		}
	}
}
func TestAlgoliaXMLFailClosed(t *testing.T) {
	resource := algoliaResource(auditTestKey)
	cases := []struct{ kind, text string }{
		{"resources", resource + resource},
		{"resources", resource + "broken"},
		{"resources", strings.Replace(resource, "</resources>", `<string name="algolia_app_id">ZZZZZZ9999</string></resources>`, 1)},
		{"resources", strings.Replace(resource, "ABCDEF1234", "@string/other", 1)},
		{"resources", strings.Replace(resource, `name="algolia_app_id"`, `name="app_id"`, 1)},
		{"resources", strings.Replace(resource, `<string name="algolia_app_id">ABCDEF1234</string>`, `<group><string name="algolia_app_id">ABCDEF1234</string></group>`, 1)},
		{"resources", `<!DOCTYPE resources [<!ENTITY injected "ABCDEF1234">]>` + resource},
		{"resources", strings.Replace(resource, `name="algolia_app_id"`, `name="algolia_app_id" extra="x"`, 1)},
		{"resources", strings.Replace(resource, "</resources>", `<string name="algolia_application_id">bad</string></resources>`, 1)},
		{"plist", strings.Replace(algoliaPlist(auditTestKey), "</dict>", `<key>algolia_application_id</key><string>ZZZZZZ9999</string></dict>`, 1)},
		{"plist", strings.Replace(algoliaPlist(auditTestKey), `<string>ABCDEF1234</string>`, `<dict><key>app</key><string>ABCDEF1234</string></dict>`, 1)},
	}
	for i, tc := range cases {
		root := parsePublicXMLRoot(t.Context(), tc.text, tc.kind)
		var b *algoliaXMLBindings
		if root != nil {
			b = parseAlgoliaXML(root, tc.kind, tc.text)
		}
		if b == nil {
			continue
		}
		for _, k := range b.keys {
			fields := b.forSpan(k.start, k.end, k.value)
			if len(fields) == 1 && (fields["algolia_app_id"] == "ABCDEF1234" || fields["algolia_application_id"] == "ABCDEF1234") {
				t.Fatal("unsafe binding accepted", i, fields)
			}
		}
	}
	text := strings.Replace(resource, auditTestKey, `<!-- algolia_api_key="`+auditTestKey+`" -->`+auditTestKey, 1)
	b := parseAlgoliaXML(parsePublicXMLRoot(t.Context(), text, "resources"), "resources", text)
	comment := strings.Index(text, auditTestKey)
	if b.forSpan(comment, comment+len(auditTestKey), auditTestKey) != nil {
		t.Fatal("comment borrowed binding")
	}
}
func TestAlgoliaXMLPipelineOrderingAndRuleSelection(t *testing.T) {
	engine, err := rules.Load("../../rules/saas/algolia-api-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"res/values/strings.xml", "app.ipa!/Payload/App.app/Info.plist"} {
		text := algoliaResource(auditTestKey)
		if strings.HasSuffix(path, "plist") {
			text = algoliaPlist(auditTestKey)
		}
		for _, drop := range []bool{false, true} {
			scored, calls := false, 0
			score := 1.
			if drop {
				score = 0
			}
			p := New(Options{Detector: detector(t), Rules: engine, ML: orderScorer{fixedMLScorer: fixedMLScorer{results: []mlscore.Result{{Score: score}}, threshold: .3}, before: func() { scored = true }}, PublicAuditor: auditFunc(func(_ context.Context, typ, key string, b map[string]string) *model.PublicKeyAudit {
				if !scored || typ != "algolia-api-key" || key != auditTestKey || len(b) != 1 {
					t.Fatal("audit lost ML order or binding", b)
				}
				calls++
				return &model.PublicKeyAudit{Provider: "algolia", Status: "search_only"}
			})})
			fs := p.Findings(t.Context(), model.Item{Source: "mobile", Path: path, Text: text})
			want := 1
			if drop {
				want = 0
			}
			if calls != want || len(fs) != want {
				t.Fatal("wrong retention", path, drop, calls, fs)
			}
			if !drop && (fs[0].Stage != "rule/xml-literal" || fs[0].Verified != nil || fs[0].Verification != nil || len(fs[0].Evidence) != 1 || fs[0].ByteEnd-fs[0].ByteStart != 32) {
				t.Fatal("lost source identity", fs)
			}
		}
		// Neither an ordinary scan nor an excluded rule gains XML candidates.
		excluded, loadErr := rules.Load("../../rules/saas/algolia-api-key.yaml")
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		for _, opts := range []Options{{Detector: detector(t), Rules: engine}, {Detector: detector(t), Rules: excluded.Filter(rules.FilterOpts{ExcludeIDs: []string{"algolia-api-key"}}), PublicAuditor: auditFunc(func(context.Context, string, string, map[string]string) *model.PublicKeyAudit {
			t.Fatal("disabled audit")
			return nil
		})}} {
			for _, f := range New(opts).Findings(t.Context(), model.Item{Source: "mobile", Path: path, Text: text}) {
				if f.Type == "algolia-api-key" {
					t.Fatal("XML bypassed opt-in/rule selection")
				}
			}
		}
	}
}
func TestAlgoliaXMLUnsupportedSignalsAreIncomplete(t *testing.T) {
	engine, err := rules.Load("../../rules/saas/algolia-api-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{`<resources><string name="algolia_api_key">@string/key</string></resources>`, `<broken algolia_api_key`, strings.Repeat(" ", maxFirebaseXMLBytes) + algoliaResource(auditTestKey), `<resources><string name="algolia_api_key"><b>` + auditTestKey + `</b></string></resources>`} {
		coverage := model.NewCoverage()
		ctx := model.WithCoverage(t.Context(), coverage)
		New(Options{Detector: detector(t), Rules: engine, PublicAuditor: auditFunc(func(context.Context, string, string, map[string]string) *model.PublicKeyAudit {
			return publicaudit.Inconclusive("unavailable")
		})}).Findings(ctx, model.Item{Source: "mobile", Path: "strings.xml", Text: text})
		complete, _, _ := coverage.Snapshot()
		if complete {
			t.Fatal("unsupported XML reported complete")
		}
	}
}
func FuzzAlgoliaXMLBindings(f *testing.F) {
	f.Add(algoliaResource(auditTestKey), false)
	f.Add(algoliaPlist(auditTestKey), true)
	f.Fuzz(func(t *testing.T, text string, plist bool) {
		kind := "resources"
		if plist {
			kind = "plist"
		}
		root := parsePublicXMLRoot(t.Context(), text, kind)
		if root == nil {
			return
		}
		b := parseAlgoliaXML(root, kind, text)
		if b == nil {
			return
		}
		for _, k := range b.keys {
			if k.start < 0 || k.end < k.start || k.end > len(text) {
				t.Fatal("invalid source span")
			}
			_ = b.forSpan(k.start, k.end, k.value)
		}
	})
}

func TestAlgoliaXMLSelectedRuleConstraintsAndContext(t *testing.T) {
	original, err := os.ReadFile("../../rules/saas/algolia-api-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "custom.yaml")
	if err := os.WriteFile(path, []byte(strings.Replace(string(original), "min: 3.3", "min: 4.1", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	custom, err := rules.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows []mlscore.Record
	opts := Options{Detector: detector(t), Rules: custom, ML: publicRecordScorer{rows: &rows}, PublicAuditor: auditFunc(func(context.Context, string, string, map[string]string) *model.PublicKeyAudit {
		t.Fatal("custom constraint bypassed")
		return nil
	})}
	for _, f := range New(opts).Findings(t.Context(), model.Item{Source: "mobile", Path: "strings.xml", Text: algoliaResource(auditTestKey)}) {
		if f.Type == "algolia-api-key" {
			t.Fatal("custom entropy bypassed")
		}
	}
	engine, err := rules.Load("../../rules/saas/algolia-api-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	opts.Rules = engine
	opts.PublicAuditor = auditFunc(func(context.Context, string, string, map[string]string) *model.PublicKeyAudit {
		return &model.PublicKeyAudit{Provider: "algolia", Status: "search_only"}
	})
	rows = nil
	New(opts).Findings(t.Context(), model.Item{Source: "mobile", Path: "strings.xml", Text: algoliaResource(auditTestKey)})
	if len(rows) != 1 || rows[0].Context.Name != "algolia_api_key" || rows[0].DirectBinding != "algolia_api_key" || rows[0].Value != auditTestKey {
		t.Fatal("ungrounded ML context", rows)
	}
}
func TestAlgoliaXMLSnapshotItemIsolation(t *testing.T) {
	engine, err := rules.Load("../../rules/saas/algolia-api-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pipeline := New(Options{Detector: detector(t), Rules: engine, PublicAuditor: auditFunc(func(_ context.Context, _ string, _ string, b map[string]string) *model.PublicKeyAudit {
		if len(b) != 1 {
			t.Error("lost item binding")
		}
		return &model.PublicKeyAudit{Provider: "algolia", Status: "search_only", Capabilities: []string{b["algolia_app_id"]}}
	})})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			app := fmt.Sprintf("ABCDEF%04d", i)
			text := strings.Replace(algoliaResource(auditTestKey), "ABCDEF1234", app, 1)
			fs := pipeline.Findings(t.Context(), model.Item{Source: "mobile", Path: "strings.xml", Text: text})
			if len(fs) != 1 || fs[0].PublicKeyAudit == nil || !reflect.DeepEqual(fs[0].PublicKeyAudit.Capabilities, []string{app}) {
				t.Error("item binding crossed snapshot", i, fs)
			}
		}(i)
	}
	wg.Wait()
	if pipeline.options.publicBindings != nil {
		t.Fatal("pipeline retained XML")
	}
}
