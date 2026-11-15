package scan

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
)

const xmlGoogleKey = "AIzaSy9Qw7Er5Ty3Ui1Op8As6Df4Gh2Jk0Lz5Xc"

func xmlResourceFixture(project, key string) string {
	return `<?xml version="1.0" encoding="utf-8"?><resources><string name="google_api_key" translatable="false">` + key + `</string><string name="project_id">` + project + `</string><string name="firebase_database_url">https://` + project + `.firebaseio.com</string><string name="google_storage_bucket">` + project + `.appspot.com</string></resources>`
}

func xmlPlistFixture(project, key string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>API_KEY</key><string>` + key + `</string><key>PROJECT_ID</key><string>` + project + `</string><key>DATABASE_URL</key><string>https://` + project + `.firebaseio.com</string><key>STORAGE_BUCKET</key><string>` + project + `.appspot.com</string><key>IS_ANALYTICS_ENABLED</key><true/></dict></plist>`
}

func TestFirebaseXMLSourceBinding(t *testing.T) {
	for _, tc := range []struct{ kind, text string }{
		{"resources", xmlResourceFixture("owned-project", xmlGoogleKey)},
		{"plist", xmlPlistFixture("owned-project", xmlGoogleKey)},
		{"resources", strings.Replace(xmlResourceFixture("owned-project", xmlGoogleKey), "AIza", "AI&#122;a", 1)},
		{"plist", strings.Replace(xmlPlistFixture("owned-project", xmlGoogleKey), "AIza", "AI&#122;a", 1)},
		{"resources", strings.Replace(xmlResourceFixture("owned-project", xmlGoogleKey), xmlGoogleKey, "<![CDATA["+xmlGoogleKey+"]]>", 1)},
	} {
		parsed := parseFirebaseXML(t.Context(), tc.text, tc.kind)
		needle := xmlGoogleKey
		if strings.Contains(tc.text, "AI&#122;a") {
			needle = strings.Replace(xmlGoogleKey, "AIza", "AI&#122;a", 1)
		}
		start := strings.Index(tc.text, needle)
		got := parsed.forSpan(start, start+len(needle), xmlGoogleKey)
		if got["projectId"] != "owned-project" || got["storageBucket"] != "owned-project.appspot.com" || got["databaseURL"] != "https://owned-project.firebaseio.com" {
			t.Fatal("lost explicit XML configuration", tc.kind)
		}
		got["projectId"] = "mutated"
		if parsed.forSpan(start, start+len(needle), xmlGoogleKey)["projectId"] != "owned-project" {
			t.Fatal("mutable binding escaped")
		}
		if parsed.forSpan(start, start+len(needle), "other") != nil || parsed.forSpan(0, 1, xmlGoogleKey) != nil {
			t.Fatal("unrelated source got fields")
		}
	}
}

func TestFirebaseXMLRejectsAmbiguityAndUnsafeSource(t *testing.T) {
	resource := xmlResourceFixture("owned-project", xmlGoogleKey)
	plist := xmlPlistFixture("owned-project", xmlGoogleKey)
	for _, tc := range []struct{ kind, text string }{
		{"resources", resource + resource},
		{"resources", resource + "broken"},
		{"resources", strings.TrimSuffix(resource, "</resources>")},
		{"resources", strings.Replace(resource, "</resources>", `<string name="project_id">foreign-project</string></resources>`, 1)},
		{"resources", strings.Replace(resource, `name="project_id"`, `name="project_id" name="other"`, 1)},
		{"resources", strings.Replace(resource, "</resources>", `<string name="google_crash_reporting_api_key">`+strings.Replace(xmlGoogleKey, "Sy9", "Sy8", 1)+`</string></resources>`, 1)},
		{"resources", `<!DOCTYPE resources [<!ENTITY target "foreign-project">]>` + resource},
		{"plist", strings.Replace(plist, "</dict>", `<key>PROJECT_ID</key><string>foreign-project</string></dict>`, 1)},
		{"plist", strings.Replace(plist, `<plist version="1.0">`, `<plist>`, 1)},
		{"plist", strings.Replace(plist, "<dict>", "<array><dict>", 1)},
	} {
		if parseFirebaseXML(t.Context(), tc.text, tc.kind) != nil {
			t.Fatal("ambiguous/invalid XML accepted", tc.kind)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if parseFirebaseXML(ctx, resource, "resources") != nil || parseFirebaseXML(t.Context(), strings.Repeat(" ", maxFirebaseXMLBytes+1), "resources") != nil {
		t.Fatal("parser limit/cancel bypassed")
	}
}

func TestFirebaseXMLUnknownCompanionsRemainUnknown(t *testing.T) {
	for _, replacement := range []string{"@string/foreign", "?attr/project", "owned\\u002dproject", " owned-project ", "%1$s", "<b>owned-project</b>"} {
		text := strings.Replace(xmlResourceFixture("owned-project", xmlGoogleKey), ">owned-project</string>", ">"+replacement+"</string>", 1)
		p := parseFirebaseXML(t.Context(), text, "resources")
		start := strings.Index(text, xmlGoogleKey)
		if p.forSpan(start, start+len(xmlGoogleKey), xmlGoogleKey)["projectId"] != "" {
			t.Fatal("dynamic Android value supplied a project")
		}
	}
	text := strings.Replace(xmlPlistFixture("owned-project", xmlGoogleKey), "<string>owned-project</string>", "<integer>42</integer>", 1)
	start := strings.Index(text, xmlGoogleKey)
	if parseFirebaseXML(t.Context(), text, "plist").forSpan(start, start+len(xmlGoogleKey), xmlGoogleKey)["projectId"] != "" {
		t.Fatal("non-string plist project became static")
	}
}

func TestFirebaseXMLResourceBudgets(t *testing.T) {
	plist := xmlPlistFixture("owned-project", xmlGoogleKey)
	deep := strings.Replace(plist, "</dict>", "<key>other</key>"+strings.Repeat("<array>", maxFirebaseXMLDepth)+"<string>x</string>"+strings.Repeat("</array>", maxFirebaseXMLDepth)+"</dict>", 1)
	if parseFirebaseXML(t.Context(), deep, "plist") != nil {
		t.Fatal("deep irrelevant plist value escaped the depth cap")
	}
	var extras strings.Builder
	for i := 0; i < maxFirebaseXMLFields; i++ {
		fmt.Fprintf(&extras, `<string name="other_%d">x</string>`, i)
	}
	resource := xmlResourceFixture("owned-project", xmlGoogleKey)
	fields := strings.Replace(resource, "</resources>", extras.String()+"</resources>", 1)
	if parseFirebaseXML(t.Context(), fields, "resources") != nil {
		t.Fatal("irrelevant resource fields escaped the field cap")
	}
	tokens := strings.Replace(resource, "</resources>", strings.Repeat("<!---->", maxFirebaseXMLTokens)+"</resources>", 1)
	if len(tokens) >= maxFirebaseXMLBytes || parseFirebaseXML(t.Context(), tokens, "resources") != nil {
		t.Fatal("comment-only work escaped the token cap")
	}
}

func TestFirebaseXMLOnlySchemaKeyOwnsConfiguration(t *testing.T) {
	text := strings.Replace(xmlResourceFixture("owned-project", xmlGoogleKey), "</resources>", `<string name="unrelated">`+xmlGoogleKey+`</string></resources>`, 1)
	p := parseFirebaseXML(t.Context(), text, "resources")
	start := strings.LastIndex(text, xmlGoogleKey)
	if p.forSpan(start, start+len(xmlGoogleKey), xmlGoogleKey) != nil {
		t.Fatal("equal unrelated key borrowed Firebase fields")
	}
	text = strings.Replace(xmlPlistFixture("owned-project", xmlGoogleKey), "</dict>", `<key>nested</key><dict><key>API_KEY</key><string>`+xmlGoogleKey+`</string></dict></dict>`, 1)
	start = strings.LastIndex(text, xmlGoogleKey)
	if parseFirebaseXML(t.Context(), text, "plist").forSpan(start, start+len(xmlGoogleKey), xmlGoogleKey) != nil {
		t.Fatal("nested plist key borrowed root configuration")
	}
}

func TestFirebaseXMLCommentInsideKeyCannotOwnData(t *testing.T) {
	for _, tc := range []struct{ kind, text string }{
		{"resources", xmlResourceFixture("owned-project", xmlGoogleKey)},
		{"plist", xmlPlistFixture("owned-project", xmlGoogleKey)},
	} {
		text := strings.Replace(tc.text, xmlGoogleKey+"</string>", xmlGoogleKey+"<!-- "+xmlGoogleKey+" --></string>", 1)
		p := parseFirebaseXML(t.Context(), text, tc.kind)
		first, last := strings.Index(text, xmlGoogleKey), strings.LastIndex(text, xmlGoogleKey)
		if first == last || p.forSpan(first, first+len(xmlGoogleKey), xmlGoogleKey)["projectId"] != "owned-project" {
			t.Fatal("real XML data lost configuration")
		}
		if p.forSpan(last, last+len(xmlGoogleKey), xmlGoogleKey) != nil {
			t.Fatal("same-value XML comment acquired data ownership")
		}
	}
}

func TestFirebaseXMLPipelineBindingAndNonRegression(t *testing.T) {
	engine, err := rules.Load("../../rules/cloud/gcp-api-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, text string }{
		{"res/values/values.xml", xmlResourceFixture("owned-project", xmlGoogleKey)},
		{"Payload/App.app/GoogleService-Info.plist", xmlPlistFixture("owned-project", xmlGoogleKey)},
	} {
		var results [2][]model.Finding
		var records [2][]mlscore.Record
		calls := 0
		for mode := 0; mode < 2; mode++ {
			opts := Options{Detector: detector(t), Rules: engine, ML: publicRecordScorer{&records[mode]}}
			if mode == 1 {
				opts.PublicAuditor = auditFunc(func(_ context.Context, typ, key string, fields map[string]string) *model.PublicKeyAudit {
					calls++
					if key != xmlGoogleKey || fields["projectId"] != "owned-project" {
						t.Fatal("XML audit lost original configuration", typ)
					}
					return nil
				})
			}
			results[mode] = New(opts).Findings(t.Context(), model.Item{Source: "code", Path: tc.path, Text: tc.text})
		}
		if calls != 1 || len(results[0]) != 1 || !reflect.DeepEqual(results[0], results[1]) || !reflect.DeepEqual(records[0], records[1]) {
			t.Fatal("XML capture changed detection/ML identity", tc.path, calls)
		}
		called := false
		New(Options{Detector: detector(t), Rules: engine, ML: fixedMLScorer{results: []mlscore.Result{{Score: 0}}, threshold: .3}, PublicAuditor: auditFunc(func(context.Context, string, string, map[string]string) *model.PublicKeyAudit {
			called = true
			return nil
		})}).Findings(t.Context(), model.Item{Source: "code", Path: tc.path, Text: tc.text})
		if called {
			t.Fatal("suppressed XML key reached public auditor")
		}
	}
}

func TestFirebaseXMLBindingsRemainItemLocal(t *testing.T) {
	engine, err := rules.Load("../../rules/cloud/gcp-api-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p := New(Options{Detector: detector(t), Rules: engine, PublicAuditor: auditFunc(func(_ context.Context, _ string, key string, fields map[string]string) *model.PublicKeyAudit {
		var id int
		if _, err := fmt.Sscanf(key[len(key)-2:], "%02d", &id); err != nil || fields["projectId"] != fmt.Sprintf("owned-project-%02d", id) {
			t.Error("cross-item XML binding")
		}
		return nil
	})})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Go(func() {
			key := xmlGoogleKey[:len(xmlGoogleKey)-2] + fmt.Sprintf("%02d", i)
			item := model.Item{Source: "code", Path: "values.xml", Text: xmlResourceFixture(fmt.Sprintf("owned-project-%02d", i), key)}
			p.Findings(t.Context(), item)
		})
	}
	wg.Wait()
	if p.options.publicBindings != nil {
		t.Fatal("shared pipeline retained XML plaintext")
	}
}

func FuzzFirebaseXMLSourceBindings(f *testing.F) {
	f.Add(xmlResourceFixture("owned-project", xmlGoogleKey), false)
	f.Add(xmlPlistFixture("owned-project", xmlGoogleKey), true)
	f.Add(`<!DOCTYPE plist [<!ENTITY x SYSTEM "file:///owned">]><plist version="1.0"/>`, true)
	f.Fuzz(func(t *testing.T, text string, plist bool) {
		if len(text) > maxFirebaseXMLBytes+1 {
			return
		}
		kind := "resources"
		if plist {
			kind = "plist"
		}
		p := parseFirebaseXML(t.Context(), text, kind)
		if p == nil {
			return
		}
		for _, key := range p.keys {
			if key.start < 0 || key.start > key.end || key.end > len(text) {
				t.Fatal("XML source span escaped input")
			}
			for _, span := range key.dataSpans {
				if span[0] < key.start || span[1] > key.end || span[0] > span[1] {
					t.Fatal("XML data token escaped its scalar")
				}
			}
		}
	})
}
