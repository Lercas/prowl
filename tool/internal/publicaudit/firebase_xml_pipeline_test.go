package publicaudit_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/publicaudit"
)

func firebaseXMLFixture(plist bool) (string, string) {
	if plist {
		return "Payload/App.app/GoogleService-Info.plist", `<?xml version="1.0"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>API_KEY</key><string>` + googleFixtureKey + `</string><key>PROJECT_ID</key><string>owned-project</string><key>DATABASE_URL</key><string>https://owned-project.firebaseio.com</string><key>STORAGE_BUCKET</key><string>owned-project.appspot.com</string></dict></plist>`
	}
	return "res/values/values.xml", `<resources><string name="google_api_key" translatable="false">` + googleFixtureKey + `</string><string name="project_id">owned-project</string><string name="firebase_database_url">https://owned-project.firebaseio.com</string><string name="google_storage_bucket">owned-project.appspot.com</string></resources>`
}

func TestFirebaseXMLReadTargetsThroughOwnedHTTP(t *testing.T) {
	for _, plist := range []bool{false, true} {
		t.Run(map[bool]string{false: "resources", true: "plist"}[plist], func(t *testing.T) {
			path, text := firebaseXMLFixture(plist)
			auditor, calls := ownedFirebase(t)
			coverage := model.NewCoverage()
			ctx := model.WithCoverage(t.Context(), coverage)
			fs := firebasePipeline(t, auditor, false).Findings(ctx, model.Item{Source: "code", Path: path, Text: text})
			complete, _, _ := coverage.Snapshot()
			if !complete || calls.Load() != 3 || len(fs) != 1 || fs[0].PublicKeyAudit == nil || fs[0].PublicKeyAudit.Status != "public_read_allowed" || len(fs[0].PublicKeyAudit.Checks) != 3 || fs[0].Verified != nil || fs[0].Verification != nil {
				t.Fatal("XML audit lost read-only targets or separated liveness", calls.Load(), len(fs))
			}
			raw, _ := json.Marshal(fs)
			for _, private := range []string{googleFixtureKey, "OWNED_PRIVATE_NAME_NOT_FOR_REPORT", "PRIVATE_ID_NOT_FOR_REPORT", "owned-project"} {
				if strings.Contains(string(raw), private) {
					t.Fatal("XML audit exposed source/response data")
				}
			}
		})
	}
}

func TestFirebaseXMLUnsafeBindingMakesNoRequests(t *testing.T) {
	path, valid := firebaseXMLFixture(false)
	plistPath, plist := firebaseXMLFixture(true)
	for _, tc := range []struct{ path, text string }{
		{path, strings.Replace(valid, "</resources>", `<string name="project_id">foreign-project</string></resources>`, 1)},
		{path, strings.Replace(valid, ">owned-project</string>", ">@string/foreign</string>", 1)},
		{path, strings.Replace(valid, `name="google_api_key"`, `name="unrelated"`, 1)},
		{path, valid + "broken"},
		{path, `<!DOCTYPE resources [<!ENTITY x SYSTEM "file:///owned-test-only">]>` + valid},
		{plistPath, strings.Replace(plist, "<string>owned-project</string>", "<integer>42</integer>", 1)},
		{plistPath, strings.Replace(plist, "<key>API_KEY</key>", "<key>other</key>", 1)},
	} {
		auditor, calls := ownedFirebase(t)
		coverage := model.NewCoverage()
		ctx := model.WithCoverage(t.Context(), coverage)
		fs := firebasePipeline(t, auditor, false).Findings(ctx, model.Item{Source: "code", Path: tc.path, Text: tc.text})
		complete, _, _ := coverage.Snapshot()
		if calls.Load() != 0 || complete || len(fs) == 0 {
			t.Fatal("unsafe XML reached a provider or certified completion", calls.Load(), len(fs))
		}
		google := 0
		for _, f := range fs {
			if !publicaudit.GoogleType(f.Type) {
				continue
			}
			google++
			if f.PublicKeyAudit == nil || f.PublicKeyAudit.Status != "inconclusive" {
				t.Fatal("unsafe XML audit silently disappeared")
			}
		}
		if google == 0 {
			t.Fatal("unsafe fixture lost its Google candidate")
		}
	}
}

func TestFirebaseXMLEqualUnrelatedValueCannotBorrowFields(t *testing.T) {
	path, text := firebaseXMLFixture(false)
	text = strings.Replace(text, "</resources>", `<string name="other">`+googleFixtureKey+`</string></resources>`, 1)
	auditor, calls := ownedFirebase(t)
	fs := firebasePipeline(t, auditor, false).Findings(t.Context(), model.Item{Source: "code", Path: path, Text: text})
	var google []model.Finding
	for _, f := range fs {
		if publicaudit.GoogleType(f.Type) {
			google = append(google, f)
		}
	}
	if len(google) != 2 || calls.Load() != 3 {
		t.Fatal("lost separate XML source occurrences", len(fs), calls.Load())
	}
	for _, f := range google {
		want := "public_read_allowed"
		if f.Col == strings.LastIndex(text, googleFixtureKey)+1 {
			want = "inconclusive"
		}
		if f.PublicKeyAudit == nil || f.PublicKeyAudit.Status != want {
			t.Fatal("unrelated equal value borrowed root config")
		}
	}
}
