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
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/publicaudit"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

const googleFixtureKey = "AIzaSy9Qw7Er5Ty3Ui1Op8As6Df4Gh2Jk0Lz5Xc"

func ownedFirebase(t *testing.T) (*publicaudit.Auditor, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.Header.Get("Authorization") != "" {
			t.Error("authenticated or mutable Firebase read")
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/.json":
			_, _ = w.Write([]byte(`{"OWNED_PRIVATE_NAME_NOT_FOR_REPORT":true}`))
		case strings.HasPrefix(r.URL.Path, "/v0/b/owned-project."):
			_, _ = w.Write([]byte(`{}`))
		case r.URL.Path == "/v1/projects/owned-project/databases/(default)/documents/public":
			_, _ = w.Write([]byte(`{"documents":[{"name":"projects/owned-project/databases/(default)/documents/public/PRIVATE_ID_NOT_FOR_REPORT"}]}`))
		default:
			t.Error("borrowed a foreign project's resource")
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(server.Close)
	local, _ := url.Parse(server.URL)
	auditor, err := publicaudit.NewWithOwnedCollections(fixtureTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.Body != nil || strings.Contains(r.URL.String(), googleFixtureKey) {
			t.Error("unsafe credential-bearing request")
		}
		switch r.URL.Host {
		case "owned-project.firebaseio.com", "firebasestorage.googleapis.com", "firestore.googleapis.com":
		default:
			t.Error("unapproved provider host")
		}
		copy := r.Clone(r.Context())
		u := *r.URL
		u.Scheme, u.Host = local.Scheme, local.Host
		copy.URL = &u
		return http.DefaultTransport.RoundTrip(copy)
	}), []string{"public"})
	if err != nil {
		t.Fatal(err)
	}
	return auditor, &calls
}

func firebasePipeline(t *testing.T, auditor *publicaudit.Auditor, ml bool) *scan.Pipeline {
	t.Helper()
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := rules.Load("../../rules/cloud/gcp-api-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	options := scan.Options{Detector: detect.New(tax), Rules: engine, PublicAuditor: auditor, AllOccurrences: true}
	if ml {
		options.ML = survivorScorer{}
	}
	return scan.New(options)
}

func TestFirebaseSourceBindingsAfterMLThroughOwnedHTTP(t *testing.T) {
	for _, fixture := range []struct{ path, text string }{
		{"prod.js", `const one={projectId:"other-project",databaseURL:"https://other-project.firebaseio.com",storageBucket:"other-project.appspot.com",apiKey:"KEY"},two={projectId:"owned-project",databaseURL:"https://owned-project.firebaseio.com",storageBucket:"owned-project.appspot.com",apiKey:"KEY"};`},
		{"prod.json", `{"one":{"projectId":"other-project","databaseURL":"https://other-project.firebaseio.com","storageBucket":"other-project.appspot.com","apiKey":"KEY"},"two":{"projectId":"owned-project","databaseURL":"https://owned-project.firebaseio.com","storageBucket":"owned-project.appspot.com","apiKey":"KEY"}}`},
		{"prod.yaml", "one: {projectId: other-project, databaseURL: 'https://other-project.firebaseio.com', storageBucket: other-project.appspot.com, apiKey: 'KEY'}\ntwo: {projectId: owned-project, databaseURL: 'https://owned-project.firebaseio.com', storageBucket: owned-project.appspot.com, apiKey: 'KEY'}\n"},
		{"prod.toml", "[one]\nprojectId='other-project'\ndatabaseURL='https://other-project.firebaseio.com'\nstorageBucket='other-project.appspot.com'\napiKey='KEY'\n[two]\nprojectId='owned-project'\ndatabaseURL='https://owned-project.firebaseio.com'\nstorageBucket='owned-project.appspot.com'\napiKey='KEY'\n"},
	} {
		t.Run(fixture.path, func(t *testing.T) {
			auditor, calls := ownedFirebase(t)
			coverage := model.NewCoverage()
			ctx := model.WithCoverage(t.Context(), coverage)
			fs := firebasePipeline(t, auditor, true).Findings(ctx, model.Item{Source: "code", Path: fixture.path, Text: strings.ReplaceAll(fixture.text, "KEY", googleFixtureKey)})
			complete, _, _ := coverage.Snapshot()
			if !complete || len(fs) != 1 || calls.Load() != 3 || fs[0].PublicKeyAudit == nil || fs[0].PublicKeyAudit.Status != "public_read_allowed" || len(fs[0].PublicKeyAudit.Checks) != 3 || fs[0].Verified != nil || fs[0].Verification != nil {
				t.Fatal("post-ML Firebase scope or liveness changed", fs, calls.Load())
			}
			raw, _ := json.Marshal(fs)
			for _, value := range []string{googleFixtureKey, "OWNED_PRIVATE_NAME_NOT_FOR_REPORT", "PRIVATE_ID_NOT_FOR_REPORT"} {
				if strings.Contains(string(raw), value) {
					t.Fatal("raw key/provider response serialized")
				}
			}
		})
	}
}

func TestAndroidFirebaseSchemaRejectsEqualKeyOutsideClient(t *testing.T) {
	auditor, calls := ownedFirebase(t)
	coverage := model.NewCoverage()
	ctx := model.WithCoverage(t.Context(), coverage)
	text := fmt.Sprintf(`{"project_info":{"project_id":"owned-project","firebase_url":"https://owned-project.firebaseio.com","storage_bucket":"owned-project.appspot.com"},"client":[{"api_key":[{"current_key":%q}]}],"notes":{"current_key":%q}}`, googleFixtureKey, googleFixtureKey)
	fs := firebasePipeline(t, auditor, false).Findings(ctx, model.Item{Source: "code", Path: "owned.apk!/assets/google-services.json", Text: text})
	accepted, rejected := 0, 0
	for _, f := range fs {
		if f.PublicKeyAudit == nil {
			continue
		}
		switch f.PublicKeyAudit.Status {
		case "public_read_allowed":
			accepted++
		case "inconclusive":
			rejected++
		}
	}
	complete, _, _ := coverage.Snapshot()
	if calls.Load() != 3 || accepted != 1 || rejected != 1 || complete {
		t.Fatal("Android key borrowed unrelated schema binding", calls.Load(), accepted, rejected, complete)
	}
}

func TestGenericGoogleFindingWithoutFirebaseConfigIsNotAudited(t *testing.T) {
	auditor, calls := ownedFirebase(t)
	// With an explicit collection, an unrelated object still cannot provide the project.
	text := `const a={projectId:"owned-project"},b={apiKey:"` + googleFixtureKey + `"};`
	fs := firebasePipeline(t, auditor, false).Findings(context.Background(), model.Item{Source: "code", Path: "prod.js", Text: text})
	if len(fs) != 1 || fs[0].PublicKeyAudit != nil || calls.Load() != 0 {
		t.Fatal("generic Google key acquired a Firebase project")
	}
}

func TestAndroidMalformedProjectCannotFallBackToAnotherResource(t *testing.T) {
	for _, info := range []string{
		`{"project_id":{},"storage_bucket":"owned-project.appspot.com"}`,
		`{"project_id":"owned-project","firebase_url":{},"storage_bucket":"owned-project.appspot.com"}`,
		`{"project_id":"owned-project","firebase_url":"https://owned-project.firebaseio.com","storage_bucket":[]}`,
	} {
		auditor, err := publicaudit.NewWithOwnedCollections(fixtureTransport(func(*http.Request) (*http.Response, error) {
			t.Fatal("malformed Android field reached transport")
			return nil, nil
		}), []string{"public"})
		if err != nil {
			t.Fatal(err)
		}
		text := fmt.Sprintf(`{"project_info":%s,"client":[{"api_key":[{"current_key":%q}]}]}`, info, googleFixtureKey)
		fs := firebasePipeline(t, auditor, false).Findings(t.Context(), model.Item{Source: "code", Path: "google-services.json", Text: text})
		found := false
		for _, f := range fs {
			if f.PublicKeyAudit != nil {
				found = true
				if f.PublicKeyAudit.Status != "inconclusive" {
					t.Fatal("malformed Android configuration accepted")
				}
			}
		}
		if !found {
			t.Fatal("known Android schema lost inconclusive audit")
		}
	}
}

func TestNonStringAliasesCannotDisappearFromStructuredPublicBindings(t *testing.T) {
	for _, fixture := range []struct{ path, text string }{
		{"prod.json", `{"projectId":"owned-project","project_id":42,"databaseURL":"https://owned-project.firebaseio.com","apiKey":"KEY"}`},
		{"prod.json", `{"projectId":"owned-project","project_id":{},"databaseURL":"https://owned-project.firebaseio.com","apiKey":"KEY"}`},
		{"prod.yaml", "projectId: owned-project\nproject_id: {other: value}\ndatabaseURL: 'https://owned-project.firebaseio.com'\napiKey: 'KEY'\n"},
		{"prod.yaml", "projectId: owned-project\nproject_id: 42\ndatabaseURL: 'https://owned-project.firebaseio.com'\napiKey: 'KEY'\n"},
		{"prod.toml", "projectId='owned-project'\nproject_id=42\ndatabaseURL='https://owned-project.firebaseio.com'\napiKey='KEY'\n"},
		{"prod.toml", "projectId='owned-project'\nproject_id={other='value'}\ndatabaseURL='https://owned-project.firebaseio.com'\napiKey='KEY'\n"},
	} {
		t.Run(fixture.path+fixture.text[:12], func(t *testing.T) {
			auditor, err := publicaudit.NewWithOwnedCollections(fixtureTransport(func(*http.Request) (*http.Response, error) {
				t.Fatal("non-string alias reached provider")
				return nil, nil
			}), nil)
			if err != nil {
				t.Fatal(err)
			}
			fs := firebasePipeline(t, auditor, false).Findings(t.Context(), model.Item{Source: "code", Path: fixture.path, Text: strings.ReplaceAll(fixture.text, "KEY", googleFixtureKey)})
			found := false
			for _, f := range fs {
				if f.PublicKeyAudit != nil {
					found = true
					if f.PublicKeyAudit.Status != "inconclusive" {
						t.Fatal("non-string alias was silently ignored")
					}
				}
			}
			if !found {
				t.Fatal("fixture lost eligible Firebase finding")
			}
		})
	}
}
