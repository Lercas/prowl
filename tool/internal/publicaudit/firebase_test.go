package publicaudit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const firebaseKey = "AIzaSy9Qw7Er5Ty3Ui1Op8As6Df4Gh2Jk0Lz5Xc"
const responseSecret = "OWNED_RESPONSE_VALUE_NEVER_SERIALIZE"

func firebaseAuditor(t *testing.T, collections []string, fn roundTrip) *Auditor {
	t.Helper()
	a, err := NewWithCollections(time.Second, collections)
	if err != nil {
		t.Fatal(err)
	}
	a.client.Transport = fn
	return a
}
func firebaseConfig() map[string]string {
	return map[string]string{"projectId": "owned-project", "databaseURL": "https://owned-project-default-rtdb.europe-west1.firebasedatabase.app", "storageBucket": "owned-project.firebasestorage.app"}
}
func firestoreBody(collection string) string {
	return `{"documents":[{"name":"projects/owned-project/databases/(default)/documents/` + collection + `/owned","fields":{}}]}`
}

func TestFirebaseReadPlanUsesNoCredentialAndNeverWrites(t *testing.T) {
	var calls atomic.Int32
	a := firebaseAuditor(t, []string{"public/parent/records"}, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.Method != "GET" || r.Body != nil || r.URL.Scheme != "https" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Algolia-API-Key") != "" || strings.Contains(r.URL.String(), firebaseKey) {
			t.Fatal("credential-bearing or mutable Firebase probe")
		}
		if len(r.Header) != 1 || r.Header.Get("Accept") != "application/json" {
			t.Fatal("unexpected Firebase authentication/header")
		}
		switch r.URL.Host {
		case "owned-project-default-rtdb.europe-west1.firebasedatabase.app":
			if r.URL.Path != "/.json" || r.URL.RawQuery != "shallow=true" {
				t.Fatal("unbounded RTDB read")
			}
			return response(`"`+responseSecret+`"`, 200), nil
		case "firebasestorage.googleapis.com":
			if r.URL.Path != "/v0/b/owned-project.firebasestorage.app/o" || r.URL.RawQuery != "maxResults=1" {
				t.Fatal("unbounded Storage listing")
			}
			return response(`{"items":[{"name":"`+responseSecret+`","bucket":"owned-project.firebasestorage.app"}]}`, 200), nil
		case "firestore.googleapis.com":
			if r.URL.Path != "/v1/projects/owned-project/databases/(default)/documents/public/parent/records" || r.URL.Query().Get("pageSize") != "1" || r.URL.Query().Get("mask.fieldPaths") != "prowlAuditMetadataOnly" || len(r.URL.Query()) != 2 {
				t.Fatal("unbounded Firestore read")
			}
			return response(firestoreBody("public/parent/records"), 200), nil
		default:
			t.Fatal("unexpected Firebase authority")
			return nil, nil
		}
	})
	got := a.Audit(t.Context(), "gcp_api_key", firebaseKey, firebaseConfig())
	if got.Status != "public_read_allowed" || len(got.Checks) != 3 || len(got.Capabilities) != 3 || calls.Load() != 3 || got.CheckedAt == "" || !got.HasAccessObservation() {
		t.Fatal("lost multi-service observation", got)
	}
	raw, _ := json.Marshal(got)
	for _, secret := range []string{firebaseKey, responseSecret, "owned-project", "public/parent/records"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("response or private locator leaked into report")
		}
	}
	for _, check := range got.Checks {
		if check.DataState != "present" || len(check.Scope) != 64 {
			t.Fatal("invalid data presence or target scope")
		}
	}
}

func TestFirebaseDenialsEmptyResultsAndPartialAccess(t *testing.T) {
	for _, tc := range []struct {
		service, body string
		code          int
		status, data  string
	}{
		{"rtdb", `{"error":"Permission denied"}`, 401, "read_denied", ""},
		{"storage", `{"error":{"code":403,"message":"` + responseSecret + `"}}`, 403, "read_denied", ""},
		{"firestore", `{"error":{"code":403,"status":"PERMISSION_DENIED","message":"` + responseSecret + `"}}`, 403, "read_denied", ""},
		{"rtdb", `null`, 200, "public_read_allowed", "empty"},
		{"rtdb", `{}`, 200, "public_read_allowed", "empty"},
		{"rtdb", `{"` + responseSecret + `":true}`, 200, "public_read_allowed", "present"},
		{"rtdb", `false`, 200, "public_read_allowed", "present"},
		{"rtdb", `1e9999`, 200, "public_read_allowed", "present"},
		{"storage", `{}`, 200, "public_read_allowed", "empty"},
		{"storage", `{"prefixes":["` + responseSecret + `/"]}`, 200, "public_read_allowed", "present"},
		{"firestore", `{}`, 200, "public_read_allowed", "empty"},
		{"firestore", `{"documents":[{"name":"projects/owned-project/databases/(default)/documents/public/owned","fields":{"prowlAuditMetadataOnly":{"stringValue":"` + responseSecret + `"}}}]}`, 200, "public_read_allowed", "present"},
	} {
		t.Run(tc.service+tc.body[:min(16, len(tc.body))], func(t *testing.T) {
			bindings := map[string]string{"projectId": "owned-project"}
			var paths []string
			switch tc.service {
			case "rtdb":
				bindings["databaseURL"] = "https://owned-project.firebaseio.com"
			case "storage":
				bindings["storageBucket"] = "owned-project.appspot.com"
			case "firestore":
				paths = []string{"public"}
			}
			a := firebaseAuditor(t, paths, func(*http.Request) (*http.Response, error) { return response(tc.body, tc.code), nil })
			got := a.Audit(t.Context(), "gcp-api-key", firebaseKey, bindings)
			if got.Status != tc.status || len(got.Checks) != 1 || got.Checks[0].DataState != tc.data {
				t.Fatal(got)
			}
			raw, _ := json.Marshal(got)
			if strings.Contains(string(raw), responseSecret) {
				t.Fatal("response data escaped")
			}
		})
	}
	a := firebaseAuditor(t, []string{"public"}, func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Host, "firebasedatabase") {
			return response(`"`+responseSecret+`"`, 200), nil
		}
		if r.URL.Host == "firebasestorage.googleapis.com" {
			return response(`{"error":{"code":403,"message":"denied"}}`, 403), nil
		}
		return response(`{"error":{"code":503}}`, 503), nil
	})
	got := a.Audit(t.Context(), "gcp_api_key", firebaseKey, firebaseConfig())
	if got.Status != "inconclusive" || len(got.Checks) != 3 || !got.HasAccessObservation() || len(got.Capabilities) != 1 {
		t.Fatal("partial audit erased observed access or claimed complete", got)
	}
}

func TestFirebaseInvalidBindingsNeverReachTransport(t *testing.T) {
	a := firebaseAuditor(t, nil, func(*http.Request) (*http.Response, error) {
		t.Fatal("unsafe binding reached network")
		return nil, nil
	})
	for _, bindings := range []map[string]string{
		{"projectId": "owned-project", "project_id": "other-project", "databaseURL": "https://owned-project.firebaseio.com"},
		{"projectId": "owned-project", "databaseURL": "https://owned-project.firebaseio.com", "database_url": ""},
		{"projectId": "owned-project", "databaseURL": "http://owned-project.firebaseio.com"},
		{"projectId": "owned-project", "databaseURL": "https://owned-project.firebaseio.com.attacker.invalid"},
		{"projectId": "owned-project", "databaseURL": "https://u:p@owned-project.firebaseio.com"},
		{"projectId": "owned-project", "databaseURL": "https://owned-project.firebaseio.com:443"},
		{"projectId": "owned-project", "databaseURL": "https://owned-project.firebaseio.com/path"},
		{"projectId": "owned-project", "databaseURL": "https://owned-project.firebaseio.com/?auth=secret"},
		{"projectId": "owned-project", "databaseURL": "https://owned-project.firebaseio.com/?"},
		{"projectId": "owned-project", "databaseURL": "https://owned-project.firebaseio.com/#fragment"},
		{"projectId": "owned-project", "databaseURL": "https://127.0.0.1"},
	} {
		got := a.Audit(t.Context(), "google-gemini-api-key", firebaseKey, bindings)
		if got == nil || got.Status != "inconclusive" || got.Provider != "firebase" {
			t.Fatal("unsafe Firebase config accepted", got)
		}
	}
	if got := a.Audit(t.Context(), "gcp_api_key", firebaseKey, map[string]string{"unrelated": "owned-project"}); got != nil {
		t.Fatal("generic Google key was mislabeled Firebase")
	}
	if got := a.Audit(t.Context(), "gcp_api_key", firebaseKey, nil); got != nil {
		t.Fatal("missing configuration claimed an audit")
	}
}

func TestFirebaseProtocolFailuresAreInconclusive(t *testing.T) {
	for _, body := range []string{`null`, `[]`, `{"error":"denied"}`, `{"items":null}`, `{"Items":[]}`, `{"items":[{"Name":"owned"}]}`, `{"items":[{"name":"owned","bucket":"other"}]}`, `{"items":[{"name":"one"},{"name":"two"}]}`, `{"items":[],"items":[]}`, `{"prefixes":[""]}`, `{"nextPageToken":null}`, `{"items":[{"name":"\ud800"}]}`, strings.Repeat(" ", maxBody+1)} {
		a := firebaseAuditor(t, nil, func(*http.Request) (*http.Response, error) { return response(body, 200), nil })
		if got := a.Audit(t.Context(), "gcp_api_key", firebaseKey, map[string]string{"projectId": "owned-project", "storageBucket": "owned-project.appspot.com"}); got.Status != "inconclusive" {
			t.Fatal("invalid Storage response accepted", body)
		}
	}
	for _, body := range []string{`{"documents":null}`, `{"Documents":[]}`, `{"documents":[{"name":"projects/other-project/databases/(default)/documents/public/id"}]}`, `{"documents":[{"name":"projects/owned-project/databases/(default)/documents/public/id/child/other"}]}`, `{"documents":[{"name":"projects/owned-project/databases/(default)/documents/public/id","fields":{"secret":{"stringValue":"` + responseSecret + `"}}}]}`} {
		a := firebaseAuditor(t, []string{"public"}, func(*http.Request) (*http.Response, error) { return response(body, 200), nil })
		if got := a.Audit(t.Context(), "gcp_api_key", firebaseKey, map[string]string{"projectId": "owned-project"}); got.Status != "inconclusive" {
			t.Fatal("invalid Firestore response accepted")
		}
	}
	for _, code := range []int{204, 301, 302, 400, 404, 429, 500, 503} {
		a := firebaseAuditor(t, nil, func(*http.Request) (*http.Response, error) { return response(`{}`, code), nil })
		if got := a.Audit(t.Context(), "gcp_api_key", firebaseKey, map[string]string{"projectId": "owned-project", "databaseURL": "https://owned-project.firebaseio.com"}); got.Status != "inconclusive" {
			t.Fatal("inconclusive HTTP accepted", code)
		}
	}
}

func TestFirebaseCacheSharingBindingScopesAndGlobalBudget(t *testing.T) {
	var calls atomic.Int32
	a := firebaseAuditor(t, nil, func(*http.Request) (*http.Response, error) { calls.Add(1); return response(`{}`, 200), nil })
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Go(func() {
			got := a.Audit(t.Context(), "gcp_api_key", firebaseKey, firebaseConfig())
			if got.Status != "public_read_allowed" {
				t.Error(got)
			}
			got.Checks[0].Status = "mutated"
		})
	}
	wg.Wait()
	if calls.Load() != 2 {
		t.Fatal("duplicate unauthenticated requests were not coalesced", calls.Load())
	}
	got := a.Audit(t.Context(), "gcp_api_key", firebaseKey, firebaseConfig())
	if got.Checks[0].Status == "mutated" {
		t.Fatal("mutable cached checks")
	}
	// Another key for the same public URL needs no second unauthenticated observation.
	_ = a.Audit(t.Context(), "gcp_api_key", "AIza"+strings.Repeat("A", 35), firebaseConfig())
	if calls.Load() != 2 {
		t.Fatal("credential-independent reads were repeated")
	}
	for i := 0; i < maxRequests+4; i++ {
		bindings := map[string]string{"projectId": "owned-project", "databaseURL": fmt.Sprintf("https://owned-%03d.firebaseio.com", i)}
		_ = a.Audit(t.Context(), "gcp_api_key", firebaseKey, bindings)
	}
	if calls.Load() != maxRequests {
		t.Fatal("shared read budget exceeded", calls.Load())
	}
}

func TestFirestoreCollectionValidationAndPolicyPrivacy(t *testing.T) {
	for _, path := range []string{"", "/users", "users/", "users/id", "a//b", "..", "a/id/..", "a/%2e%2e/b", "a/id\\evil/b", "a/id/b?query", "a/id/b#fragment", "__private__", "a/\n/b", strings.Repeat("a", 129)} {
		if _, err := ValidateCollections([]string{path}); err == nil {
			t.Fatal("unsafe Firestore collection path accepted", path)
		}
	}
	paths := []string{"users/owned-record/notes", "документы", "public"}
	a, err := NewWithCollections(time.Second, paths)
	if err != nil {
		t.Fatal(err)
	}
	paths[0] = "mutated"
	if a.collections[0] == "mutated" {
		t.Fatal("mutable collection selection")
	}
	raw, _ := json.Marshal(a.Policy())
	if strings.Contains(string(raw), "owned-record") {
		t.Fatal("collection locator leaked through policy")
	}
	if _, err := ValidateCollections(make([]string, 9)); err == nil {
		t.Fatal("unbounded collection selection")
	}
}

func TestFirestoreCollectionCannotForwardFindingValue(t *testing.T) {
	a := firebaseAuditor(t, []string{firebaseKey}, func(*http.Request) (*http.Response, error) {
		t.Fatal("finding value reached Firebase URL")
		return nil, nil
	})
	got := a.Audit(t.Context(), "gcp_api_key", firebaseKey, firebaseConfig())
	if got.Status != "inconclusive" {
		t.Fatal("key-containing collection selection accepted")
	}
}

func TestExplicitRTDBAndCustomBucketsDoNotNeedProjectInference(t *testing.T) {
	a := firebaseAuditor(t, nil, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "owned-project.firebaseio.com" {
			t.Fatal("RTDB host guessed")
		}
		return response(`null`, 200), nil
	})
	if got := a.Audit(t.Context(), "gcp_api_key", firebaseKey, map[string]string{"databaseURL": "https://owned-project.firebaseio.com"}); got.Status != "public_read_allowed" {
		t.Fatal("explicit RTDB required an unrelated project ID", got)
	}
	for _, bucket := range []string{"owned-custom-bucket", "gs://owned-custom-bucket", "other-project.appspot.com", "owned-project.appspot.com.attacker.invalid"} {
		a := firebaseAuditor(t, nil, func(r *http.Request) (*http.Response, error) {
			if r.URL.Host != "firebasestorage.googleapis.com" || r.URL.Scheme != "https" || r.URL.Path != "/v0/b/"+strings.TrimPrefix(bucket, "gs://")+"/o" || strings.Contains(r.URL.String(), firebaseKey) {
				t.Fatal("bucket identifier changed provider authority")
			}
			return response(`{}`, 200), nil
		})
		if got := a.Audit(t.Context(), "gcp_api_key", firebaseKey, map[string]string{"storageBucket": bucket}); got.Status != "public_read_allowed" {
			t.Fatal("explicit bucket identity rejected", got)
		}
	}
}
