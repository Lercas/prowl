package publicaudit

import (
	"net/http"
	"strings"
	"testing"
)

func FuzzFirebaseBindings(f *testing.F) {
	for _, seed := range []string{"https://owned-project.firebaseio.com", "https://u:p@owned-project.firebaseio.com", "https://owned-project.firebaseio.com.attacker.invalid", "gs://owned-custom-bucket", "owned-custom-bucket", "public/owned/records", firebaseKey, "\xff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 4096 {
			return
		}
		transport := roundTrip(func(r *http.Request) (*http.Response, error) {
			if r.Method != "GET" || r.URL.Scheme != "https" || r.Body != nil || strings.Contains(r.URL.String(), firebaseKey) || r.Header.Get("Authorization") != "" || r.Header.Get("X-Goog-Api-Key") != "" {
				t.Fatal("unsafe Firebase read")
			}
			if r.URL.Host != "firebasestorage.googleapis.com" && r.URL.Host != "firestore.googleapis.com" && !databaseHost.MatchString(r.URL.Host) {
				t.Fatal("untrusted Firebase authority")
			}
			return response(`{}`, 200), nil
		})
		for _, bindings := range []map[string]string{
			{"projectId": "owned-project", "databaseURL": text},
			{"storageBucket": text},
			{"projectId": text, "databaseURL": "https://owned-project.firebaseio.com"},
		} {
			a := firebaseAuditor(t, nil, transport)
			_ = a.Audit(t.Context(), "gcp_api_key", firebaseKey, bindings)
		}
		if paths, err := ValidateCollections([]string{text}); err == nil {
			a := firebaseAuditor(t, paths, transport)
			_ = a.Audit(t.Context(), "gcp_api_key", firebaseKey, map[string]string{"projectId": "owned-project"})
		}
	})
}
