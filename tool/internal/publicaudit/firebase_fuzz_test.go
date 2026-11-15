package publicaudit

import "testing"

func FuzzFirebaseResponses(f *testing.F) {
	for _, seed := range []string{`null`, `"owned"`, `{"a":true}`, `{"items":[{"name":"owned"}]}`, `{"documents":[]}`, `{"error":{"code":403,"status":"PERMISSION_DENIED"}}`, `{"items":[],"items":null}`, "\xff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > maxBody || !strictFirebaseJSON([]byte(raw)) {
			return
		}
		for _, service := range []string{"rtdb", "storage", "firestore"} {
			present, valid := firebaseData([]byte(raw), firebaseProbe{service: service, project: "owned-project", bucket: "owned-project.appspot.com", collection: "public"})
			if present && !valid {
				t.Fatal("invalid response produced observed data")
			}
			_ = firebaseDenial([]byte(raw), 403, service)
		}
	})
}
