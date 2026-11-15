package scan

import "testing"

func FuzzFirebaseAndroidSchema(f *testing.F) {
	for _, seed := range []string{`{"project_info":{"project_id":"owned-project"},"client":[{"api_key":[{"current_key":"owned"}]}]}`, `{"client":{"api_key":{"current_key":"wrong role"}}}`, `{"project_info":{"firebase_url":{}}}`, `null`, "\xff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		schema := parseFirebaseAndroid(t.Context(), text)
		if len(schema.project) > 4 || len(schema.groups) > 50000 {
			t.Fatal("unbounded Android schema")
		}
		for id := range schema.groups {
			if id <= 0 || id > 100000 {
				t.Fatal("invalid schema group")
			}
		}
	})
}
