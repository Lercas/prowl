package scan

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	"github.com/Lercas/prowl/tool/internal/model"
)

type firebaseSchemaBindings struct {
	project map[string]string
	groups  map[int]bool
}

// Android's documented schema associates project_info with client[].api_key[].current_key.
// No unrelated key occurrence can borrow that project merely because its value is equal.
func (doc *literalDocument) firebaseAndroidBindings(ctx context.Context, path string, c verificationCandidate, fallback map[string]string) map[string]string {
	if filepath.Base(model.SafeLocator(path)) != "google-services.json" {
		return fallback
	}
	marker := map[string]string{"firebaseConfig": "google-services.json"}
	v := doc.locate(c.start, c.end)
	if v == nil || v.name != "current_key" || v.value != c.value || doc.verificationUnsafe || doc.unsafeGroups[v.group] {
		return marker
	}
	if doc.firebaseSchema == nil {
		doc.firebaseSchema = parseFirebaseAndroid(ctx, doc.original)
	}
	schema := doc.firebaseSchema
	if !schema.groups[v.group] {
		return marker
	}
	result := make(map[string]string, len(schema.project))
	for k, value := range schema.project {
		result[k] = value
	}
	return result
}

func parseFirebaseAndroid(ctx context.Context, text string) *firebaseSchemaBindings {
	result := &firebaseSchemaBindings{project: map[string]string{"firebaseConfig": "google-services.json"}, groups: map[int]bool{}}
	if len(text) > 1<<20 {
		return result
	}
	const (
		root    = 1
		info    = 2
		clients = 3
		client  = 4
		keys    = 5
		key     = 6
	)
	type frame struct {
		role            int
		object, wantKey bool
		name            string
	}
	var stack []frame
	group := 0
	decoder := json.NewDecoder(strings.NewReader(strings.TrimPrefix(text, "\uFEFF")))
	decoder.UseNumber()
	consume := func() {
		if len(stack) > 0 && stack[len(stack)-1].object {
			stack[len(stack)-1].wantKey = true
			stack[len(stack)-1].name = ""
		}
	}
	record := func(value string) {
		if len(stack) == 0 || stack[len(stack)-1].role != info {
			return
		}
		switch stack[len(stack)-1].name {
		case "project_id":
			result.project["projectId"] = value
		case "firebase_url":
			result.project["databaseURL"] = value
		case "storage_bucket":
			result.project["storageBucket"] = value
		}
	}
	for count := 0; count < 100000; count++ {
		if ctx.Err() != nil {
			return &firebaseSchemaBindings{project: map[string]string{}, groups: map[int]bool{}}
		}
		value, err := decoder.Token()
		if err == io.EOF {
			return result
		}
		if err != nil {
			break
		}
		switch value := value.(type) {
		case json.Delim:
			if value == '{' || value == '[' {
				if len(stack) >= 64 {
					return &firebaseSchemaBindings{project: map[string]string{}, groups: map[int]bool{}}
				}
				record("")
				role := 0
				if len(stack) == 0 && value == '{' {
					role = root
				} else if len(stack) > 0 {
					p := stack[len(stack)-1]
					switch {
					case p.role == root && p.name == "project_info" && value == '{':
						role = info
					case p.role == root && p.name == "client" && value == '[':
						role = clients
					case p.role == clients && value == '{':
						role = client
					case p.role == client && p.name == "api_key" && value == '[':
						role = keys
					case p.role == keys && value == '{':
						role = key
					}
				}
				consume()
				group++
				if role == key {
					result.groups[group] = true
				}
				stack = append(stack, frame{role: role, object: value == '{', wantKey: value == '{'})
			} else {
				if len(stack) == 0 {
					break
				}
				stack = stack[:len(stack)-1]
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].wantKey {
				stack[len(stack)-1].name = value
				stack[len(stack)-1].wantKey = false
				continue
			}
			record(value)
			consume()
		default:
			record("")
			consume()
		}
	}
	return &firebaseSchemaBindings{project: map[string]string{}, groups: map[int]bool{}}
}
