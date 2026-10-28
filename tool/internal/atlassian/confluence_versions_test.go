package atlassian

import (
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestConfluenceMissingListVersionRecoversData(t *testing.T) {
	for _, cloud := range []bool{true, false} {
		for _, mode := range []string{"complete", "current-only", "current-metadata-absent", "empty-history", "failed-history", "partial-history", "wrong-version", "edited"} {
			t.Run(map[bool]string{true: "Cloud", false: "Server"}[cloud]+"/"+mode, func(t *testing.T) {
				var liveCalls, historicalCalls atomic.Int32
				items := collectFixture(t, "confluence", Options{CurrentOnly: mode == "current-only" || mode == "current-metadata-absent"}, func(r *http.Request) (int, any) {
					prefix := "/rest/api"
					if cloud {
						prefix = "/wiki/api/v2"
					}
					q := r.URL.Query()
					spacePath, pagePath := prefix+"/space", prefix+"/content"
					bodyPath, historyPath := prefix+"/content/1", prefix+"/content/1/version"
					if cloud {
						spacePath, pagePath = prefix+"/spaces", prefix+"/spaces/1/pages"
						bodyPath, historyPath = prefix+"/pages/1", prefix+"/pages/1/versions"
					}
					switch r.URL.Path {
					case spacePath:
						return 200, map[string]any{"results": []any{map[string]any{"id": "1", "key": "S"}}}
					case pagePath:
						if q.Get("status") == "trashed" || q.Get("status") == "draft" {
							return 400, nil
						}
						page := map[string]any{"id": "1", "title": "Page"}
						if mode == "edited" {
							page["version"] = map[string]any{"number": 3}
						}
						return 200, map[string]any{"results": []any{page}}
					case historyPath:
						if mode == "failed-history" {
							return 500, nil
						}
						if mode == "empty-history" {
							return 200, map[string]any{"results": []any{}}
						}
						if mode == "partial-history" {
							if q.Get("cursor") != "" || q.Get("start") != "0" && !cloud {
								return 500, nil
							}
							return 200, map[string]any{"results": []any{map[string]any{"number": 1}}, "_links": map[string]any{"next": "/next?cursor=next"}}
						}
						return 200, map[string]any{"results": []any{map[string]any{"number": 1}, map[string]any{"number": 2}, map[string]any{"number": 3}, map[string]any{"number": 4}}}
					case bodyPath:
						n, _ := strconv.Atoi(q.Get("version"))
						if n == 0 {
							liveCalls.Add(1)
							n = 4
						} else {
							historicalCalls.Add(1)
							if !cloud && n == 4 {
								return 404, nil // The live version is not served as historical.
							}
						}
						text := "ordinary version " + strconv.Itoa(n)
						switch n {
						case 1:
							text = "secret in oldest version"
						case 4:
							text = "secret in live version"
						}
						actual := n
						if mode == "wrong-version" && n == 2 {
							actual, text = 5, "wrong version response"
						}
						body := map[string]any{"body": map[string]any{"storage": map[string]any{"value": text}}}
						if mode != "current-metadata-absent" {
							body["version"] = map[string]any{"number": actual}
						}
						return 200, body
					}
					return 404, nil
				})
				wantErrors := 0
				if mode == "empty-history" || mode == "failed-history" || mode == "partial-history" || mode == "wrong-version" {
					wantErrors = 1
				}
				if diagnostics(items) != wantErrors {
					t.Fatalf("wrong completeness: want=%d items=%+v", wantErrors, items)
				}
				if !anyContains(items, "secret in live version") {
					t.Fatalf("missing list version lost live body: %+v", items)
				}
				if mode == "complete" || mode == "partial-history" || mode == "wrong-version" || mode == "edited" {
					if !anyContains(items, "secret in oldest version") {
						t.Fatal("available old version lost")
					}
				}
				for _, it := range items {
					if strings.Contains(it.Text, "secret in live version") {
						want := "@v4"
						if mode == "current-metadata-absent" {
							want = "@current"
						}
						if !strings.HasSuffix(it.Path, want) {
							t.Fatalf("live body received guessed/stale version: %+v", it)
						}
					}
					if strings.Contains(it.Text, "wrong version response") && !strings.HasSuffix(it.Path, "@v5") {
						t.Fatalf("wrong response labeled as requested v2: %+v", it)
					}
				}
				if mode == "current-only" || mode == "current-metadata-absent" {
					if liveCalls.Load() != 1 || historicalCalls.Load() != 0 {
						t.Fatalf("current-only guessed a historical number: live=%d history=%d", liveCalls.Load(), historicalCalls.Load())
					}
				}
			})
		}
	}
}

func TestConfluenceServerVersionBudgetIncludesLiveRequest(t *testing.T) {
	var bodyCalls atomic.Int32
	items := collectFixture(t, "confluence", Options{}, func(r *http.Request) (int, any) {
		switch r.URL.Path {
		case "/wiki/api/v2/spaces", "/wiki/rest/api/space":
			return 404, nil
		case "/rest/api/space":
			return 200, map[string]any{"results": []any{map[string]any{"key": "S"}}}
		case "/rest/api/content":
			if r.URL.Query().Get("status") != "current" {
				return 400, nil
			}
			return 200, map[string]any{"results": []any{map[string]any{"id": "1", "title": "Page", "version": map[string]any{"number": maxVersionsPerPage + 1}}}}
		case "/rest/api/content/1/version":
			versions := make([]any, maxVersionsPerPage+1)
			for i := range versions {
				versions[i] = map[string]any{"number": i + 1}
			}
			return 200, map[string]any{"results": versions}
		case "/rest/api/content/1":
			bodyCalls.Add(1)
			n, _ := strconv.Atoi(r.URL.Query().Get("version"))
			if n == 0 {
				n = maxVersionsPerPage + 1
			}
			return 200, map[string]any{"body": map[string]any{"storage": map[string]any{"value": "unchanged body"}}, "version": map[string]any{"number": n}}
		}
		return 404, nil
	})
	if diagnostics(items) != 1 || len(items) != 2 || bodyCalls.Load() != maxVersionsPerPage {
		t.Fatalf("live fetch was not charged to the version budget: requests=%d items=%+v", bodyCalls.Load(), items)
	}
}

func TestConfluenceOverlappingVersionListsDoNotSpendBudgetTwice(t *testing.T) {
	for _, cloud := range []bool{false, true} {
		t.Run(map[bool]string{true: "Cloud", false: "Server"}[cloud], func(t *testing.T) {
			var bodyCalls atomic.Int32
			items := collectFixture(t, "confluence", Options{}, func(r *http.Request) (int, any) {
				p := r.URL.Path
				if p == "/wiki/api/v2/spaces" && !cloud || p == "/wiki/rest/api/space" {
					return 404, nil
				}
				if p == "/wiki/api/v2/spaces" || p == "/rest/api/space" {
					return 200, map[string]any{"results": []any{map[string]any{"id": "1", "key": "S"}}}
				}
				if p == "/wiki/api/v2/spaces/1/pages" || p == "/rest/api/content" {
					if r.URL.Query().Get("status") == "trashed" || r.URL.Query().Get("status") == "draft" {
						return 400, nil
					}
					return 200, map[string]any{"results": []any{map[string]any{"id": "1", "title": "Page", "version": map[string]any{"number": 3}}}}
				}
				if strings.HasSuffix(p, "/versions") || strings.HasSuffix(p, "/version") {
					versions := make([]any, maxVersionsPerPage+1)
					for i := range versions {
						versions[i] = map[string]any{"number": i%3 + 1}
					}
					return 200, map[string]any{"results": versions}
				}
				bodyCalls.Add(1)
				n, _ := strconv.Atoi(r.URL.Query().Get("version"))
				if n == 0 {
					n = 3
				}
				return 200, map[string]any{"body": map[string]any{"storage": map[string]any{"value": "identical body"}}, "version": map[string]any{"number": n}}
			})
			if diagnostics(items) != 0 || len(items) != 1 || !strings.HasSuffix(items[0].Path, "@v1") || bodyCalls.Load() != 3 {
				t.Fatalf("overlapping numbers caused truncation/repeated fetch or nondeterminism: requests=%d items=%+v", bodyCalls.Load(), items)
			}
		})
	}
}
