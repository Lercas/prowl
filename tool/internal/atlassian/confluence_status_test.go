package atlassian

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestConfluenceCloudCurrentOnlyDoesNotPinStaleVersion(t *testing.T) {
	for _, listVersion := range []int{1, 3} {
		for _, bodyMetadata := range []bool{false, true} {
			t.Run(strconv.Itoa(listVersion)+"/metadata="+strconv.FormatBool(bodyMetadata), func(t *testing.T) {
				var pinned, history atomic.Int32
				items := collectFixture(t, "confluence", Options{CurrentOnly: true}, func(r *http.Request) (int, any) {
					switch r.URL.Path {
					case "/wiki/api/v2/spaces":
						return 200, map[string]any{"results": []any{map[string]any{"id": "1", "key": "S"}}}
					case "/wiki/api/v2/spaces/1/pages":
						if r.URL.Query().Get("status") == "trashed" {
							return 400, nil
						}
						return 200, map[string]any{"results": []any{map[string]any{"id": "1", "version": map[string]any{"number": listVersion}}}}
					case "/wiki/api/v2/pages/1/versions":
						history.Add(1)
						return 200, map[string]any{"results": []any{map[string]any{"number": listVersion}}}
					case "/wiki/api/v2/pages/1":
						if r.URL.Query().Get("version") != "" {
							pinned.Add(1)
							return 200, map[string]any{"body": map[string]any{"storage": map[string]any{"value": "stale body"}}, "version": map[string]any{"number": listVersion}}
						}
						body := map[string]any{"body": map[string]any{"storage": map[string]any{"value": "latest body"}}}
						if bodyMetadata {
							body["version"] = map[string]any{"number": 4}
						}
						return 200, body
					}
					return 404, nil
				})
				want := "@current"
				if bodyMetadata {
					want = "@v4"
				}
				if len(items) != 1 || !strings.HasSuffix(items[0].Path, want) || items[0].Text != "latest body" || history.Load() != 0 || pinned.Load() != 0 {
					t.Fatalf("current-only read a stale body or guessed its number: %+v pinned=%d history=%d", items, pinned.Load(), history.Load())
				}
			})
		}
	}
}

func TestConfluenceCloudBodyPreservesListingStatus(t *testing.T) {
	for _, currentOnly := range []bool{false, true} {
		for _, metadata := range []bool{false, true} {
			t.Run("current-only="+strconv.FormatBool(currentOnly)+"/metadata="+strconv.FormatBool(metadata), func(t *testing.T) {
				statuses := []string{"current", "archived", "trashed", "deleted"}
				items := collectFixture(t, "confluence", Options{CurrentOnly: currentOnly}, func(r *http.Request) (int, any) {
					q := r.URL.Query()
					if r.URL.Path == "/wiki/api/v2/spaces" {
						return 200, map[string]any{"results": []any{map[string]any{"id": "1", "key": "S"}}}
					}
					if r.URL.Path == "/wiki/api/v2/spaces/1/pages" {
						var pages []any
						for _, status := range q["status"] {
							page := map[string]any{"id": status, "title": status, "version": map[string]any{"number": 2}}
							if metadata {
								page["status"] = status
							}
							pages = append(pages, page)
						}
						return 200, map[string]any{"results": pages}
					}
					for _, status := range statuses {
						path := "/wiki/api/v2/pages/" + status
						if r.URL.Path == path+"/versions" {
							return 200, map[string]any{"results": []any{map[string]any{"number": 1}, map[string]any{"number": 2}}}
						}
						if r.URL.Path == path {
							if !slices.Contains(q["status"], status) {
								return 404, nil
							}
							n := fixtureVersion(r, 2)
							if n == 1 && !slices.Contains(q["status"], "historical") {
								return 404, nil
							}
							return 200, map[string]any{"body": map[string]any{"storage": map[string]any{"value": status + " body " + strconv.Itoa(n)}}, "version": map[string]any{"number": n}}
						}
					}
					return 404, nil
				})
				want := 8
				if currentOnly {
					want = 4
				}
				if len(items) != want || diagnostics(items) != 0 {
					t.Fatalf("status context lost: %+v", items)
				}
				for _, status := range statuses {
					if !anyContains(items, status+" body 2") || !currentOnly && !anyContains(items, status+" body 1") {
						t.Fatalf("%s body omitted: %+v", status, items)
					}
				}
			})
		}
	}
}

func TestConfluenceCloudOptionalStatusesRecoverIndividually(t *testing.T) {
	for _, rejection := range []int{400, 404, 405, 401, 403, 500} {
		for _, supported := range []string{"trashed", "deleted"} {
			t.Run(strconv.Itoa(rejection)+"/"+supported, func(t *testing.T) {
				var separate atomic.Int32
				items := collectFixture(t, "confluence", Options{CurrentOnly: true}, func(r *http.Request) (int, any) {
					q := r.URL.Query()
					switch r.URL.Path {
					case "/wiki/api/v2/spaces":
						return 200, map[string]any{"results": []any{map[string]any{"id": "1", "key": "S"}}}
					case "/wiki/api/v2/spaces/1/pages":
						status := q.Get("status")
						if status == "current" {
							return 200, map[string]any{"results": []any{map[string]any{"id": "current", "version": map[string]any{"number": 1}}}}
						}
						if len(q["status"]) > 1 {
							return rejection, nil
						}
						separate.Add(1)
						if status != supported {
							return 400, nil
						}
						// Status metadata is absent, so the successful scalar filter must be retained.
						return 200, map[string]any{"results": []any{map[string]any{"id": status, "version": map[string]any{"number": 1}}}}
					case "/wiki/api/v2/pages/current":
						return 200, map[string]any{"body": map[string]any{"storage": map[string]any{"value": "current body"}}, "version": map[string]any{"number": 1}}
					case "/wiki/api/v2/pages/" + supported:
						if q.Get("status") != supported {
							return 404, nil
						}
						return 200, map[string]any{"body": map[string]any{"storage": map[string]any{"value": supported + " body"}}, "version": map[string]any{"number": 1}}
					}
					return 404, nil
				})
				if !anyContains(items, "current body") {
					t.Fatalf("live content lost: %+v", items)
				}
				if rejection == 400 || rejection == 404 || rejection == 405 {
					if separate.Load() != 2 || diagnostics(items) != 0 || !anyContains(items, supported+" body") {
						t.Fatalf("combined rejection lost supported status: separate=%d items=%+v", separate.Load(), items)
					}
				} else if separate.Load() != 0 || diagnostics(items) != 1 {
					t.Fatalf("access/server failure treated as unsupported: separate=%d items=%+v", separate.Load(), items)
				}
			})
		}
	}
}

func TestConfluenceStatusFailureDoesNotStopOtherStatuses(t *testing.T) {
	for _, cloud := range []bool{false, true} {
		for _, failed := range []string{"current", "draft"} {
			t.Run("cloud="+strconv.FormatBool(cloud)+"/failed="+failed, func(t *testing.T) {
				items := collectFixture(t, "confluence", Options{CurrentOnly: true}, func(r *http.Request) (int, any) {
					q := r.URL.Query()
					if r.URL.Path == "/wiki/api/v2/spaces" {
						if !cloud {
							return 404, nil
						}
						return 200, map[string]any{"results": []any{map[string]any{"id": "1", "key": "S"}}}
					}
					if r.URL.Path == "/wiki/rest/api/space" {
						return 404, nil
					}
					if r.URL.Path == "/rest/api/space" {
						return 200, map[string]any{"results": []any{map[string]any{"key": "S"}}}
					}
					if r.URL.Path == "/rest/api/content" || r.URL.Path == "/wiki/api/v2/spaces/1/pages" {
						status := q.Get("status")
						if cloud && failed == "draft" {
							// Force scalar retries, then fail the first one without hiding the second.
							if status == "trashed" && len(q["status"]) > 1 {
								return 400, nil
							}
							if status == "trashed" {
								return 403, nil
							}
						} else if status == failed {
							return 500, nil
						}
						return 200, map[string]any{"results": []any{map[string]any{"id": status, "version": map[string]any{"number": 1}}}}
					}
					if strings.HasPrefix(r.URL.Path, "/rest/api/content/") || strings.HasPrefix(r.URL.Path, "/wiki/api/v2/pages/") {
						status := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
						return 200, map[string]any{"body": map[string]any{"storage": map[string]any{"value": status + " body"}}, "version": map[string]any{"number": 1}}
					}
					return 404, nil
				})
				want := "trashed body"
				if cloud && failed == "draft" {
					want = "deleted body"
				}
				if diagnostics(items) != 1 || !anyContains(items, want) {
					t.Fatalf("failed status stopped remaining readable states: %+v", items)
				}
			})
		}
	}
}
