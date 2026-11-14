package atlassian

import (
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestConfluenceCloudFullScanReadsLiveBeforeHistory(t *testing.T) {
	for _, listed := range []int{0, 1, 3} {
		t.Run(strconv.Itoa(listed), func(t *testing.T) {
			var liveCalls, historicalCalls atomic.Int32
			items := collectFixture(t, "confluence", Options{}, func(r *http.Request) (int, any) {
				switch r.URL.Path {
				case "/wiki/api/v2/spaces":
					return 200, map[string]any{"results": []any{map[string]any{"id": "1", "key": "S"}}}
				case "/wiki/api/v2/spaces/1/pages":
					if r.URL.Query().Get("status") != "current" {
						return 400, nil
					}
					return 200, map[string]any{"results": []any{map[string]any{"id": "1", "title": "Page", "version": map[string]any{"number": listed}}}}
				case "/wiki/api/v2/pages/1/versions":
					if liveCalls.Load() != 1 {
						t.Error("history was chosen before reading the latest version")
					}
					// A version listing may omit the current version, or lag behind a new edit.
					return 200, map[string]any{"results": []any{map[string]any{"number": 1}, map[string]any{"number": 2}, map[string]any{"number": 3}}}
				case "/wiki/api/v2/pages/1":
					n := fixtureVersion(r, 4)
					if r.URL.Query().Get("version") == "" {
						liveCalls.Add(1)
					} else {
						historicalCalls.Add(1)
						if n == 4 {
							t.Error("cached live version was fetched again")
						}
					}
					return 200, map[string]any{"body": map[string]any{"storage": map[string]any{"value": "secret in version " + strconv.Itoa(n)}}, "version": map[string]any{"number": n}}
				}
				return 404, nil
			})
			if diagnostics(items) != 0 || len(items) != 4 || liveCalls.Load() != 1 || historicalCalls.Load() != 3 {
				t.Fatalf("stale page list lost live/history content: %+v live=%d history=%d", items, liveCalls.Load(), historicalCalls.Load())
			}
			for n := 1; n <= 4; n++ {
				if !anyContains(items, "secret in version "+strconv.Itoa(n)) {
					t.Fatalf("version %d lost: %+v", n, items)
				}
			}
		})
	}
}

func TestConfluenceCloudLiveFailureStillReadsHistory(t *testing.T) {
	for _, failure := range []int{200, 403, 500} {
		t.Run(strconv.Itoa(failure), func(t *testing.T) {
			var liveCalls atomic.Int32
			items := collectFixture(t, "confluence", Options{}, func(r *http.Request) (int, any) {
				switch r.URL.Path {
				case "/wiki/api/v2/spaces":
					return 200, map[string]any{"results": []any{map[string]any{"id": "1", "key": "S"}}}
				case "/wiki/api/v2/spaces/1/pages":
					if r.URL.Query().Get("status") != "current" {
						return 400, nil
					}
					return 200, map[string]any{"results": []any{map[string]any{"id": "1", "version": map[string]any{"number": 1}}}}
				case "/wiki/api/v2/pages/1/versions":
					return 200, map[string]any{"results": []any{map[string]any{"number": 1}, map[string]any{"number": 2}, map[string]any{"number": 3}}}
				case "/wiki/api/v2/pages/1":
					if r.URL.Query().Get("version") == "" {
						liveCalls.Add(1)
						// A successful HTTP response with missing storage data is also a live failure.
						return failure, map[string]any{"version": map[string]any{"number": 4}}
					}
					n := fixtureVersion(r, 4)
					return 200, map[string]any{"body": map[string]any{"storage": map[string]any{"value": "historical secret " + strconv.Itoa(n)}}, "version": map[string]any{"number": n}}
				}
				return 404, nil
			})
			if diagnostics(items) != 1 || len(items) != 4 || liveCalls.Load() != 1 || !anyContains(items, "historical secret 3") {
				t.Fatalf("live failure lost readable history or claimed completeness: %+v live=%d", items, liveCalls.Load())
			}
		})
	}
}

func TestConfluenceCloudLiveEmptyOrUnknownMetadata(t *testing.T) {
	for _, mode := range []string{"empty", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			var bodyCalls atomic.Int32
			items := collectFixture(t, "confluence", Options{}, func(r *http.Request) (int, any) {
				switch r.URL.Path {
				case "/wiki/api/v2/spaces":
					return 200, map[string]any{"results": []any{map[string]any{"id": "1", "key": "S"}}}
				case "/wiki/api/v2/spaces/1/pages":
					if r.URL.Query().Get("status") != "current" {
						return 400, nil
					}
					return 200, map[string]any{"results": []any{map[string]any{"id": "1", "version": map[string]any{"number": 3}}}}
				case "/wiki/api/v2/pages/1/versions":
					return 200, map[string]any{"results": []any{map[string]any{"number": 1}, map[string]any{"number": 2}, map[string]any{"number": 3}}}
				case "/wiki/api/v2/pages/1":
					bodyCalls.Add(1)
					n := fixtureVersion(r, 4)
					text := "historical body " + strconv.Itoa(n)
					if n == 4 {
						text = "unknown live secret"
						if mode == "empty" {
							text = ""
						}
					}
					body := map[string]any{"body": map[string]any{"storage": map[string]any{"value": text}}}
					if mode != "unknown" || n != 4 {
						body["version"] = map[string]any{"number": n}
					}
					return 200, body
				}
				return 404, nil
			})
			want := 3
			if mode == "unknown" {
				want = 4
				found := false
				for _, it := range items {
					if it.Text == "unknown live secret" && strings.HasSuffix(it.Path, "@current") {
						found = true
					}
				}
				if !found {
					t.Fatalf("unknown current number guessed from stale listing: %+v", items)
				}
			}
			if diagnostics(items) != 0 || len(items) != want || bodyCalls.Load() != 4 {
				t.Fatalf("empty/unknown live body mishandled: %+v requests=%d", items, bodyCalls.Load())
			}
		})
	}
}
