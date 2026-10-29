package atlassian

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

type fixtureTransport func(*http.Request) (int, any)

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	status, value := f(r)
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw)), Request: r}, nil
}

func collectFixture(t *testing.T, product string, opts Options, route fixtureTransport) []model.Item {
	t.Helper()
	opts.HTTPClient = &http.Client{Transport: route}
	items := collect(t, "https://fixture.invalid", product, opts)
	return items
}

func diagnostics(items []model.Item) int {
	n := 0
	for _, it := range items {
		if it.Error != nil {
			n++
		}
	}
	return n
}

func cloudIssue() map[string]any {
	return map[string]any{"id": "1", "key": "P-1", "fields": map[string]any{"summary": "current text"}}
}

func TestJiraPartialProjectsRetainContent(t *testing.T) {
	items := collectFixture(t, "jira", Options{CurrentOnly: true}, func(r *http.Request) (int, any) {
		switch r.URL.Path {
		case "/rest/api/2/serverInfo":
			return 200, map[string]any{"deploymentType": "Cloud"}
		case "/rest/api/3/project/search":
			if r.URL.Query().Get("startAt") != "0" {
				return 500, "provider response containing a secret"
			}
			return 200, map[string]any{"values": []any{map[string]any{"key": "P"}}, "maxResults": 1}
		case "/rest/api/3/search/jql":
			return 200, map[string]any{"isLast": true, "issues": []any{cloudIssue()}}
		}
		return 404, nil
	})
	if diagnostics(items) != 1 || !anyContains(items, "current text") {
		t.Fatalf("partial project listing lost content or diagnostic: %+v", items)
	}
}

func TestJiraCursorCycleIsIncomplete(t *testing.T) {
	var calls atomic.Int32
	items := collectFixture(t, "jira", Options{Projects: []string{"P"}, CurrentOnly: true}, func(r *http.Request) (int, any) {
		if r.URL.Path == "/rest/api/2/serverInfo" {
			return 200, map[string]any{"deploymentType": "Cloud"}
		}
		n := calls.Add(1)
		token := "a"
		if n == 2 {
			token = "b"
		}
		return 200, map[string]any{"nextPageToken": token, "issues": []any{cloudIssue()}}
	})
	if diagnostics(items) != 1 || calls.Load() != 3 || !anyContains(items, "current text") {
		t.Fatalf("cursor cycle accepted or content lost: calls=%d items=%+v", calls.Load(), items)
	}
}

func TestJiraBudgetConcurrent(t *testing.T) {
	for _, limit := range []int{1, 17, 100} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			items := collectFixture(t, "jira", Options{Projects: []string{"P"}, CurrentOnly: true, Workers: 16, MaxItems: limit}, func(r *http.Request) (int, any) {
				if r.URL.Path == "/rest/api/2/serverInfo" {
					return 200, map[string]any{"deploymentType": "Cloud"}
				}
				issues := make([]any, 100)
				for i := range issues {
					issues[i] = cloudIssue()
				}
				return 200, map[string]any{"isLast": true, "issues": issues}
			})
			wantErrors := 1
			if limit == 100 {
				wantErrors = 0
			}
			if diagnostics(items) != wantErrors || len(items)-diagnostics(items) != limit {
				t.Fatalf("budget overrun, dropped reserved item or false truncation: items=%d diagnostics=%d", len(items), diagnostics(items))
			}
		})
	}
}

func TestJiraCommentsFailureRetainsInline(t *testing.T) {
	items := collectFixture(t, "jira", Options{Projects: []string{"P"}, CurrentOnly: true}, func(r *http.Request) (int, any) {
		switch r.URL.Path {
		case "/rest/api/2/serverInfo":
			return 200, map[string]any{"deploymentType": "Cloud"}
		case "/rest/api/3/search/jql":
			issue := cloudIssue()
			issue["fields"].(map[string]any)["comment"] = map[string]any{"total": 2, "comments": []any{map[string]any{"id": "9", "body": "inline secret candidate"}}}
			return 200, map[string]any{"isLast": true, "issues": []any{issue}}
		default:
			return 403, nil
		}
	})
	if diagnostics(items) != 1 || !anyContains(items, "inline secret candidate") {
		t.Fatalf("comments failure concealed or inline discarded: %+v", items)
	}
}

func TestJiraInlineCommentsDoNotConsumeBudgetTwice(t *testing.T) {
	items := collectFixture(t, "jira", Options{Projects: []string{"P"}, CurrentOnly: true, MaxItems: 3}, func(r *http.Request) (int, any) {
		comments := []any{map[string]any{"id": "9", "body": "inline comment"}, map[string]any{"id": "10", "body": "additional comment"}}
		switch r.URL.Path {
		case "/rest/api/2/serverInfo":
			return 200, map[string]any{"deploymentType": "Cloud"}
		case "/rest/api/3/search/jql":
			issue := cloudIssue()
			issue["fields"].(map[string]any)["comment"] = map[string]any{"total": 2, "comments": comments[:1]}
			return 200, map[string]any{"isLast": true, "issues": []any{issue}}
		case "/rest/api/3/issue/P-1/comment":
			return 200, map[string]any{"total": 2, "comments": comments}
		}
		return 404, nil
	})
	if diagnostics(items) != 0 || len(items) != 3 || !anyContains(items, "additional comment") {
		t.Fatalf("duplicate inline comment exhausted content budget: %+v", items)
	}
}

func TestJiraInvalidInlineCountsRecoverThroughCommentsEndpoint(t *testing.T) {
	for _, count := range []any{nil, true, -1, json.Number("0.5"), json.Number("1e1000"), json.Number("9223372036854775808"), json.Number("9007199254740993")} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			var calls atomic.Int32
			items := collectFixture(t, "jira", Options{Projects: []string{"P"}, CurrentOnly: true}, func(r *http.Request) (int, any) {
				switch r.URL.Path {
				case "/rest/api/2/serverInfo":
					return 200, map[string]any{"deploymentType": "Cloud"}
				case "/rest/api/3/search/jql":
					issue := cloudIssue()
					issue["fields"].(map[string]any)["comment"] = map[string]any{"total": count, "comments": []any{}}
					return 200, map[string]any{"isLast": true, "issues": []any{issue}}
				case "/rest/api/3/issue/P-1/comment":
					calls.Add(1)
					return 200, map[string]any{"total": 1, "comments": []any{map[string]any{"id": "9", "body": "recovered comment candidate"}}}
				}
				return 404, nil
			})
			if calls.Load() != 1 || diagnostics(items) != 0 || !anyContains(items, "recovered comment candidate") {
				t.Fatalf("invalid count hid comments or complete fallback failed: calls=%d items=%+v", calls.Load(), items)
			}
		})
	}
}

func TestJiraBulkInterruptedRefetchesSeenIssue(t *testing.T) {
	for _, mode := range []string{"late-error", "cycle", "fallback-error", "missing-id"} {
		t.Run(mode, func(t *testing.T) {
			var bulkCalls, fallbackCalls atomic.Int32
			items := collectFixture(t, "jira", Options{Projects: []string{"P"}}, func(r *http.Request) (int, any) {
				history := func(id, text string) any {
					return map[string]any{"id": id, "items": []any{map[string]any{"field": "description", "fromString": text}}}
				}
				switch r.URL.Path {
				case "/rest/api/2/serverInfo":
					return 200, map[string]any{"deploymentType": "Cloud"}
				case "/rest/api/3/search/jql":
					issue := cloudIssue()
					if mode == "missing-id" {
						delete(issue, "id")
					}
					return 200, map[string]any{"isLast": true, "issues": []any{issue}}
				case "/rest/api/3/changelog/bulkfetch":
					n := bulkCalls.Add(1)
					if n > 1 && mode != "cycle" {
						return 500, nil
					}
					return 200, map[string]any{"nextPageToken": "next", "issueChangeLogs": []any{map[string]any{"issueId": "1", "changeHistories": []any{history("9", "first history")}}}}
				case "/rest/api/3/issue/P-1/changelog":
					fallbackCalls.Add(1)
					if mode == "fallback-error" {
						return 403, nil
					}
					return 200, map[string]any{"isLast": true, "values": []any{history("9", "first history"), history("10", "later history secret")}}
				}
				return 404, nil
			})
			if fallbackCalls.Load() != 1 {
				t.Fatalf("already-seen issue not refetched: %d", fallbackCalls.Load())
			}
			if mode == "fallback-error" {
				if diagnostics(items) != 1 || !anyContains(items, "first history") {
					t.Fatalf("failed fallback accepted as complete: %+v", items)
				}
			} else {
				if diagnostics(items) != 0 || !anyContains(items, "later history secret") {
					t.Fatalf("successful fallback incomplete: %+v", items)
				}
				first := 0
				for _, it := range items {
					if strings.Contains(it.Text, "first history") {
						first++
					}
				}
				if first != 1 {
					t.Fatalf("fallback duplicated first history: %d", first)
				}
			}
			if mode == "missing-id" && bulkCalls.Load() != 0 {
				t.Fatal("sent an empty issue batch to bulkfetch")
			}
		})
	}
}

func TestConfluenceIncompleteVersions(t *testing.T) {
	for _, kind := range []string{"Cloud", "Server"} {
		for _, mode := range []string{"list-error", "body-error", "bad-link", "cycle"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				var versionCalls atomic.Int32
				client := NewClient("https://fixture.invalid", Auth{}, 0)
				client.http = &http.Client{Transport: fixtureTransport(func(r *http.Request) (int, any) {
					if strings.HasSuffix(r.URL.Path, "/versions") || strings.HasSuffix(r.URL.Path, "/version") {
						n := versionCalls.Add(1)
						if n > 1 && mode == "list-error" {
							return 500, nil
						}
						next := "/next?cursor=a"
						if mode == "bad-link" {
							next = "/next?other=x"
						} else if mode == "body-error" {
							next = ""
						} else if kind == "Server" && mode == "cycle" {
							// An empty offset page cannot advance despite the advertised link.
							return 200, map[string]any{"results": []any{}, "_links": map[string]any{"next": next}}
						}
						if kind == "Server" && mode == "bad-link" {
							return 200, map[string]any{"results": []any{}, "_links": map[string]any{"next": next}}
						}
						return 200, map[string]any{"results": []any{map[string]any{"number": 1}}, "_links": map[string]any{"next": next}}
					}
					if mode == "body-error" && (r.URL.Query().Get("version") == "1") {
						return 403, nil
					}
					return 200, map[string]any{"body": map[string]any{"storage": map[string]any{"value": "retained version " + r.URL.Query().Get("version")}}}
				})}
				var items []model.Item
				// Version bodies can emit diagnostics concurrently.
				out := make(chan model.Item, 10)
				emit := func(it model.Item) { out <- it }
				sem := make(chan struct{}, 2)
				if kind == "Cloud" {
					p := confPageV2{ID: "1", Title: "Page"}
					p.Version.Number = 3
					confCloudScanPage(context.Background(), client, Deployment{Kind: "cloud"}, sem, "S", p, Options{}, emit)
				} else {
					p := confContentV1{ID: "1", Title: "Page"}
					p.Version.Number = 3
					confServerScanPage(context.Background(), client, Deployment{Kind: "server"}, sem, "S", "current", p, Options{}, emit)
				}
				close(out)
				for it := range out {
					items = append(items, it)
				}
				if diagnostics(items) != 1 || !anyContains(items, "retained version") {
					t.Fatalf("incomplete history concealed or current dropped: %+v", items)
				}
				if mode == "list-error" && !anyContains(items, "retained version 1") {
					t.Fatal("successfully listed historical version discarded")
				}
			})
		}
	}
}

func TestOptionalStatusesDoNotConcealFailures(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 405, 500} {
		for _, first := range []bool{false, true} {
			got := unsupportedStatus(&reqError{Status: status}, first)
			want := first && (status == 400 || status == 404 || status == 405)
			if got != want {
				t.Fatalf("HTTP %d first=%v: unsupported=%v", status, first, got)
			}
		}
	}
}

func TestCursorPageBudget(t *testing.T) {
	var walk cursorWalk
	for i := 0; i < maxPages; i++ {
		err := walk.advance(fmt.Sprint(i))
		if (err != nil) != (i == maxPages-1) {
			t.Fatalf("page %d: %v", i+1, err)
		}
	}
}

func TestProviderErrorDoesNotExposeBody(t *testing.T) {
	err := &reqError{Status: 403, URL: "https://user:password@fixture.invalid/path", Body: "secret-from-provider"}
	if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "secret-from-provider") {
		t.Fatalf("provider error exposed credentials: %s", err)
	}
}

func TestConfluenceVersionBudgetSurvivesBodyDedup(t *testing.T) {
	var bodyCalls atomic.Int32
	client := NewClient("https://fixture.invalid", Auth{}, 0)
	client.http = &http.Client{Transport: fixtureTransport(func(r *http.Request) (int, any) {
		if strings.HasSuffix(r.URL.Path, "/versions") {
			versions := make([]any, maxVersionsPerPage+1)
			for i := range versions {
				versions[i] = map[string]any{"number": i + 1}
			}
			return 200, map[string]any{"results": versions}
		}
		bodyCalls.Add(1)
		return 200, map[string]any{"body": map[string]any{"storage": map[string]any{"value": "identical across all versions"}}}
	})}
	p := confPageV2{ID: "1", Title: "Page"}
	p.Version.Number = maxVersionsPerPage + 1
	var items []model.Item
	confCloudScanPage(context.Background(), client, Deployment{Kind: "cloud"}, make(chan struct{}, 8), "S", p, Options{}, func(it model.Item) { items = append(items, it) })
	if diagnostics(items) != 1 || len(items) != 2 || bodyCalls.Load() != maxVersionsPerPage {
		t.Fatalf("version budget concealed by dedup: items=%d diagnostics=%d requests=%d", len(items), diagnostics(items), bodyCalls.Load())
	}
}

func TestConfluenceArchivedFailureRetainsCurrentSpace(t *testing.T) {
	for _, status := range []int{400, 403, 500} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			items := collectFixture(t, "confluence", Options{CurrentOnly: true}, func(r *http.Request) (int, any) {
				switch r.URL.Path {
				case "/wiki/api/v2/spaces":
					if r.URL.Query().Get("status") == "archived" {
						return status, nil
					}
					return 200, map[string]any{"results": []any{map[string]any{"id": "1", "key": "S"}}}
				case "/wiki/api/v2/spaces/1/pages":
					if r.URL.Query().Get("status") == "trashed" {
						return 400, nil
					}
					return 200, map[string]any{"results": []any{map[string]any{"id": "1", "title": "Page", "version": map[string]any{"number": 1}}}}
				case "/wiki/api/v2/pages/1":
					return 200, map[string]any{"body": map[string]any{"storage": map[string]any{"value": "current page text"}}}
				}
				return 404, nil
			})
			wantErrors := 1
			if status == 400 {
				wantErrors = 0
			}
			if diagnostics(items) != wantErrors || !anyContains(items, "current page text") {
				t.Fatalf("archived failure concealed or current content lost: %+v", items)
			}
		})
	}
}
