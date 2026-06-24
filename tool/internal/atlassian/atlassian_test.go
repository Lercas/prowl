package atlassian

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/safehttp"
)

// the mock servers run on loopback; allow the SSRF-guarded transport to reach them (as e2e does via
// PROWL_ALLOW_PRIVATE_IPS=1).
func TestMain(m *testing.M) {
	safehttp.AllowPrivate.Store(true)
	os.Exit(m.Run())
}

// the marker lives ONLY in version 1 / a changelog fromString — never in current content.
const v1Secret = "SECRET_ONLY_IN_V1_AKIAIOSFODNN7EXAMPLE"

func collect(t *testing.T, base, product string, opts Options) []model.Item {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ch, _, err := Collect(ctx, base, product, Auth{Email: "e@x", Token: "tok"}, opts)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var items []model.Item
	for it := range ch {
		items = append(items, it)
	}
	return items
}

func anyContains(items []model.Item, sub string) bool {
	for _, it := range items {
		if strings.Contains(it.Text, sub) {
			return true
		}
	}
	return false
}

// jiraCloudMock serves the minimal Cloud Jira surface: serverInfo, project/search, search/jql, and a
// changelog whose description `fromString` holds a secret that the CURRENT issue fields do not.
func jiraCloudMock() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/api/2/serverInfo", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"deploymentType":"Cloud","version":"","baseUrl":"` + "http://x" + `"}`))
	})
	mux.HandleFunc("/rest/api/3/project/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"isLast":true,"total":1,"maxResults":50,"startAt":0,"values":[{"key":"PROJ"}]}`))
	})
	mux.HandleFunc("/rest/api/3/search/jql", func(w http.ResponseWriter, r *http.Request) {
		// current content is clean — the secret is gone from the live issue
		w.Write([]byte(`{"isLast":true,"issues":[{"id":"1","key":"PROJ-1","fields":{"summary":"deploy notes","description":{"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"all clean now"}]}]}}}]}`))
	})
	mux.HandleFunc("/rest/api/3/issue/PROJ-1/changelog", func(w http.ResponseWriter, r *http.Request) {
		// the description USED to contain the secret (fromString) and was scrubbed (toString)
		w.Write([]byte(`{"isLast":true,"total":1,"maxResults":100,"startAt":0,"values":[{"id":"9","created":"2020-01-02T00:00:00.000+0000","author":{"emailAddress":"dev@x"},"items":[{"field":"description","fieldId":"description","fromString":"deploy with key ` + v1Secret + `","toString":"all clean now"}]}]}`))
	})
	return httptest.NewServer(mux)
}

func TestJiraHistorySecretFound(t *testing.T) {
	srv := jiraCloudMock()
	defer srv.Close()

	// full-history scan (default) MUST surface the v1-only secret from the changelog fromString.
	items := collect(t, srv.URL, "jira", Options{})
	if !anyContains(items, v1Secret) {
		t.Fatalf("T30 violated: the secret that exists only in changelog history was NOT collected; items=%d", len(items))
	}
	// the current-content item must NOT contain it (proves the find came from history, not current).
	for _, it := range items {
		if it.Meta["version"] == "current" && strings.Contains(it.Text, v1Secret) {
			t.Fatalf("current item unexpectedly contains the historical secret")
		}
	}
}

func TestJiraCurrentOnlySkipsHistory(t *testing.T) {
	srv := jiraCloudMock()
	defer srv.Close()
	items := collect(t, srv.URL, "jira", Options{CurrentOnly: true})
	if anyContains(items, v1Secret) {
		t.Fatalf("--current-only must NOT walk history, but the v1 secret was collected")
	}
}

// confluenceCloudMock serves spaces -> pages -> versions, where version 1's storage body holds a
// secret absent from the current (version 3) body.
func confluenceCloudMock() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/wiki/api/v2/spaces", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"id":"100","key":"SP"}],"_links":{}}`))
	})
	mux.HandleFunc("/wiki/api/v2/spaces/100/pages", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"id":"200","title":"Runbook","version":{"number":3}}],"_links":{}}`))
	})
	mux.HandleFunc("/wiki/api/v2/pages/200/versions", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"number":1},{"number":2},{"number":3}],"_links":{}}`))
	})
	mux.HandleFunc("/wiki/api/v2/pages/200", func(w http.ResponseWriter, r *http.Request) {
		body := "<p>nothing sensitive</p>"
		if r.URL.Query().Get("version") == "1" {
			// a secret inside a code-macro CDATA block (quotes here would break hand-built JSON,
			// so the whole response is json-encoded — proving the raw storage is scanned, T23).
			body = `<ac:structured-macro ac:name="code"><ac:plain-text-body><![CDATA[token=` + v1Secret + `]]></ac:plain-text-body></ac:structured-macro>`
		}
		json.NewEncoder(w).Encode(map[string]any{
			"id": "200", "title": "Runbook",
			"body":    map[string]any{"storage": map[string]any{"value": body}},
			"version": map[string]any{"number": 1},
			"_links":  map[string]any{"webui": "/spaces/SP/pages/200"},
		})
	})
	return httptest.NewServer(mux)
}

func TestConfluenceHistorySecretFound(t *testing.T) {
	srv := confluenceCloudMock()
	defer srv.Close()
	items := collect(t, srv.URL, "confluence", Options{})
	if !anyContains(items, v1Secret) {
		t.Fatalf("T30 violated: the secret in Confluence page version 1 (CDATA code macro) was NOT collected; items=%d", len(items))
	}
}

func TestConfluenceCurrentOnly(t *testing.T) {
	srv := confluenceCloudMock()
	defer srv.Close()
	items := collect(t, srv.URL, "confluence", Options{CurrentOnly: true})
	if anyContains(items, v1Secret) {
		t.Fatalf("--current-only must fetch only the latest version, but the v1 secret was collected")
	}
}

func TestDetectJiraCloud(t *testing.T) {
	srv := jiraCloudMock()
	defer srv.Close()
	c := NewClient(srv.URL, Auth{Email: "e", Token: "t"}, 5*time.Second)
	dep, err := DetectJira(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if !dep.Cloud() {
		t.Fatalf("expected Cloud, got %q", dep.Kind)
	}
}

func TestDetectConfluenceCloud(t *testing.T) {
	srv := confluenceCloudMock()
	defer srv.Close()
	c := NewClient(srv.URL, Auth{Email: "e", Token: "t"}, 5*time.Second)
	dep, err := DetectConfluence(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if !dep.Cloud() || dep.WikiPrefix != "/wiki" {
		t.Fatalf("expected Cloud /wiki, got kind=%q prefix=%q", dep.Kind, dep.WikiPrefix)
	}
}

func TestADFTextWalksAttrs(t *testing.T) {
	// a token hidden as a link href must be extracted (pitfall T16), not just node text
	adf := map[string]any{
		"type": "doc",
		"content": []any{
			map[string]any{"type": "text", "text": "see "},
			map[string]any{"type": "text", "text": "link", "marks": []any{
				map[string]any{"type": "link", "attrs": map[string]any{"href": "https://h/?k=" + v1Secret}},
			}},
		},
	}
	got := adfText(adf)
	if !strings.Contains(got, "see") || !strings.Contains(got, v1Secret) {
		t.Fatalf("adfText missed text or href attr: %q", got)
	}
}

// regression for audit bug #3: a Cloud /search/jql first page that is EMPTY but carries a
// nextPageToken (results still materializing / permission-filtered) must NOT terminate the walk —
// the issues on page 2 were being silently dropped.
func TestJiraSearchEmptyFirstPageWithCursor(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/api/2/serverInfo", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"deploymentType":"Cloud"}`))
	})
	mux.HandleFunc("/rest/api/3/project/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"isLast":true,"values":[{"key":"P"}]}`))
	})
	mux.HandleFunc("/rest/api/3/search/jql", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("nextPageToken") == "" {
			w.Write([]byte(`{"issues":[],"isLast":false,"nextPageToken":"PAGE2"}`)) // empty, NOT last
			return
		}
		w.Write([]byte(`{"issues":[{"id":"1","key":"P-1","fields":{"description":"token ` + v1Secret + `"}}],"isLast":true}`))
	})
	mux.HandleFunc("/rest/api/3/issue/P-1/changelog", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"isLast":true,"values":[]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	items := collect(t, srv.URL, "jira", Options{CurrentOnly: true})
	if !anyContains(items, v1Secret) {
		t.Fatalf("empty-but-not-last search page terminated the walk; page-2 issue dropped; items=%d", len(items))
	}
}

// regression for audit bug #1 (CRITICAL): the Server/DC version list is offset-paginated; the oldest
// versions (which may hold a since-removed secret) sit on later pages and must not be dropped.
func TestConfluenceServerVersionPagination(t *testing.T) {
	mux := http.NewServeMux()
	four04 := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }
	mux.HandleFunc("/wiki/api/v2/spaces", four04)
	mux.HandleFunc("/wiki/rest/api/space", four04)
	mux.HandleFunc("/rest/api/space", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"key":"ENG"}],"_links":{}}`))
	})
	mux.HandleFunc("/rest/api/content", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"id":"500","title":"Doc","version":{"number":3}}],"_links":{}}`))
	})
	mux.HandleFunc("/rest/api/content/500/version", func(w http.ResponseWriter, r *http.Request) {
		// page 1 (start=0, limit=200) returns the two newest WITH a next link; v1 is only on page 2.
		if r.URL.Query().Get("start") == "0" {
			w.Write([]byte(`{"results":[{"number":3},{"number":2}],"size":2,"limit":2,"_links":{"next":"/rest/api/content/500/version?start=2&limit=2"}}`))
			return
		}
		w.Write([]byte(`{"results":[{"number":1}],"size":1,"limit":2,"_links":{}}`)) // short page = last
	})
	mux.HandleFunc("/rest/api/content/500", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		body := "current clean"
		if q.Get("status") == "historical" && q.Get("version") == "1" {
			body = "old " + v1Secret
		} else if q.Get("status") == "historical" {
			body = "older clean"
		}
		json.NewEncoder(w).Encode(map[string]any{
			"id": "500", "title": "Doc",
			"body":    map[string]any{"storage": map[string]any{"value": body}},
			"version": map[string]any{"number": 3}, "_links": map[string]any{"webui": "/x"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	items := collect(t, srv.URL, "confluence", Options{})
	if !anyContains(items, v1Secret) {
		t.Fatalf("CRITICAL: version-1 secret on page 2 of the version list was dropped (single-shot listing); items=%d", len(items))
	}
}

// regression for audit bug #6: a credential inlined in the base URL (https://user:token@host) must be
// stripped so it never reaches a log, an error, or a finding's Meta["url"].
func TestNewClientStripsUserinfo(t *testing.T) {
	c := NewClient("https://alice@corp.com:SUPERSECRETTOKEN@site.atlassian.net/", Auth{PAT: "x"}, time.Second)
	if strings.Contains(c.base, "SUPERSECRETTOKEN") || strings.Contains(c.base, "@") {
		t.Fatalf("userinfo not stripped from base URL: %q", c.base)
	}
	if c.base != "https://site.atlassian.net" {
		t.Fatalf("unexpected normalized base: %q", c.base)
	}
}

// regression for the short-page-guard fix: a Server/DC search page that is SHORT (fewer than
// maxResults, e.g. a permission-filtered middle page) but whose total says more remain must NOT
// terminate the walk — the issue on the next page (carrying the secret) must still be scanned.
func TestJiraServerShortMiddlePageContinues(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/api/2/serverInfo", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"deploymentType":"Server"}`))
	})
	mux.HandleFunc("/rest/api/2/project", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"key":"P"}]`))
	})
	mux.HandleFunc("/rest/api/2/search", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			StartAt int `json:"startAt"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.StartAt == 0 { // SHORT first page (1 of maxResults 50) but total=2 -> more remain
			w.Write([]byte(`{"startAt":0,"maxResults":50,"total":2,"issues":[{"id":"1","key":"P-1","fields":{"description":"clean"}}]}`))
			return
		}
		w.Write([]byte(`{"startAt":1,"maxResults":50,"total":2,"issues":[{"id":"2","key":"P-2","fields":{"description":"leak ` + v1Secret + `"}}]}`))
	})
	mux.HandleFunc("/rest/api/2/issue/P-1/changelog", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"isLast":true,"values":[]}`)) })
	mux.HandleFunc("/rest/api/2/issue/P-2/changelog", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"isLast":true,"values":[]}`)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	items := collect(t, srv.URL, "jira", Options{CurrentOnly: true})
	if !anyContains(items, v1Secret) {
		t.Fatalf("short middle page under a known total terminated the walk; page-2 issue dropped; items=%d", len(items))
	}
}

// regression for re-audit bug #2: the real Cloud v2 /versions endpoint validates the `sort` enum
// (only modified-date / -modified-date) and 400s on sort=version. If the scanner sends sort=version,
// the version list 400s, the walk falls back to current-only, and ALL page history is silently lost.
// This mock 400s when ANY sort is present, proving the scanner sends none.
func TestConfluenceCloudVersionsRejectsBadSort(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wiki/api/v2/spaces", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"id":"100","key":"SP"}],"_links":{}}`))
	})
	mux.HandleFunc("/wiki/api/v2/spaces/100/pages", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"id":"200","title":"Doc","version":{"number":2}}],"_links":{}}`))
	})
	mux.HandleFunc("/wiki/api/v2/pages/200/versions", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("sort") != "" { // strict enum validation, as real Atlassian does
			w.WriteHeader(400)
			w.Write([]byte(`{"errors":[{"status":400,"title":"Invalid value for sort"}]}`))
			return
		}
		w.Write([]byte(`{"results":[{"number":1},{"number":2}],"_links":{}}`))
	})
	mux.HandleFunc("/wiki/api/v2/pages/200", func(w http.ResponseWriter, r *http.Request) {
		body := "current clean"
		if r.URL.Query().Get("version") == "1" {
			body = "old " + v1Secret
		}
		json.NewEncoder(w).Encode(map[string]any{
			"id": "200", "title": "Doc",
			"body":    map[string]any{"storage": map[string]any{"value": body}},
			"version": map[string]any{"number": 1}, "_links": map[string]any{"webui": "/x"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	items := collect(t, srv.URL, "confluence", Options{})
	if !anyContains(items, v1Secret) {
		t.Fatalf("version list rejected the sort param and history was dropped; v1 secret not found; items=%d", len(items))
	}
}

// regression for the round-3 cloud-status resilience fix: a build that 400s the trashed/deleted page
// listing must NOT lose the live (current+archived) pages of that space.
func TestConfluenceCloudStatusResilience(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wiki/api/v2/spaces", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"id":"100","key":"SP"}],"_links":{}}`))
	})
	mux.HandleFunc("/wiki/api/v2/spaces/100/pages", func(w http.ResponseWriter, r *http.Request) {
		for _, s := range r.URL.Query()["status"] {
			if s == "trashed" || s == "deleted" { // this build rejects those statuses
				w.WriteHeader(400)
				return
			}
		}
		w.Write([]byte(`{"results":[{"id":"200","title":"Doc","version":{"number":1}}],"_links":{}}`))
	})
	mux.HandleFunc("/wiki/api/v2/pages/200/versions", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"number":1}],"_links":{}}`))
	})
	mux.HandleFunc("/wiki/api/v2/pages/200", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"id": "200", "title": "Doc",
			"body":    map[string]any{"storage": map[string]any{"value": "live " + v1Secret}},
			"version": map[string]any{"number": 1}, "_links": map[string]any{"webui": "/x"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	items := collect(t, srv.URL, "confluence", Options{})
	if !anyContains(items, v1Secret) {
		t.Fatalf("a 400 on the trashed/deleted listing lost the whole space's live pages; items=%d", len(items))
	}
}

// #1 regression: a secret in a custom textarea field must be EXTRACTED when --field requests it
// (the flag was previously a no-op — requested but never read).
func TestJiraCustomFieldExtracted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/api/2/serverInfo", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"deploymentType":"Cloud"}`)) })
	mux.HandleFunc("/rest/api/3/project/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"isLast":true,"values":[{"key":"P"}]}`))
	})
	mux.HandleFunc("/rest/api/3/search/jql", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Query().Get("fields"), "customfield_10010") {
			t.Errorf("custom field not requested: %s", r.URL.Query().Get("fields"))
		}
		w.Write([]byte(`{"isLast":true,"issues":[{"id":"1","key":"P-1","fields":{"summary":"x","customfield_10010":"token ` + v1Secret + `"}}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	items := collect(t, srv.URL, "jira", Options{CurrentOnly: true, Fields: []string{"customfield_10010"}})
	if !anyContains(items, v1Secret) {
		t.Fatalf("--field custom field secret was not extracted; items=%d", len(items))
	}
}

// #5/#7 regression: when the search comment field is truncated (total>returned), the dedicated
// /comment endpoint must be paged so an OLD comment's secret is not missed.
func TestJiraCommentPaginationFetchesAll(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/api/2/serverInfo", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"deploymentType":"Cloud"}`)) })
	mux.HandleFunc("/rest/api/3/project/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"isLast":true,"values":[{"key":"P"}]}`))
	})
	mux.HandleFunc("/rest/api/3/search/jql", func(w http.ResponseWriter, r *http.Request) {
		// 25 comments total, only 1 inline -> truncated -> the walker must fetch /comment
		w.Write([]byte(`{"isLast":true,"issues":[{"id":"1","key":"P-1","fields":{"summary":"x","comment":{"comments":[{"body":"recent"}],"total":25}}}]}`))
	})
	mux.HandleFunc("/rest/api/3/issue/P-1/comment", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"startAt":0,"maxResults":100,"total":1,"comments":[{"id":"7","body":"old creds ` + v1Secret + `"}]}`))
	})
	mux.HandleFunc("/rest/api/3/issue/P-1/changelog", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"isLast":true,"values":[]}`)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	items := collect(t, srv.URL, "jira", Options{CurrentOnly: true})
	if !anyContains(items, v1Secret) {
		t.Fatalf("truncated comments were not paged; old comment secret missed; items=%d", len(items))
	}
}

// #3/#4: N versions with byte-identical bodies must emit ONE item, not N (skip-by-body-hash dedup).
func TestConfluenceSkipIdenticalVersions(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wiki/api/v2/spaces", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"id":"100","key":"SP"}],"_links":{}}`))
	})
	mux.HandleFunc("/wiki/api/v2/spaces/100/pages", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"id":"200","title":"Doc","version":{"number":3}}],"_links":{}}`))
	})
	mux.HandleFunc("/wiki/api/v2/pages/200/versions", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"number":1},{"number":2},{"number":3}],"_links":{}}`))
	})
	mux.HandleFunc("/wiki/api/v2/pages/200", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{ // SAME body for every version
			"id": "200", "title": "Doc",
			"body":    map[string]any{"storage": map[string]any{"value": "unchanged " + v1Secret}},
			"version": map[string]any{"number": 1}, "_links": map[string]any{"webui": "/x"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	items := collect(t, srv.URL, "confluence", Options{})
	n := 0
	for _, it := range items {
		if it.Source == "confluence" && strings.Contains(it.Text, v1Secret) {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("identical versions not deduped: got %d confluence items with the secret, want 1", n)
	}
}

// #2: many issues each with a distinct history secret must ALL be found (the worker pool processes
// every issue; also runs under -race to catch concurrent-emit bugs).
func TestJiraManyIssuesAllFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/api/2/serverInfo", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"deploymentType":"Cloud"}`)) })
	mux.HandleFunc("/rest/api/3/project/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"isLast":true,"values":[{"key":"P"}]}`))
	})
	mux.HandleFunc("/rest/api/3/search/jql", func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		b.WriteString(`{"isLast":true,"issues":[`)
		for i := 1; i <= 20; i++ {
			if i > 1 {
				b.WriteByte(',')
			}
			b.WriteString(`{"id":"` + strconv.Itoa(i) + `","key":"P-` + strconv.Itoa(i) + `","fields":{"summary":"x"}}`)
		}
		b.WriteString(`]}`)
		w.Write([]byte(b.String()))
	})
	mux.HandleFunc("/rest/api/3/issue/", func(w http.ResponseWriter, r *http.Request) {
		// .../issue/P-N/changelog -> a secret unique to issue N
		key := strings.TrimPrefix(strings.TrimSuffix(r.URL.Path, "/changelog"), "/rest/api/3/issue/")
		w.Write([]byte(`{"isLast":true,"values":[{"created":"2020","items":[{"field":"description","fromString":"SECRET-` + key + `-` + v1Secret + `"}]}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	items := collect(t, srv.URL, "jira", Options{Workers: 6})
	for i := 1; i <= 20; i++ {
		want := "SECRET-P-" + strconv.Itoa(i) + "-" + v1Secret
		if !anyContains(items, want) {
			t.Fatalf("issue P-%d history secret missing — the pool dropped an issue; items=%d", i, len(items))
		}
	}
}

// #1 regression: a Confluence storage body HTML-entity-encodes '&' as '&amp;'. A secret whose value
// (or whose surrounding URL) contains '&' is split by the detector unless the body is entity-decoded.
func TestStorageTextDecodesEntities(t *testing.T) {
	if got := storageText("user=x&amp;token=" + v1Secret + "&amp;sig=y"); !strings.Contains(got, "&token="+v1Secret+"&sig=") {
		t.Fatalf("entities not decoded: %q", got)
	}
	// tags are preserved (T23 — macro params / CDATA still scanned in place)
	if got := storageText(`<ac:parameter ac:name="x">` + v1Secret + `</ac:parameter>`); !strings.Contains(got, "ac:parameter") || !strings.Contains(got, v1Secret) {
		t.Fatalf("tags wrongly stripped or text lost: %q", got)
	}
}

// #1 end-to-end: an entity-encoded secret in a Confluence page body is reconstructed and collected.
func TestConfluenceEntityEncodedSecretFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wiki/api/v2/spaces", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"id":"100","key":"SP"}],"_links":{}}`))
	})
	mux.HandleFunc("/wiki/api/v2/spaces/100/pages", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"id":"200","title":"Doc","version":{"number":1}}],"_links":{}}`))
	})
	mux.HandleFunc("/wiki/api/v2/pages/200", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"id": "200", "title": "Doc",
			"body":    map[string]any{"storage": map[string]any{"value": "url=https://h/?a=1&amp;k=" + v1Secret}},
			"version": map[string]any{"number": 1}, "_links": map[string]any{"webui": "/x"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	items := collect(t, srv.URL, "confluence", Options{CurrentOnly: true})
	// the decoded contiguous "&k=SECRET" must be present (not the "&amp;k=" split form)
	found := false
	for _, it := range items {
		if strings.Contains(it.Text, "&k="+v1Secret) {
			found = true
		}
	}
	if !found {
		t.Fatalf("entity-encoded secret not reconstructed; items=%d", len(items))
	}
}

// #7: the Cloud bulk-changelog path must extract the history secret from /changelog/bulkfetch (one
// call for the whole batch) — not just the per-issue fallback. Two issues share one bulk fetch.
func TestJiraBulkHistorySecretFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/api/2/serverInfo", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"deploymentType":"Cloud"}`)) })
	mux.HandleFunc("/rest/api/3/project/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"isLast":true,"values":[{"key":"P"}]}`))
	})
	mux.HandleFunc("/rest/api/3/search/jql", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"isLast":true,"issues":[{"id":"10","key":"P-1","fields":{"summary":"a"}},{"id":"11","key":"P-2","fields":{"summary":"b"}}]}`))
	})
	bulkHit := false
	mux.HandleFunc("/rest/api/3/changelog/bulkfetch", func(w http.ResponseWriter, r *http.Request) {
		bulkHit = true
		var body struct {
			IssueIdsOrKeys []string `json:"issueIdsOrKeys"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if len(body.IssueIdsOrKeys) != 2 {
			t.Errorf("bulkfetch did not batch both issues: %v", body.IssueIdsOrKeys)
		}
		// an entry per requested issue (P-2 has no history -> empty changeHistories), as the real API
		// returns — so neither issue is "omitted" and no per-issue fallback fires.
		w.Write([]byte(`{"issueChangeLogs":[{"issueId":"10","changeHistories":[{"created":"2020","author":{"emailAddress":"d@x"},"items":[{"field":"description","fromString":"old ` + v1Secret + `","toString":"clean"}]}]},{"issueId":"11","changeHistories":[]}]}`))
	})
	// the per-issue endpoint must NOT be needed when bulk works
	mux.HandleFunc("/rest/api/3/issue/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("per-issue changelog hit despite bulk being available: %s", r.URL.Path)
		w.Write([]byte(`{"isLast":true,"values":[]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	items := collect(t, srv.URL, "jira", Options{})
	if !bulkHit {
		t.Fatal("bulk changelog endpoint was never called")
	}
	if !anyContains(items, v1Secret) {
		t.Fatalf("bulk-history secret not collected; items=%d", len(items))
	}
}

// ultra-audit regressions: storageText decodes only the 5 XML entities (not 250+ HTML named / legacy
// no-semicolon forms that could corrupt a secret); confPath distinguishes same-titled pages by id;
// retryAfter caps a hostile huge value instead of overflowing Duration to a negative (-> panic).
// the parallel per-version fetch (scanVersionsParallel) must not drop or duplicate any version: a page
// with 3 versions each carrying a DISTINCT secret yields all 3, at distinct version paths.
func TestConfluenceParallelVersionsAllFound(t *testing.T) {
	secrets := map[string]string{"1": "AKIAV1AAAAAAAAAAAAA1", "2": "AKIAV2AAAAAAAAAAAAA2", "3": "AKIAV3AAAAAAAAAAAAA3"}
	mux := http.NewServeMux()
	mux.HandleFunc("/wiki/api/v2/spaces", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"id":"100","key":"SP"}],"_links":{}}`))
	})
	mux.HandleFunc("/wiki/api/v2/spaces/100/pages", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"id":"200","title":"Doc","version":{"number":3}}],"_links":{}}`))
	})
	mux.HandleFunc("/wiki/api/v2/pages/200/versions", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"number":1},{"number":2},{"number":3}],"_links":{}}`))
	})
	mux.HandleFunc("/wiki/api/v2/pages/200", func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("version")
		json.NewEncoder(w).Encode(map[string]any{
			"id": "200", "title": "Doc",
			"body":    map[string]any{"storage": map[string]any{"value": "key=" + secrets[v]}},
			"version": map[string]any{"number": 1}, "_links": map[string]any{"webui": "/x"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	items := collect(t, srv.URL, "confluence", Options{})
	for v, sec := range secrets {
		if !anyContains(items, sec) {
			t.Errorf("version %s secret %s not found among %d items (parallel fetch dropped a version)", v, sec, len(items))
		}
	}
}

// determinism regression: when several versions share an identical body, the parallel dedup must emit
// exactly one item at the SMALLEST version (deterministic Path/Fingerprint), not a race-dependent one.
func TestConfluenceIdenticalBodyEmitsMinVersion(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wiki/api/v2/spaces", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"id":"100","key":"SP"}],"_links":{}}`))
	})
	mux.HandleFunc("/wiki/api/v2/spaces/100/pages", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"id":"200","title":"Doc","version":{"number":4}}],"_links":{}}`))
	})
	mux.HandleFunc("/wiki/api/v2/pages/200/versions", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"number":2},{"number":3},{"number":4}],"_links":{}}`))
	})
	mux.HandleFunc("/wiki/api/v2/pages/200", func(w http.ResponseWriter, r *http.Request) {
		// every version returns the SAME body (the secret was added early and never changed)
		json.NewEncoder(w).Encode(map[string]any{
			"id": "200", "title": "Doc",
			"body":    map[string]any{"storage": map[string]any{"value": "key=" + v1Secret}},
			"version": map[string]any{"number": 1}, "_links": map[string]any{"webui": "/x"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	items := collect(t, srv.URL, "confluence", Options{})
	var hits []model.Item
	for _, it := range items {
		if strings.Contains(it.Text, v1Secret) {
			hits = append(hits, it)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("identical bodies must dedup to ONE item, got %d", len(hits))
	}
	if !strings.Contains(hits[0].Path, "@v2") { // min of {2,3,4} (the live cur=4 is appended but body is identical)
		t.Errorf("expected the smallest version in the path, got %q", hits[0].Path)
	}
}

func TestStorageTextTargetedEntities(t *testing.T) {
	if got := storageText("user=x&amp;tok=" + v1Secret); !strings.Contains(got, "&tok=") {
		t.Errorf("&amp; not decoded: %q", got)
	}
	if got := storageText("p&copy;q"); got != "p&copy;q" { // &copy; is NOT one of the 5 XML entities
		t.Errorf("legacy/named HTML entity wrongly decoded: %q", got)
	}
	if got := storageText("a&amp;lt;b"); got != "a&lt;b" { // single pass: double-escape -> literal "&lt;"
		t.Errorf("double-escaped entity re-decoded: %q", got)
	}
}

func TestConfPathDistinguishesPagesByID(t *testing.T) {
	if a, b := confPath("Runbook", "200", 1), confPath("Runbook", "201", 1); a == b {
		t.Errorf("same-titled pages collide on path: %q == %q", a, b)
	}
}

func TestRetryAfterCapsHostileValue(t *testing.T) {
	resp := &http.Response{Header: http.Header{"Retry-After": {"999999999999999"}}}
	if d := retryAfter(resp, time.Second); d <= 0 || d > 60*time.Second {
		t.Fatalf("retryAfter did not cap a hostile value (got %v) — negative would panic rand.Int64N", d)
	}
}

func TestAuthHeader(t *testing.T) {
	if h := (Auth{PAT: "p"}).header(); h != "Bearer p" {
		t.Errorf("PAT -> %q, want Bearer p", h)
	}
	if h := (Auth{Email: "a@b", Token: "t"}).header(); !strings.HasPrefix(h, "Basic ") {
		t.Errorf("email+token -> %q, want Basic ...", h)
	}
	if !(Auth{}).Empty() {
		t.Error("empty Auth should report Empty()")
	}
}

// the secret that lives only in the CURRENT version (to prove current content is scanned on Server/DC).
const currentSecret = "CURRENT_VERSION_ghp_REALTOKENPLACEHOLDER1234"

// jiraServerMock serves the Server/Data Center surface: serverInfo deploymentType=DataCenter, a FLAT
// /project array (not paginated), POST /rest/api/2/search (startAt pagination), and a STRING (wiki
// markup, not ADF) description. The secret lives only in the changelog fromString.
func jiraServerMock() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/api/2/serverInfo", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"deploymentType":"DataCenter","version":"9.4.0"}`))
	})
	mux.HandleFunc("/rest/api/2/project", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"key":"OPS"},{"key":"SEC"}]`)) // flat array, NOT a {values:[]} page
	})
	mux.HandleFunc("/rest/api/2/search", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("_p") == "" && r.Method != "POST" {
			// guard: Server/DC search must be POST
		}
		w.Write([]byte(`{"startAt":0,"maxResults":50,"total":1,"issues":[{"id":"1","key":"OPS-1","fields":{"summary":"ticket","description":"now clean wiki text"}}]}`))
	})
	mux.HandleFunc("/rest/api/2/issue/OPS-1/changelog", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"isLast":true,"total":1,"maxResults":100,"startAt":0,"values":[{"created":"2019-05-01T00:00:00.000+0000","author":{"displayName":"ops"},"items":[{"field":"description","fromString":"creds: ` + v1Secret + `","toString":"now clean wiki text"}]}]}`))
	})
	return httptest.NewServer(mux)
}

func TestJiraServerHistory(t *testing.T) {
	srv := jiraServerMock()
	defer srv.Close()
	c := NewClient(srv.URL, Auth{PAT: "x"}, 5*time.Second)
	if dep, err := DetectJira(context.Background(), c); err != nil || dep.Cloud() {
		t.Fatalf("expected Server/DC, got dep=%+v err=%v", dep, err)
	}
	items := collect(t, srv.URL, "jira", Options{})
	if !anyContains(items, v1Secret) {
		t.Fatalf("Server/DC Jira: changelog-history secret NOT found; items=%d", len(items))
	}
}

// confServerMock serves the Server/DC surface (NO /wiki prefix). It is REALISTIC about historical
// fetches: status=historical returns a body ONLY for versions strictly older than current; the
// CURRENT version is served WITHOUT status=historical (status=historical&version=current -> 404,
// as real Confluence behaves). v1 holds one secret; the current version holds another.
func confServerMock() *httptest.Server {
	mux := http.NewServeMux()
	four04 := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }
	mux.HandleFunc("/wiki/api/v2/spaces", four04)  // not Cloud v2
	mux.HandleFunc("/wiki/rest/api/space", four04) // not Cloud v1
	mux.HandleFunc("/rest/api/space", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"key":"ENG"}],"_links":{}}`))
	})
	mux.HandleFunc("/rest/api/content/500/version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"number":1},{"number":2},{"number":3}]}`))
	})
	mux.HandleFunc("/rest/api/content/500", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		historical := q.Get("status") == "historical"
		ver := q.Get("version")
		body := ""
		switch {
		case !historical: // current-version fetch (no status=historical) -> latest body
			body = "current runbook " + currentSecret
		case ver == "1":
			body = "old runbook " + v1Secret
		case ver == "2":
			body = "v2 clean"
		default: // status=historical on the CURRENT version: real Confluence 404s this
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"id": "500", "title": "Runbook",
			"body":    map[string]any{"storage": map[string]any{"value": body}},
			"version": map[string]any{"number": 3},
			"_links":  map[string]any{"webui": "/display/ENG/Runbook"},
		})
	})
	mux.HandleFunc("/rest/api/content", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"id":"500","title":"Runbook","version":{"number":3}}],"_links":{}}`))
	})
	return httptest.NewServer(mux)
}

func TestConfluenceServerHistoryAndCurrent(t *testing.T) {
	srv := confServerMock()
	defer srv.Close()
	c := NewClient(srv.URL, Auth{PAT: "x"}, 5*time.Second)
	if dep, err := DetectConfluence(context.Background(), c); err != nil || dep.Cloud() {
		t.Fatalf("expected Server/DC, got dep=%+v err=%v", dep, err)
	}
	items := collect(t, srv.URL, "confluence", Options{})
	if !anyContains(items, v1Secret) {
		t.Errorf("Server/DC Confluence: historical v1 secret NOT found; items=%d", len(items))
	}
	if !anyContains(items, currentSecret) {
		t.Errorf("Server/DC Confluence: CURRENT-version secret NOT found — status=historical does not serve the latest version; items=%d", len(items))
	}
}
