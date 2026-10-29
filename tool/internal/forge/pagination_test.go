package forge

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/safehttp"
)

func localAPI(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	previous := safehttp.AllowPrivate.Swap(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(previous) })
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	t.Setenv("GITHUB_API", s.URL)
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GITLAB_TOKEN", "")
	return s
}

func TestPaginationRetainsPartialLists(t *testing.T) {
	for _, mode := range []string{"cap", "server-error", "late-404", "short-page", "cycle"} {
		t.Run(mode, func(t *testing.T) {
			old := maxPages
			maxPages = 2
			t.Cleanup(func() { maxPages = old })
			if mode == "cap" {
				maxPages = 1
			}
			calls := 0
			localAPI(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Query().Get("page") == "2" {
					switch mode {
					case "server-error":
						w.WriteHeader(500)
						return
					case "late-404":
						w.WriteHeader(404)
						return
					}
					fmt.Fprint(w, `[{"clone_url":"https://owned.invalid/b.git"}]`)
					return
				}
				next := "2"
				if mode == "cycle" {
					next = "1"
				}
				w.Header().Set("Link", fmt.Sprintf(`<?per_page=100&page=%s>; rel="next"`, next))
				fmt.Fprint(w, `[{"clone_url":"https://owned.invalid/a.git"}]`)
			})
			urls, err := ListRepos(context.Background(), "github:owned")
			if len(urls) == 0 || urls[0] != "https://owned.invalid/a.git" {
				t.Fatalf("lost partial list: %v %v", urls, err)
			}
			if mode == "short-page" {
				if err != nil || len(urls) != 2 {
					t.Fatalf("ignored continuation: %v %v", urls, err)
				}
			} else if err == nil {
				t.Fatalf("incomplete listing accepted: %v (%d calls)", urls, calls)
			}
		})
	}
}

func TestInventoryJSONMustBeWholeAndValid(t *testing.T) {
	for _, body := range []string{`[] {}`, `[] garbage`, `null`, `[{"clone_url":"https://owned.invalid/a.git"},{}]`, "[]" + strings.Repeat(" ", (32<<20)+1)} {
		t.Run(fmt.Sprintf("body-%d", len(body)), func(t *testing.T) {
			localAPI(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			urls, err := ListRepos(context.Background(), "github:owned")
			if err == nil {
				t.Fatalf("invalid/incomplete inventory accepted: %v", urls)
			}
			if strings.Contains(body, "clone_url") && len(urls) != 1 {
				t.Fatalf("healthy entry lost: %v", urls)
			}
		})
	}
}

func TestPaginationNeverRequestsAnotherOrigin(t *testing.T) {
	hits := 0
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; fmt.Fprint(w, `[]`) }))
	t.Cleanup(other.Close)
	localAPI(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<`+other.URL+r.URL.Path+`?page=2>; rel="next"`)
		fmt.Fprint(w, `[{"clone_url":"https://owned.invalid/a.git"}]`)
	})
	t.Setenv("GITHUB_TOKEN", "owned-test-token")
	urls, err := ListRepos(context.Background(), "github:owned")
	if err == nil || hits != 0 || len(urls) != 1 {
		t.Fatalf("untrusted pagination followed: %v %v hits=%d", urls, err, hits)
	}
}

func TestGistsHTTPFailureIsNotEmptySuccess(t *testing.T) {
	localAPI(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) })
	if _, err := ListGists(context.Background(), "github:owned"); err == nil {
		t.Fatal("failed gist listing accepted")
	}
}

func TestGitlabNextPageHeader(t *testing.T) {
	s := localAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			w.Header().Set("X-Next-Page", "2")
			fmt.Fprint(w, `[{"http_url_to_repo":"https://owned.invalid/a.git"}]`)
		} else {
			fmt.Fprint(w, `[{"http_url_to_repo":"https://owned.invalid/b.git"}]`)
		}
	})
	t.Setenv("GITLAB_API", s.URL)
	urls, err := ListRepos(context.Background(), "gitlab:owned")
	if err != nil || len(urls) != 2 {
		t.Fatalf("GitLab continuation lost: %v %v", urls, err)
	}
}

func TestFullTerminalPageIsComplete(t *testing.T) {
	entries := make([]string, 100)
	for i := range entries {
		entries[i] = fmt.Sprintf(`{"clone_url":"https://owned.invalid/%d.git"}`, i)
	}
	localAPI(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "["+strings.Join(entries, ",")+"]") })
	old := maxPages
	maxPages = 1
	t.Cleanup(func() { maxPages = old })
	urls, err := ListRepos(context.Background(), "github:owned")
	if err != nil || len(urls) != 100 {
		t.Fatalf("complete page falsely truncated: %d %v", len(urls), err)
	}
}

func TestBitbucketContinuationRetainsPartialAndProtectsToken(t *testing.T) {
	hits := 0
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; fmt.Fprint(w, `{"values":[]}`) }))
	t.Cleanup(other.Close)
	s := localAPI(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"values":[{"links":{"clone":[{"name":"https","href":"https://owned.invalid/a.git"}]}}],"next":%q}`, other.URL+r.URL.Path)
	})
	urls, err := bitbucketList(context.Background(), s.URL+"/repositories/owned", map[string]string{"Authorization": "Bearer owned-test-token"})
	if err == nil || len(urls) != 1 || hits != 0 {
		t.Fatalf("unsafe bitbucket continuation: %v %v hits=%d", urls, err, hits)
	}
}
