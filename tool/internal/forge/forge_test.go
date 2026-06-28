package forge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/safehttp"
)

// stubForge serves GitHub/GitLab-shaped project lists. Each entry in routes maps a request path
// prefix (e.g. "/groups/", "/users/") to the JSON array of repos that prefix should return; any
// path without a matching prefix gets a 404, which is exactly what the org→user fallback keys on.
func stubForge(t *testing.T, routes map[string]string) *httptest.Server {
	t.Helper()
	// httptest binds loopback, which safehttp's client now blocks by default; allow it for the test.
	safehttp.AllowPrivate.Store(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(false) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for prefix, body := range routes {
			if strings.HasPrefix(r.URL.Path, prefix) {
				w.Header().Set("Content-Type", "application/json")
				// Pagination stops on a short page, so a single non-full page ends the loop.
				w.Write([]byte(body))
				return
			}
		}
		http.Error(w, `{"message":"404 Not Found"}`, http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestListGists(t *testing.T) {
	srv := stubForge(t, map[string]string{
		"/users/octocat/gists": `[{"git_pull_url":"https://gist.github.com/aaa.git","clone_url":"https://x/wrong"},{"git_pull_url":"https://gist.github.com/bbb.git"}]`,
	})
	t.Setenv("GITHUB_API", srv.URL)
	t.Setenv("GITHUB_TOKEN", "")
	urls, err := ListGists(context.Background(), "github:octocat")
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 2 || urls[0] != "https://gist.github.com/aaa.git" {
		t.Fatalf("expected gist git_pull_urls, got %v", urls)
	}
	if _, err := ListGists(context.Background(), "gitlab:x"); err == nil {
		t.Error("expected error for a non-github target")
	}
}

func TestGitlabReposFallback(t *testing.T) {
	const groupProj = `[{"http_url_to_repo":"https://gitlab.com/grp/a.git"}]`
	const userProj = `[{"http_url_to_repo":"https://gitlab.com/usr/b.git"}]`

	tests := []struct {
		name    string
		routes  map[string]string
		want    []string
		wantErr bool
	}{
		{
			name:   "group found returns group projects",
			routes: map[string]string{"/groups/": groupProj},
			want:   []string{"https://gitlab.com/grp/a.git"},
		},
		{
			name:   "group 404 falls back to user projects",
			routes: map[string]string{"/users/": userProj},
			want:   []string{"https://gitlab.com/usr/b.git"},
		},
		{
			name:    "both 404 is a clean not-found error",
			routes:  map[string]string{}, // every path 404s
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := stubForge(t, tt.routes)
			t.Setenv("GITLAB_API", srv.URL)
			t.Setenv("GITLAB_TOKEN", "")

			got, err := gitlabRepos(context.Background(), "lercas")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got urls %v", got)
				}
				if !strings.Contains(err.Error(), "404") {
					t.Errorf("want a 404 not-found error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGithubReposFallback pins the existing GitHub org→user fallback that the GitLab one mirrors,
// so a regression in either path is caught the same way.
func TestGithubReposFallback(t *testing.T) {
	const orgRepo = `[{"clone_url":"https://github.com/org/a.git"}]`
	const userRepo = `[{"clone_url":"https://github.com/usr/b.git"}]`

	tests := []struct {
		name    string
		routes  map[string]string
		want    []string
		wantErr bool
	}{
		{
			name:   "org found returns org repos",
			routes: map[string]string{"/orgs/": orgRepo},
			want:   []string{"https://github.com/org/a.git"},
		},
		{
			name:   "org 404 falls back to user repos",
			routes: map[string]string{"/users/": userRepo},
			want:   []string{"https://github.com/usr/b.git"},
		},
		{
			name:    "both 404 is a clean not-found error",
			routes:  map[string]string{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := stubForge(t, tt.routes)
			t.Setenv("GITHUB_API", srv.URL)
			t.Setenv("GITHUB_TOKEN", "")

			got, err := githubRepos(context.Background(), "lercas")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got urls %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestForgeDoesNotLeakTokenAcrossRedirect proves the H1 fix: a (malicious / compromised / MITM'd) API
// that 302-redirects to another origin must NOT receive the GitLab PRIVATE-TOKEN. The bare http.Client
// forwarded it (Go strips Authorization on a host change but never a custom header, nor on a port
// change); safehttp's cross-host-redirect guard refuses the hop so the token never reaches the target.
func TestForgeDoesNotLeakTokenAcrossRedirect(t *testing.T) {
	// httptest binds loopback, which safehttp blocks by default; allow it so the redirect GUARD (not the
	// dial guard) is what's exercised. The attacker origin differs from the API by port → different origin.
	safehttp.AllowPrivate.Store(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(false) })

	var attackerSawToken string
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get("PRIVATE-TOKEN"); v != "" {
			attackerSawToken = v
		}
		w.Write([]byte(`[]`))
	}))
	t.Cleanup(attacker.Close)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(api.Close)
	t.Setenv("GITLAB_API", api.URL)
	t.Setenv("GITLAB_TOKEN", "glpat-SUPERSECRET-DO-NOT-LEAK")

	_, _ = ListRepos(context.Background(), "gitlab:somegroup") // errors on the blocked redirect — fine
	if attackerSawToken != "" {
		t.Fatalf("GITLAB_TOKEN leaked across redirect to attacker origin: %q", attackerSawToken)
	}
}
