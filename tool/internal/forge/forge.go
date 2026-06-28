// Package forge enumerates the repositories of a GitHub org/user, GitLab group, or Bitbucket
// workspace via each platform's REST API, so `prowl org` can clone and scan them all. Credentials
// come from a per-platform environment token, so private repositories are included when one is set.
package forge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Lercas/prowl/tool/internal/safehttp"
)

// client routes through safehttp so the cross-host-redirect guard can't forward the GitLab PRIVATE-TOKEN
// / GitHub Bearer to an attacker host (Go strips Authorization on a host change but not a custom header
// or a port change), and private-IP dials are blocked (SSRF via a GITHUB_API/GITLAB_API override).
// Self-hosted forge on an internal IP uses PROWL_ALLOW_PRIVATE_IPS; the redirect guard still applies.
var client = safehttp.Client(30 * time.Second)

// maxPages caps pagination so a malicious/compromised API can't drive an unbounded fetch loop.
// Overridable via config (limits.org_max_pages); set once at startup before ListRepos.
var maxPages = 200

// SetMaxPages overrides the pagination cap (limits.org_max_pages); a non-positive value is ignored.
func SetMaxPages(n int) {
	if n > 0 {
		maxPages = n
	}
}

// ListRepos returns the https clone URLs of every repository under target, where target is
// "<platform>:<name>" — github:<org-or-user>, gitlab:<group>, or bitbucket:<workspace>.
func ListRepos(ctx context.Context, target string) ([]string, error) {
	platform, name, ok := strings.Cut(target, ":")
	if !ok || name == "" {
		return nil, fmt.Errorf("target must be <platform>:<name> (e.g. github:Lercas), got %q", target)
	}
	switch platform {
	case "github":
		return githubRepos(ctx, name)
	case "gitlab":
		return gitlabRepos(ctx, name)
	case "bitbucket":
		return bitbucketRepos(ctx, name)
	default:
		return nil, fmt.Errorf("unknown platform %q (use github, gitlab, or bitbucket)", platform)
	}
}

// ListGists returns the clone URLs of every public gist of a github:<user> target. Gists are
// user-scoped (orgs have none) and clone from git_pull_url, not clone_url.
func ListGists(ctx context.Context, target string) ([]string, error) {
	platform, name, ok := strings.Cut(target, ":")
	if !ok || name == "" || platform != "github" {
		return nil, fmt.Errorf("--gists supports a github:<user> target, got %q", target)
	}
	token, host := os.Getenv("GITHUB_TOKEN"), envOr("GITHUB_API", "https://api.github.com")
	hdr := map[string]string{"Accept": "application/vnd.github+json", "Authorization": bearer(token)}
	var urls []string
	for page := 1; page <= maxPages; page++ {
		u := fmt.Sprintf("%s/users/%s/gists?per_page=100&page=%d", host, url.PathEscape(name), page)
		var gists []struct {
			GitPullURL string `json:"git_pull_url"`
		}
		status, err := getJSON(ctx, u, hdr, &gists)
		if err != nil {
			return urls, err
		}
		if status != http.StatusOK {
			return urls, fmt.Errorf("github gists API returned %d for %q (set GITHUB_TOKEN for rate limits)", status, name)
		}
		for _, g := range gists {
			if g.GitPullURL != "" {
				urls = append(urls, g.GitPullURL)
			}
		}
		if len(gists) < 100 {
			break
		}
	}
	return urls, nil
}

func githubRepos(ctx context.Context, name string) ([]string, error) {
	token, host := os.Getenv("GITHUB_TOKEN"), envOr("GITHUB_API", "https://api.github.com")
	hdr := map[string]string{"Accept": "application/vnd.github+json", "Authorization": bearer(token)}
	// An org first; fall back to a user account on 404.
	urls, status, err := githubList(ctx, host, "orgs", name, hdr)
	if status == http.StatusNotFound {
		urls, status, err = githubList(ctx, host, "users", name, hdr)
	}
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("github API returned %d for %q (set GITHUB_TOKEN for private repos / rate limits)", status, name)
	}
	return urls, nil
}

func githubList(ctx context.Context, host, kind, name string, hdr map[string]string) ([]string, int, error) {
	var urls []string
	for page := 1; page <= maxPages; page++ {
		// No "type" param: GitHub defaults to all repos for an org and owner-only for a user, which is
		// what we want (type=all on a user would wrongly include repos they merely collaborate on).
		u := fmt.Sprintf("%s/%s/%s/repos?per_page=100&page=%d", host, kind, url.PathEscape(name), page)
		var repos []struct {
			CloneURL string `json:"clone_url"`
		}
		status, err := getJSON(ctx, u, hdr, &repos)
		if err != nil || status != http.StatusOK {
			return urls, status, err
		}
		for _, r := range repos {
			if r.CloneURL != "" {
				urls = append(urls, r.CloneURL)
			}
		}
		if len(repos) < 100 {
			return urls, http.StatusOK, nil
		}
	}
	return urls, http.StatusOK, nil // hit the page cap; return what we have
}

func gitlabRepos(ctx context.Context, name string) ([]string, error) {
	token, host := os.Getenv("GITLAB_TOKEN"), envOr("GITLAB_API", "https://gitlab.com/api/v4")
	hdr := map[string]string{"PRIVATE-TOKEN": token}
	// A group first; fall back to a user account on 404 (a username is not a group).
	urls, status, err := gitlabList(ctx, host, "groups", name, hdr)
	if status == http.StatusNotFound {
		urls, status, err = gitlabList(ctx, host, "users", name, hdr)
	}
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("gitlab API returned %d for %q (set GITLAB_TOKEN for private groups)", status, name)
	}
	return urls, nil
}

func gitlabList(ctx context.Context, host, kind, name string, hdr map[string]string) ([]string, int, error) {
	var urls []string
	for page := 1; page <= maxPages; page++ {
		// include_subgroups is a groups-only param; GitLab ignores unknown query params on /users, so
		// the same URL shape works for both endpoints (it just has no effect when listing a user).
		u := fmt.Sprintf("%s/%s/%s/projects?per_page=100&include_subgroups=true&page=%d", host, kind, url.PathEscape(name), page)
		var projs []struct {
			HTTPURL string `json:"http_url_to_repo"`
		}
		status, err := getJSON(ctx, u, hdr, &projs)
		if err != nil || status != http.StatusOK {
			return urls, status, err
		}
		for _, p := range projs {
			if p.HTTPURL != "" {
				urls = append(urls, p.HTTPURL)
			}
		}
		if len(projs) < 100 {
			return urls, http.StatusOK, nil
		}
	}
	return urls, http.StatusOK, nil // hit the page cap; return what we have
}

func bitbucketRepos(ctx context.Context, name string) ([]string, error) {
	hdr := map[string]string{"Authorization": bearer(os.Getenv("BITBUCKET_TOKEN"))}
	next := fmt.Sprintf("https://api.bitbucket.org/2.0/repositories/%s?pagelen=100", url.PathEscape(name))
	var urls []string
	for page := 0; next != "" && page < maxPages; page++ {
		var page struct {
			Values []struct {
				Links struct {
					Clone []struct{ Name, Href string } `json:"clone"`
				} `json:"links"`
			} `json:"values"`
			Next string `json:"next"`
		}
		status, err := getJSON(ctx, next, hdr, &page)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("bitbucket API returned %d for %q (set BITBUCKET_TOKEN for private workspaces)", status, name)
		}
		for _, v := range page.Values {
			for _, cl := range v.Links.Clone {
				if cl.Name == "https" {
					urls = append(urls, cl.Href)
				}
			}
		}
		next = page.Next
	}
	return urls, nil
}

func getJSON(ctx context.Context, u string, hdr map[string]string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	for k, v := range hdr {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode %s: %w", u, err)
		}
	}
	return resp.StatusCode, nil
}

func bearer(token string) string {
	if token == "" {
		return ""
	}
	return "Bearer " + token
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
