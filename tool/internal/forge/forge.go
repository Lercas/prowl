// Package forge enumerates the repositories of a GitHub org/user, GitLab group, or Bitbucket
// workspace via each platform's REST API, so `prowl org` can clone and scan them all. Credentials
// come from a per-platform environment token, so private repositories are included when one is set.
package forge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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
	u := fmt.Sprintf("%s/users/%s/gists?per_page=100&page=1", strings.TrimRight(host, "/"), url.PathEscape(name))
	urls, status, err := listArrays(ctx, u, hdr, "git_pull_url")
	if status != http.StatusOK {
		err = errors.Join(err, fmt.Errorf("github gists API returned %d", status))
	}
	return urls, err
}

func githubRepos(ctx context.Context, name string) ([]string, error) {
	hdr := map[string]string{"Accept": "application/vnd.github+json", "Authorization": bearer(os.Getenv("GITHUB_TOKEN"))}
	return accountRepos(ctx, envOr("GITHUB_API", "https://api.github.com"), "orgs", name, "repos", "clone_url", hdr)
}

func gitlabRepos(ctx context.Context, name string) ([]string, error) {
	hdr := map[string]string{"PRIVATE-TOKEN": os.Getenv("GITLAB_TOKEN")}
	return accountRepos(ctx, envOr("GITLAB_API", "https://gitlab.com/api/v4"), "groups", name, "projects", "http_url_to_repo", hdr)
}

func accountRepos(ctx context.Context, host, kind, name, resource, field string, hdr map[string]string) ([]string, error) {
	endpoint := func(kind string) string {
		query := "per_page=100&page=1"
		if resource == "projects" {
			query += "&include_subgroups=true"
		}
		return fmt.Sprintf("%s/%s/%s/%s?%s", strings.TrimRight(host, "/"), kind, url.PathEscape(name), resource, query)
	}
	urls, status, err := listArrays(ctx, endpoint(kind), hdr, field)
	// Fallback only when the FIRST endpoint is absent, never after partial pagination.
	if status == http.StatusNotFound && err == nil {
		urls, status, err = listArrays(ctx, endpoint("users"), hdr, field)
	}
	if status != http.StatusOK {
		err = errors.Join(err, fmt.Errorf("repository API returned %d for %q", status, name))
	}
	return urls, err
}

func listArrays(ctx context.Context, first string, hdr map[string]string, field string) ([]string, int, error) {
	next := first
	seen := map[string]bool{}
	repos := map[string]bool{}
	var urls []string
	var problems error
	for page := 0; next != "" && page < maxPages; page++ {
		if seen[next] {
			return urls, 200, errors.Join(problems, errors.New("repository pagination cycle"))
		}
		seen[next] = true
		var entries []map[string]json.RawMessage
		status, headers, err := getJSON(ctx, next, hdr, &entries)
		if err != nil || status != 200 {
			if page > 0 && err == nil {
				err = fmt.Errorf("repository pagination returned %d", status)
			}
			return urls, status, errors.Join(problems, err)
		}
		if entries == nil {
			return urls, status, errors.Join(problems, errors.New("repository API must return an array"))
		}
		for _, entry := range entries {
			var clone string
			if err := json.Unmarshal(entry[field], &clone); err != nil || clone == "" {
				problems = errors.New("one or more repository entries have no clone URL")
				continue
			}
			if !repos[clone] {
				urls = append(urls, clone)
				repos[clone] = true
			}
		}
		continuation, err := nextPage(headers, next)
		if err != nil {
			return urls, status, errors.Join(problems, err)
		}
		if continuation != "" {
			continuation, err = checkedPageURL(first, next, continuation)
			if err != nil {
				return urls, status, errors.Join(problems, err)
			}
		}
		next = continuation
	}
	if next != "" {
		problems = errors.Join(problems, fmt.Errorf("repository pagination exceeded %d pages", maxPages))
	}
	return urls, 200, problems
}

func bitbucketRepos(ctx context.Context, name string) ([]string, error) {
	first := fmt.Sprintf("https://api.bitbucket.org/2.0/repositories/%s?pagelen=100", url.PathEscape(name))
	return bitbucketList(ctx, first, map[string]string{"Authorization": bearer(os.Getenv("BITBUCKET_TOKEN"))})
}

func bitbucketList(ctx context.Context, first string, hdr map[string]string) ([]string, error) {
	next := first
	seen := map[string]bool{}
	repos := map[string]bool{}
	var urls []string
	var problems error
	for n := 0; next != "" && n < maxPages; n++ {
		if seen[next] {
			return urls, errors.Join(problems, errors.New("repository pagination cycle"))
		}
		seen[next] = true
		var page struct {
			Values []struct {
				Links struct {
					Clone []struct{ Name, Href string } `json:"clone"`
				} `json:"links"`
			} `json:"values"`
			Next string `json:"next"`
		}
		status, _, err := getJSON(ctx, next, hdr, &page)
		if status != 200 {
			err = errors.Join(err, fmt.Errorf("bitbucket API returned %d", status))
		}
		if err != nil {
			return urls, errors.Join(problems, err)
		}
		if page.Values == nil {
			return urls, errors.Join(problems, errors.New("bitbucket API has no repository array"))
		}
		for _, v := range page.Values {
			found := false
			for _, cl := range v.Links.Clone {
				if cl.Name == "https" && cl.Href != "" {
					found = true
					if !repos[cl.Href] {
						urls = append(urls, cl.Href)
						repos[cl.Href] = true
					}
				}
			}
			if !found {
				problems = errors.New("one or more bitbucket entries have no HTTPS clone URL")
			}
		}
		next = page.Next
		if next != "" {
			next, err = checkedPageURL(first, first, next)
			if err != nil {
				return urls, errors.Join(problems, err)
			}
		}
	}
	if next != "" {
		problems = errors.Join(problems, fmt.Errorf("repository pagination exceeded %d pages", maxPages))
	}
	return urls, problems
}

// API-provided continuations are new requests, so redirect guards alone cannot protect credentials.
func checkedPageURL(first, current, next string) (string, error) {
	root, err := url.Parse(first)
	if err != nil {
		return "", err
	}
	base, err := url.Parse(current)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(next)
	if err != nil {
		return "", err
	}
	u := base.ResolveReference(ref)
	if u.User != nil || u.Fragment != "" || !strings.EqualFold(u.Scheme, root.Scheme) || !strings.EqualFold(u.Host, root.Host) || u.EscapedPath() != root.EscapedPath() {
		return "", errors.New("repository pagination left the original API endpoint")
	}
	return u.String(), nil
}

func nextPage(headers http.Header, current string) (string, error) {
	var next string
	for _, line := range headers.Values("Link") {
		for _, part := range strings.Split(line, ",") {
			part = strings.TrimSpace(part)
			end := strings.IndexByte(part, '>')
			if !strings.HasPrefix(part, "<") || end < 0 {
				return "", errors.New("malformed repository pagination Link")
			}
			_, params, err := mime.ParseMediaType("link" + strings.TrimSpace(part[end+1:]))
			if err != nil {
				return "", errors.New("malformed repository pagination Link")
			}
			for _, rel := range strings.Fields(params["rel"]) {
				if rel == "next" {
					if next != "" {
						return "", errors.New("multiple next-page links")
					}
					next = part[1:end]
				}
			}
		}
	}
	if next != "" {
		return next, nil
	}
	if page := headers.Get("X-Next-Page"); page != "" {
		n, err := strconv.Atoi(page)
		if err != nil || n < 1 {
			return "", errors.New("invalid next-page index")
		}
		u, err := url.Parse(current)
		if err != nil {
			return "", err
		}
		q := u.Query()
		q.Set("page", page)
		u.RawQuery = q.Encode()
		return u.String(), nil
	}
	return "", nil
}

func getJSON(ctx context.Context, u string, hdr map[string]string, out any) (int, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range hdr {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		const limit = 32 << 20
		body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err == nil && len(body) > limit {
			err = errors.New("repository API response exceeds 32 MiB")
		}
		if err == nil && !utf8.Valid(body) {
			err = errors.New("repository API response is not UTF-8")
		}
		if err == nil {
			err = json.Unmarshal(body, out)
		}
		if err != nil {
			return resp.StatusCode, resp.Header, fmt.Errorf("decode repository API: %w", err)
		}
	}
	return resp.StatusCode, resp.Header, nil
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
