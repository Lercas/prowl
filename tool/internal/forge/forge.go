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
	"sync/atomic"
	"time"

	"github.com/Lercas/prowl/tool/internal/jsonstrict"
	"github.com/Lercas/prowl/tool/internal/safehttp"
)

// client routes through safehttp so the cross-host-redirect guard can't forward the GitLab PRIVATE-TOKEN
// / GitHub Bearer to an attacker host (Go strips Authorization on a host change but not a custom header
// or a port change), and private-IP dials are blocked (SSRF via a GITHUB_API/GITLAB_API override).
// Self-hosted forge on an internal IP uses PROWL_ALLOW_PRIVATE_IPS; the redirect guard still applies.
var client = safehttp.Client(30 * time.Second)

const DefaultMaxPages = 200

var legacyMaxPages atomic.Int64

func init() { legacyMaxPages.Store(DefaultMaxPages) }

// SetMaxPages changes only defaults for future legacy listing calls.
func SetMaxPages(n int) {
	if n > 0 {
		legacyMaxPages.Store(int64(min(n, hardMaxPages)))
	}
}
func currentMaxPages() int { return int(legacyMaxPages.Load()) }

// Options describes one listing's immutable operational limits.
type Options struct{ MaxPages int }
type pageLimitKey struct{}

func withPageLimit(ctx context.Context, n int) context.Context {
	if n <= 0 {
		n = DefaultMaxPages
	}
	return context.WithValue(ctx, pageLimitKey{}, min(n, hardMaxPages))
}
func snapshotPageLimit(ctx context.Context) context.Context {
	if _, ok := ctx.Value(pageLimitKey{}).(int); ok {
		return ctx
	}
	return withPageLimit(ctx, currentMaxPages())
}
func pageLimit(ctx context.Context) int {
	if n, ok := ctx.Value(pageLimitKey{}).(int); ok {
		return n
	}
	return currentMaxPages()
}

func ListReposWithOptions(ctx context.Context, target string, options Options) ([]string, error) {
	return ListRepos(withPageLimit(ctx, options.MaxPages), target)
}
func ListGistsWithOptions(ctx context.Context, target string, options Options) ([]string, error) {
	return ListGists(withPageLimit(ctx, options.MaxPages), target)
}

// ListRepos returns the https clone URLs of every repository under target, where target is
// "<platform>:<name>" — github:<org-or-user>, gitlab:<group>, or bitbucket:<workspace>.
func ListRepos(ctx context.Context, target string) (urls []string, err error) {
	ctx = snapshotPageLimit(ctx)
	defer func() { recordInventory(ctx, target, false, urls, err) }()
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
func ListGists(ctx context.Context, target string) (urls []string, err error) {
	ctx = snapshotPageLimit(ctx)
	defer func() { recordInventory(ctx, target, true, urls, err) }()
	platform, name, ok := strings.Cut(target, ":")
	if !ok || name == "" || platform != "github" {
		return nil, fmt.Errorf("--gists supports a github:<user> target, got %q", target)
	}
	token, host := os.Getenv("GITHUB_TOKEN"), envOr("GITHUB_API", "https://api.github.com")
	host, err = apiBase(host)
	if err != nil {
		return nil, err
	}
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
	base, err := apiBase(host)
	if err != nil {
		return nil, err
	}
	host = base
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
	ctx = snapshotPageLimit(ctx)
	next := first
	seen := map[string]bool{}
	repos := map[string]bool{}
	var urls []string
	var problems error
	for page := 0; next != "" && page < pageLimit(ctx); page++ {
		if seen[next] {
			return urls, 200, errors.Join(problems, errors.New("repository pagination cycle"))
		}
		seen[next] = true
		var entries []map[string]json.RawMessage
		status, headers, err := getJSON(ctx, next, hdr, &entries)
		if status != 200 || (err != nil && !errors.Is(err, errListingClose)) {
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
			if err := json.Unmarshal(entry[field], &clone); err != nil || !validCloneEntry(clone) {
				problems = errors.New("one or more repository entries have no clone URL")
				continue
			}
			if !repos[clone] {
				urls = append(urls, clone)
				repos[clone] = true
			}
		}
		if err != nil {
			return urls, status, errors.Join(problems, err)
		}
		continuation, err := nextPage(headers, next)
		if err != nil {
			return urls, status, errors.Join(problems, err)
		}
		if continuation != "" {
			continuation, err = checkedArrayPageURL(first, next, continuation)
			if err != nil {
				return urls, status, errors.Join(problems, err)
			}
		}
		next = continuation
	}
	if next != "" {
		problems = errors.Join(problems, fmt.Errorf("repository pagination exceeded %d pages", pageLimit(ctx)))
	}
	return urls, 200, problems
}

func bitbucketRepos(ctx context.Context, name string) ([]string, error) {
	ctx = snapshotPageLimit(ctx)
	first := fmt.Sprintf("https://api.bitbucket.org/2.0/repositories/%s?pagelen=100", url.PathEscape(name))
	return bitbucketList(ctx, first, map[string]string{"Authorization": bearer(os.Getenv("BITBUCKET_TOKEN"))})
}

func bitbucketList(ctx context.Context, first string, hdr map[string]string) ([]string, error) {
	next := first
	seen := map[string]bool{}
	repos := map[string]bool{}
	var urls []string
	var problems error
	for n := 0; next != "" && n < pageLimit(ctx); n++ {
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
		if status != 200 || (err != nil && !errors.Is(err, errListingClose)) {
			return urls, errors.Join(problems, err)
		}
		if page.Values == nil {
			return urls, errors.Join(problems, errors.New("bitbucket API has no repository array"))
		}
		for _, v := range page.Values {
			found := false
			for _, cl := range v.Links.Clone {
				if cl.Name == "https" && validCloneEntry(cl.Href) {
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
		if err != nil {
			return urls, errors.Join(problems, err)
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
		problems = errors.Join(problems, fmt.Errorf("repository pagination exceeded %d pages", pageLimit(ctx)))
	}
	return urls, problems
}

// API-provided continuations are new requests, so redirect guards alone cannot protect credentials.
func checkedPageURL(first, current, next string) (string, error) {
	if len(next) > 8192 {
		return "", errors.New("repository continuation URL exceeds size limit")
	}
	root, err := url.Parse(first)
	if err != nil {
		return "", errors.New("invalid repository pagination URL")
	}
	base, err := url.Parse(current)
	if err != nil {
		return "", errors.New("invalid repository pagination URL")
	}
	ref, err := url.Parse(next)
	if err != nil {
		return "", errors.New("invalid repository pagination URL")
	}
	u := base.ResolveReference(ref)
	if u.User != nil || u.Fragment != "" || !strings.EqualFold(u.Scheme, root.Scheme) || !strings.EqualFold(u.Host, root.Host) || u.EscapedPath() != root.EscapedPath() {
		return "", errors.New("repository pagination left the original API endpoint")
	}
	return u.String(), nil
}

// GitHub/GitLab array listings use offset pages while preserving the requested selection.
// Bitbucket next links remain opaque within checkedPageURL's endpoint boundary.
func checkedArrayPageURL(first, current, next string) (string, error) {
	address, err := checkedPageURL(first, current, next)
	if err != nil {
		return "", err
	}
	root, _ := url.Parse(first)
	u, _ := url.Parse(address)
	firstQuery, err := url.ParseQuery(root.RawQuery)
	if err != nil {
		return "", errors.New("invalid repository selection query")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", errors.New("invalid repository continuation query")
	}
	for key, values := range firstQuery {
		if key == "page" {
			continue
		}
		if strings.Join(values, "\x00") != strings.Join(query[key], "\x00") {
			return "", errors.New("repository pagination changed the requested selection")
		}
	}
	for key := range query {
		if key != "page" && firstQuery[key] == nil {
			return "", errors.New("repository pagination introduced a selection parameter")
		}
	}
	if len(query["page"]) > 1 {
		return "", errors.New("ambiguous repository page index")
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
					if part[1:end] == "" {
						return "", errors.New("empty repository next-page link")
					}
					if next != "" {
						return "", errors.New("multiple next-page links")
					}
					next = part[1:end]
				}
			}
		}
	}
	pages := headers.Values("X-Next-Page")
	if len(pages) > 1 {
		return "", errors.New("ambiguous repository next-page header")
	}
	if next != "" {
		if page := headers.Get("X-Next-Page"); page != "" {
			u, err := url.Parse(next)
			if err != nil || u.Query().Get("page") != page {
				return "", errors.New("conflicting repository next-page headers")
			}
		}
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

// apiRequestError keeps the underlying error available for classification without reflecting a
// credential-bearing API URL, response or transport diagnostic into logs.
type apiRequestError struct{ cause error }

func (e *apiRequestError) Error() string { return "repository API request failed" }
func (e *apiRequestError) Unwrap() error { return e.cause }

var errListingClose = errors.New("close repository listing body failed")

func getJSON(ctx context.Context, rawURL string, hdr map[string]string, out any) (status int, headers http.Header, err error) {
	if len(rawURL) > 8192 {
		return 0, nil, errors.New("repository API endpoint exceeds size limit")
	}
	u, parseErr := url.Parse(rawURL)
	if parseErr != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
		return 0, nil, errors.New("invalid repository API endpoint")
	}
	registerAPI(ctx, rawURL, hdr)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, &apiRequestError{err}
	}
	for k, v := range hdr {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, &apiRequestError{err}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil && err == nil {
			err = errListingClose
		}
	}()
	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxJSONBody+1))
		if err != nil {
			return resp.StatusCode, resp.Header, errors.New("read repository API response failed")
		}
		if len(body) > maxJSONBody {
			return resp.StatusCode, resp.Header, errors.New("repository API response exceeds 32 MiB")
		}
		if err := boundListingRows(body, out); err != nil {
			return resp.StatusCode, resp.Header, err
		}
		if err := jsonstrict.UnmarshalContext(ctx, body, out); err != nil {
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
