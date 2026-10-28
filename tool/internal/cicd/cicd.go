// Package cicd streams CI/CD logs and artifacts into Prowl's common scan pipeline.
package cicd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"github.com/Lercas/prowl/tool/internal/source"
	"github.com/Lercas/prowl/tool/internal/unpack"
)

const (
	defaultMaxRuns      = 20
	defaultMaxArtifacts = 100
	defaultMaxDownload  = int64(100 << 20)
	maxJSONBody         = int64(32 << 20)
)

// Options bounds one CI collection. BaseURL and Token are supplied by the command from environment
// variables; credentials never travel through argv.
type Options struct {
	BaseURL          string
	Token            string
	Branch           string
	MaxRuns          int
	MaxArtifacts     int
	MaxDownload      int64
	MaxItem          int64
	IncludeLogs      bool
	IncludeArtifacts bool
}

// Result describes collection completeness. Failures means at least one selected log/artifact could
// not be fetched or decoded, so callers can fail closed rather than certify a partial scan as clean.
type Result struct {
	Runs      int
	Artifacts int
	Items     int
	Skipped   int
	Failures  int
	LastError error
}

type target struct {
	platform string
	repo     string
}

type collector struct {
	target target
	opts   Options
	api    *http.Client
	direct *http.Client
}

// Collect starts a bounded read-only collection for github:owner/repo or gitlab:group/project.
// The single Result value is ready by the time the item channel closes.
func Collect(ctx context.Context, rawTarget string, opts Options) (<-chan model.Item, <-chan Result, error) {
	t, err := parseTarget(rawTarget)
	if err != nil {
		return nil, nil, err
	}
	if opts.Token == "" {
		return nil, nil, fmt.Errorf("%s token is required", t.platform)
	}
	opts = defaults(t, opts)
	if opts.MaxDownload == math.MaxInt64 || opts.MaxItem == math.MaxInt64 {
		return nil, nil, errors.New("CI size limit is too large")
	}
	if err := validateBaseURL(opts.BaseURL); err != nil {
		return nil, nil, err
	}
	if !opts.IncludeLogs && !opts.IncludeArtifacts {
		return nil, nil, errors.New("at least one of logs or artifacts must be enabled")
	}

	c := &collector{
		target: t,
		opts:   opts,
		api: &http.Client{
			Timeout:   45 * time.Second,
			Transport: safehttp.SafeTransport(15 * time.Second),
			// API endpoints return signed object-store redirects for downloads. Stop before following
			// so download() can deliberately create a second request with all credentials stripped.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		direct: safehttp.Client(45 * time.Second),
	}
	model.CoverageFrom(ctx).RegisterScope("cicd", rawTarget, struct {
		Branch                string
		MaxRuns, MaxArtifacts int
		MaxItem               int64
		Logs, Artifacts       bool
	}{opts.Branch, opts.MaxRuns, opts.MaxArtifacts, opts.MaxItem, opts.IncludeLogs, opts.IncludeArtifacts})
	items := make(chan model.Item, 32)
	done := make(chan Result, 1)
	go func() {
		defer close(items)
		var result Result
		switch t.platform {
		case "github":
			c.collectGitHub(ctx, items, &result)
		case "gitlab":
			c.collectGitLab(ctx, items, &result)
		}
		if result.Failures > 0 {
			model.Note(ctx, "ci_collection_failed", rawTarget, true)
			select {
			case items <- model.Item{Source: "ci", Path: rawTarget, Error: result.LastError}:
			case <-ctx.Done():
			}
		}
		if result.Skipped > 0 {
			model.Note(ctx, "ci_collection_skipped", rawTarget, true)
		}
		if result.Items == 0 {
			model.Note(ctx, "ci_empty", rawTarget, true)
		}
		done <- result
		close(done)
	}()
	return items, done, nil
}

func parseTarget(raw string) (target, error) {
	platform, repo, ok := strings.Cut(strings.TrimSpace(raw), ":")
	repo = strings.Trim(strings.TrimSpace(repo), "/")
	if !ok || repo == "" || !strings.Contains(repo, "/") {
		return target{}, fmt.Errorf("target must be github:owner/repo or gitlab:group/project, got %q", raw)
	}
	switch platform {
	case "github", "gitlab":
	default:
		return target{}, fmt.Errorf("unsupported CI platform %q (use github or gitlab)", platform)
	}
	if strings.ContainsAny(repo, "?#") {
		return target{}, fmt.Errorf("repository path contains URL query/fragment characters")
	}
	parts := strings.Split(repo, "/")
	for _, part := range parts {
		if strings.TrimSpace(part) == "" || part == "." || part == ".." {
			return target{}, fmt.Errorf("invalid repository path %q", repo)
		}
	}
	if platform == "github" && len(parts) != 2 {
		return target{}, fmt.Errorf("GitHub target must be github:owner/repo, got %q", raw)
	}
	return target{platform: platform, repo: repo}, nil
}

func defaults(t target, o Options) Options {
	if o.MaxRuns <= 0 {
		o.MaxRuns = defaultMaxRuns
	}
	if o.MaxArtifacts <= 0 {
		o.MaxArtifacts = defaultMaxArtifacts
	}
	if o.MaxDownload <= 0 {
		o.MaxDownload = defaultMaxDownload
	}
	if o.MaxItem <= 0 {
		o.MaxItem = 10 << 20
	}
	if o.BaseURL == "" {
		if t.platform == "github" {
			o.BaseURL = "https://api.github.com"
		} else {
			o.BaseURL = "https://gitlab.com/api/v4"
		}
	}
	o.BaseURL = strings.TrimRight(o.BaseURL, "/")
	return o
}

func validateBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("invalid CI API base URL %q (http/https required)", safehttp.RedactURL(raw))
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("CI API base URL must not contain credentials, query, or fragment")
	}
	return nil
}

type httpError struct {
	Status int
	URL    string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("%s returned HTTP %d", safehttp.RedactURL(e.URL), e.Status)
}

func (c *collector) request(ctx context.Context, rawURL string, auth bool) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if auth {
		switch c.target.platform {
		case "github":
			req.Header.Set("Authorization", "Bearer "+c.opts.Token)
			req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		case "gitlab":
			req.Header.Set("PRIVATE-TOKEN", c.opts.Token)
		}
	}
	return c.api.Do(req)
}

func (c *collector) getJSON(ctx context.Context, rawURL string, out any) error {
	resp, err := c.request(ctx, rawURL, true)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return &httpError{Status: resp.StatusCode, URL: rawURL}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJSONBody)).Decode(out); err != nil {
		return fmt.Errorf("decode %s: %w", safehttp.RedactURL(rawURL), err)
	}
	return nil
}

// download fetches an API download endpoint. A forge may redirect to a signed object-store URL; the
// second request is built from scratch with no Authorization/PRIVATE-TOKEN headers, preventing a
// cross-origin credential leak.
func (c *collector) download(ctx context.Context, rawURL string) ([]byte, error) {
	resp, err := c.request(ctx, rawURL, true)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		_ = resp.Body.Close()
		if loc == "" {
			return nil, fmt.Errorf("download redirect from %s has no Location", safehttp.RedactURL(rawURL))
		}
		base, _ := url.Parse(rawURL)
		next, err := base.Parse(loc)
		if err != nil || next.User != nil || (next.Scheme != "https" && next.Scheme != "http") {
			return nil, fmt.Errorf("refusing invalid CI download redirect")
		}
		if next.Scheme != "https" && !(safehttp.AllowPrivate.Load() && base.Scheme == "http") {
			return nil, fmt.Errorf("refusing CI download redirect that downgrades to plain HTTP")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next.String(), nil)
		if err != nil {
			return nil, err
		}
		resp, err = c.direct.Do(req)
		if err != nil {
			reason := "request failed"
			switch {
			case errors.Is(err, safehttp.ErrBlockedAddress):
				reason = "destination blocked by SSRF guard"
			case errors.Is(err, safehttp.ErrCrossHostRedirect):
				reason = "redirect changed origin"
			case ctx.Err() != nil:
				reason = "request cancelled or timed out"
			}
			// Never wrap err: net/http includes the full signed URL (and its bearer query) in errors.
			return nil, fmt.Errorf("signed CI download from %s failed: %s", next.Hostname(), reason)
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return nil, &httpError{Status: resp.StatusCode, URL: rawURL}
	}
	if resp.ContentLength > c.opts.MaxDownload {
		return nil, fmt.Errorf("download exceeds --max-download (%d > %d)", resp.ContentLength, c.opts.MaxDownload)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, c.opts.MaxDownload+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > c.opts.MaxDownload {
		return nil, fmt.Errorf("download exceeds --max-download (%d bytes)", c.opts.MaxDownload)
	}
	return raw, nil
}

func (c *collector) emitPayload(ctx context.Context, out chan<- model.Item, prefix, itemURL string, raw []byte, result *Result) error {
	stats, recognized, err := unpack.Walk(prefix, raw, unpack.BoundedLimits(c.opts.MaxItem, c.opts.MaxDownload), func(entry unpack.Entry) error {
		return c.emitFile(ctx, out, entry.Path, itemURL, entry.Data, result)
	})
	result.Skipped += stats.Skipped
	if recognized {
		if err == nil && stats.Limited > 0 {
			return fmt.Errorf("artifact content omitted at extraction limits")
		}
		return err
	}
	return c.emitFile(ctx, out, prefix, itemURL, raw, result)
}

func (c *collector) emitFile(ctx context.Context, out chan<- model.Item, itemPath, itemURL string, raw []byte, result *Result) error {
	if int64(len(raw)) > c.opts.MaxItem {
		result.Skipped++
		return fmt.Errorf("CI item exceeds --max-size (%d bytes)", c.opts.MaxItem)
	}
	text, ok := source.ScannableText(raw)
	if !ok || len(text) == 0 {
		result.Skipped++
		return nil
	}
	item := model.Item{
		Text:   string(text),
		Source: "ci",
		Path:   itemPath,
		Meta:   map[string]any{"url": itemURL},
	}
	model.AttachProvenance(ctx, &item)
	select {
	case out <- item:
		result.Items++
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *collector) fail(result *Result, err error) {
	if err == nil {
		return
	}
	result.Failures++
	result.LastError = err
}

func apiURL(base, suffix string, q url.Values) string {
	u := strings.TrimRight(base, "/") + suffix
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return u
}

func runLabel(name string, id int64) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "run"
	}
	name = strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r < 0x20 {
			return '-'
		}
		return r
	}, name)
	return name + "-" + strconv.FormatInt(id, 10)
}
