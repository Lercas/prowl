package atlassian

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
)

// DefaultMaxItems bounds a single scan's emitted units (issue/page versions) so a pathological or
// enormous instance cannot run unbounded. It is generous enough for large real instances; the cap
// is reported as an incomplete source when exceeded and is raised with --max-items.
const DefaultMaxItems = 200000

// Options tunes a Jira/Confluence scan.
type Options struct {
	CurrentOnly bool          // scan only the latest version (default: EVERY version, from the first)
	Projects    []string      // Jira: restrict to these project keys (empty = all visible)
	Spaces      []string      // Confluence: restrict to these space keys (empty = all visible)
	Fields      []string      // Jira: extra custom field ids to scan (e.g. customfield_10010)
	MaxItems    int           // cap on emitted items (0 -> DefaultMaxItems); a runaway backstop
	Workers     int           // concurrency for per-item detail fetches (0 -> defaultWorkers)
	Timeout     time.Duration // per-request timeout
	HTTPClient  *http.Client  // optional caller-owned transport; nil uses SSRF-guarded HTTP
}

// Collect detects the deployment behind baseURL for the given product ("jira" | "confluence"),
// then walks it, streaming one model.Item per scannable unit — current content AND every historical
// version. The channel closes when the walk finishes, the item cap is hit, or ctx is cancelled.
//
// Contract: the caller MUST drain the returned channel until it closes, or cancel ctx to stop early
// — abandoning it without cancelling leaks the producer goroutine (it blocks on a full channel).
// A detection/auth failure is returned synchronously (before any goroutine starts).
func Collect(ctx context.Context, baseURL, product string, auth Auth, opts Options) (<-chan model.Item, Deployment, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.MaxItems <= 0 {
		opts.MaxItems = DefaultMaxItems
	}
	c := NewClient(baseURL, auth, opts.Timeout)
	if c.initErr != nil {
		return nil, Deployment{}, c.initErr
	}
	if opts.HTTPClient != nil {
		c.http = opts.HTTPClient
	}

	var (
		dep Deployment
		err error
	)
	switch product {
	case "jira":
		dep, err = DetectJira(ctx, c)
	case "confluence":
		dep, err = DetectConfluence(ctx, c)
	default:
		return nil, Deployment{}, fmt.Errorf("unknown product %q (want jira|confluence)", product)
	}
	if err != nil {
		return nil, dep, fmt.Errorf("detect %s: %w", product, err)
	}

	origin := "[atlassian]"
	if parsed, err := url.Parse(baseURL); err == nil && parsed.Host != "" {
		origin = parsed.Scheme + "://" + parsed.Host
	}
	model.CoverageFrom(ctx).RegisterScope(product, origin, struct {
		BaseURL string
		Options Options
	}{baseURL, opts})
	out := make(chan model.Item, 256)
	walkCtx, cancel := context.WithCancel(ctx)
	go func() {
		defer close(out)
		defer cancel()
		// Reserve each content slot atomically. Diagnostics do not consume the content budget.
		var emitted atomic.Int64
		var capped atomic.Bool
		max := int64(opts.MaxItems)
		emit := func(it model.Item) {
			if it.Error != nil {
				model.Note(ctx, "atlassian_coverage_incomplete", it.Path, true)
			}
			if it.Error == nil {
				for {
					n := emitted.Load()
					if n >= max {
						capped.Store(true)
						cancel()
						return
					}
					if emitted.CompareAndSwap(n, n+1) {
						break
					}
				}
			}
			select {
			case out <- it:
			case <-ctx.Done():
			}
		}
		var werr error
		if product == "jira" {
			werr = walkJira(walkCtx, c, dep, opts, emit)
		} else {
			werr = walkConfluence(walkCtx, c, dep, opts, emit)
		}
		// Use the parent context: hitting our own budget cancels the walker, not the consumer.
		var diagnostic model.Item
		if capped.Load() {
			model.Note(ctx, "atlassian_item_limit", baseURL, true)
			diagnostic = sourceFailure(product, product, "item budget exhausted")
		} else if werr != nil {
			model.Note(ctx, "atlassian_collection_failed", baseURL, true)
			diagnostic = sourceFailure(product, product, "enumeration failed")
		}
		if diagnostic.Error != nil {
			select {
			case out <- diagnostic:
			case <-ctx.Done():
			}
		}
	}()
	return out, dep, nil
}

// sourceFailure keeps provider response bodies and credentials out of diagnostic logs.
func sourceFailure(source, path, operation string) model.Item {
	return model.Item{Source: source, Path: path, Error: errors.New(operation + "; results are incomplete")}
}

// cursorWalk detects cycles of any length, not only immediately repeated tokens.
type cursorWalk struct {
	seen  map[string]bool
	pages int
}

func (w *cursorWalk) advance(next string) error {
	if w.seen == nil {
		w.seen = make(map[string]bool)
	}
	w.pages++
	if next == "" {
		return nil
	}
	if w.seen[next] {
		return errors.New("pagination cursor repeated")
	}
	if w.pages >= maxPages {
		return errors.New("pagination page budget exhausted")
	}
	w.seen[next] = true
	return nil
}

// Unsupported optional status filters are tolerated only before any page has been collected.
func unsupportedStatus(err error, first bool) bool {
	s := statusOf(err)
	return first && (s == 400 || s == 404 || s == 405)
}
