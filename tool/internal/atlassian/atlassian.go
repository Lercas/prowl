package atlassian

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/safehttp"
)

// DefaultMaxItems bounds a single scan's emitted units (issue/page versions) so a pathological or
// enormous instance cannot run unbounded. It is generous enough for large real instances; the cap
// is announced loudly when hit (never a silent truncation) and is raised with --max-items.
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
		// RedactURL strips any user:token@ that slipped into the base URL before it reaches the error.
		return nil, dep, fmt.Errorf("detect %s at %s: %w", product, safehttp.RedactURL(baseURL), err)
	}

	out := make(chan model.Item, 256)
	walkCtx, cancel := context.WithCancel(ctx)
	go func() {
		defer close(out)
		defer cancel()
		// emit is called from many pool workers — the counter/flag are atomic. A small overrun past the
		// cap is fine (workers may pass the check before the Add); the cancel() then stops every loop.
		var emitted atomic.Int64
		var warned atomic.Bool
		max := int64(opts.MaxItems)
		emit := func(it model.Item) {
			if emitted.Load() >= max {
				if warned.CompareAndSwap(false, true) {
					logx.Warn("atlassian: item cap reached — scan truncated; raise --max-items to scan more",
						"cap", opts.MaxItems, "product", product)
				}
				cancel() // unblock every paginating loop via its ctx.Err() check
				return
			}
			select {
			case out <- it:
				emitted.Add(1)
			case <-walkCtx.Done():
			}
		}
		var werr error
		if product == "jira" {
			werr = walkJira(walkCtx, c, dep, opts, emit)
		} else {
			werr = walkConfluence(walkCtx, c, dep, opts, emit)
		}
		if werr != nil && walkCtx.Err() == nil {
			logx.Error(product+" scan error", "err", werr)
		}
	}()
	return out, dep, nil
}
