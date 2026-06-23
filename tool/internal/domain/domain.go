// Package domain implements focused external secret discovery for a single domain: its HTML, inline
// SSR/hydration state blobs, and referenced JS bundles + source-maps. Recon adds a crt.sh+wayback sweep.
package domain

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
)

// sendItem delivers an item unless ctx is cancelled; returns false when discovery should stop.
func sendItem(ctx context.Context, ch chan<- model.Item, it model.Item) bool {
	select {
	case ch <- it:
		return true
	case <-ctx.Done():
		return false
	}
}

// Options configures discovery.
type Options struct {
	Authorized bool
	Recon      bool // opt-in deep sweep: subdomains (crt.sh) + wayback history
	MaxAssets  int
	Timeout    time.Duration
}

// Discover returns a stream of fetched Items (HTML, state blobs, JS, source-maps) to scan.
// All network I/O is ctx-cancellable, retried with backoff, and guarded by a per-host breaker.
func Discover(ctx context.Context, target string, opts Options) (<-chan model.Item, *atomic.Bool) {
	if opts.MaxAssets == 0 {
		opts.MaxAssets = 300
	}
	ch := make(chan model.Item, 64)
	reached := &atomic.Bool{} // set once the root page is fetched, so the caller can exit non-zero on an unreachable host
	go func() {
		defer close(ch)
		apex := normalizeDomain(target)
		b := newBudget(opts.MaxAssets)
		client := newClient(opts.Timeout)

		var assetURLs []string
		emit := func(base, htmlText string) bool {
			if b.take() && !sendItem(ctx, ch, model.Item{Text: htmlText, Source: "code", Path: base}) {
				return false
			}
			// inline hydration/state/config blobs
			for _, it := range ExtractStateBlobs(htmlText, base) {
				if b.done() {
					break
				}
				if b.take() && !sendItem(ctx, ch, it) {
					return false
				}
			}
			assetURLs = append(assetURLs, extractAssets(htmlText, base)...)
			return true
		}

		// fetch the domain's own page(s): apex + www, https first, http fallback
		got := false
		for _, base := range []string{"https://" + apex, "https://www." + apex} {
			if h, ok := getText(ctx, client, base); ok {
				got = true
				if !emit(base, h) {
					return
				}
			}
		}
		if !got {
			if h, ok := getText(ctx, client, "http://"+apex); ok {
				got = true
				emit("http://"+apex, h)
			}
		}
		if !got {
			logx.Warn("domain root not reachable", "host", apex)
			return
		}
		reached.Store(true)

		// fetch & scan the referenced JS bundles / source-maps / json
		assetURLs = withSourceMaps(dedup(assetURLs))
		logx.Info("page assets referenced", "host", apex, "count", len(assetURLs))
		fetchAll(ctx, ch, client, assetURLs, "code", b, 8)

		// optional deep recon: subdomains + wayback history + path probes
		if opts.Recon && ctx.Err() == nil {
			subs := crtshSubdomains(ctx, apex)
			logx.Info("recon: subdomains via crt.sh", "count", len(subs))
			wb := waybackAssets(ctx, apex, 120)
			logx.Info("recon: historical assets via wayback", "count", len(wb))
			fetchAll(ctx, ch, client, wb, "code", b, 6)
			var paths []string
			for _, s := range capStrings(subs, 30) {
				for _, p := range commonPaths {
					paths = append(paths, "https://"+s+p)
				}
			}
			fetchAll(ctx, ch, client, paths, "code", b, 8)
		}
		logx.Info("domain scan complete", "fetched", b.used())
	}()
	return ch, reached
}

func fetchAll(ctx context.Context, ch chan<- model.Item, c *http.Client, urls []string, source string, b *budget, conc int) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, conc)
	for _, u := range urls {
		if b.done() || ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			if !b.take() {
				return
			}
			if txt, ok := getText(ctx, c, u); ok && len(txt) > 0 {
				sendItem(ctx, ch, model.Item{Text: txt, Source: source, Path: u})
			}
		}(u)
	}
	wg.Wait()
}

func normalizeDomain(t string) string {
	t = strings.TrimSpace(strings.ToLower(t))
	t = strings.TrimPrefix(t, "https://")
	t = strings.TrimPrefix(t, "http://")
	if i := strings.IndexAny(t, "/:?"); i >= 0 {
		t = t[:i]
	}
	return strings.TrimPrefix(t, "www.")
}

func withSourceMaps(urls []string) []string {
	out := make([]string, 0, len(urls)*2)
	for _, u := range urls {
		out = append(out, u)
		base := u
		if i := strings.IndexByte(base, '?'); i >= 0 {
			base = base[:i]
		}
		if strings.HasSuffix(base, ".js") {
			out = append(out, base+".map") // probe the source-map (classic key leak)
		}
	}
	return out
}

func dedup(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func capStrings(ss []string, n int) []string {
	if len(ss) > n {
		return ss[:n]
	}
	return ss
}
