// Package domain implements focused external secret discovery for a single domain: its HTML, inline
// SSR/hydration state blobs, and referenced JS bundles + source-maps. Recon adds a crt.sh+wayback sweep.
package domain

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
)

// sendItem delivers an item unless ctx is cancelled; returns false when discovery should stop.
func sendItem(ctx context.Context, ch chan<- model.Item, it model.Item) bool {
	if it.Error != nil {
		model.Note(ctx, "web_source_error", it.Path, true)
	}
	// Only this source knows its paths are web locators; URL-looking local filenames stay literal.
	if u, err := url.Parse(it.Path); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		it.ArtifactURI = it.Path
	}
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
	HTTPClient *http.Client // Optional owned transport; the default retains the SSRF guard.
}

// Discover returns a stream of fetched Items (HTML, state blobs, JS, source-maps) to scan.
// All network I/O is ctx-cancellable, retried with backoff, and guarded by a per-origin breaker.
func Discover(ctx context.Context, target string, opts Options) (<-chan model.Item, *atomic.Bool) {
	if opts.MaxAssets == 0 {
		opts.MaxAssets = 300
	}
	model.CoverageFrom(ctx).RegisterScope("domain", target, struct {
		Recon     bool
		MaxAssets int
	}{opts.Recon, opts.MaxAssets})
	ch := make(chan model.Item, 64)
	reached := &atomic.Bool{} // set once the root page is fetched, so the caller can exit non-zero on an unreachable host
	go func() {
		defer close(ch)
		if !opts.Authorized {
			sendItem(ctx, ch, model.Item{Path: "[unauthorized domain target]", Source: "code", Error: errors.New("domain discovery requires authorization")})
			return
		}
		if opts.MaxAssets < 1 {
			sendItem(ctx, ch, model.Item{Path: "domain", Source: "code", Error: errors.New("max-assets must be positive")})
			return
		}
		address, err := ParseTarget(target)
		if err != nil || opts.Recon && !address.ReconEligible {
			if err == nil {
				err = errors.New("recon requires a DNS hostname without an explicit port")
			}
			sendItem(ctx, ch, model.Item{Path: "[invalid domain target]", Source: "code", Error: err})
			return
		}
		apex := address.Host
		target = address.Canonical
		b := newBudget(opts.MaxAssets)
		client := opts.HTTPClient
		if client == nil {
			client = newClient(opts.Timeout)
		}
		fetcher := newTextFetcher(client)
		diagnostic := func(path string, err error) bool {
			return sendItem(ctx, ch, model.Item{Path: path, Source: "code", Error: err})
		}

		bodyDedup := &contentSeen{seen: map[uint64]bool{}}
		discoveredBodies := map[string]bool{}
		var assetURLs []string
		emit := func(base, htmlText string, complete bool) bool {
			if bodyDedup.firstTime(htmlText) {
				if !b.take() {
					diagnostic(base, errors.New("domain asset budget exhausted"))
					return false
				}
				if !sendItem(ctx, ch, model.Item{Text: htmlText, Source: "code", Path: base}) {
					return false
				}
			}
			if !complete {
				return true // Scan the prefix, but do not discover more URLs from an incomplete document.
			}
			// Identical documents on different roots still resolve relative URLs to different hosts.
			root, err := parseHTMLDocument(htmlText)
			if err != nil && !diagnostic(base, err) {
				return false
			}
			if root != nil {
				links, err := extractAssetsFromDocument(root, base)
				if err != nil && !diagnostic(base, err) {
					return false
				}
				assetURLs = append(assetURLs, links...)
			}
			if discoveredBodies[htmlText] {
				return true
			}
			// A complete alternate root may repeat a previously scanned prefix. It still supplies
			// authoritative asset links, which the incomplete document did not discover.
			discoveredBodies[htmlText] = true
			// inline hydration/state/config blobs
			for _, it := range extractStateBlobsFromDocument(htmlText, root, base) {
				if !sendItem(ctx, ch, it) {
					return false
				}
			}
			return true
		}

		// fetch the domain's own page(s): apex + www, https first, http fallback
		got := false
		for _, base := range address.roots {
			if b.done() {
				diagnostic(base, errors.New("domain asset budget exhausted"))
				break
			}
			content, err := fetcher.getDocument(ctx, base)
			if err != nil && content.present {
				if content.text != "" && !emit(content.url, content.text, false) || !diagnostic(content.url, err) {
					return
				}
			}
			if err == nil && content.present {
				got = true
				reached.Store(true)
				if !emit(content.url, content.text, true) {
					return
				}
			}
		}
		if !got && address.fallback != "" {
			base := address.fallback
			content, err := fetcher.getDocument(ctx, base)
			if err != nil && content.present {
				if content.text != "" && !emit(content.url, content.text, false) || !diagnostic(content.url, err) {
					return
				}
			}
			if err == nil && content.present {
				got = true
				reached.Store(true)
				if !emit(content.url, content.text, true) {
					return
				}
			}
		}
		if !got {
			model.Note(ctx, "domain_unreachable", apex, true)
			logx.Warn("domain root not reachable", "host", apex)
			diagnostic(target, errors.New("no root endpoint could be read completely"))
			return
		}

		// fetch & scan the referenced JS bundles / source-maps / json
		required := map[string]bool{}
		for _, u := range assetURLs {
			required[u] = true
		}
		assetURLs = dedup(withSourceMaps(dedup(assetURLs)))
		logx.Info("page assets referenced", "host", apex, "count", len(assetURLs))
		fetcher.fetchAll(ctx, ch, assetURLs, "code", b, 8, bodyDedup, required)

		// optional deep recon: subdomains + wayback history + path probes
		if opts.Recon && ctx.Err() == nil {
			subs, err := fetcher.crtshSubdomains(ctx, apex)
			if err != nil {
				diagnostic("https://crt.sh/", err)
			}
			logx.Info("recon: subdomains via crt.sh", "count", len(subs))
			wb, err := fetcher.waybackAssets(ctx, apex, 120)
			if err != nil {
				diagnostic("https://web.archive.org/", err)
			}
			logx.Info("recon: historical assets via wayback", "count", len(wb))
			historical := map[string]bool{}
			for _, u := range wb {
				historical[u] = true
			}
			fetcher.fetchAll(ctx, ch, wb, "code", b, 6, bodyDedup, historical)
			var paths []string
			if len(subs) > 30 {
				diagnostic("https://crt.sh/", errors.New("recon subdomain limit exhausted"))
			}
			for _, s := range capStrings(subs, 30) {
				for _, p := range commonPaths {
					paths = append(paths, "https://"+s+p)
				}
			}
			fetcher.fetchAll(ctx, ch, paths, "code", b, 8, bodyDedup, nil)
		}
		logx.Info("domain scan complete", "fetched", b.used())
	}()
	return ch, reached
}

// contentSeen scans each byte-identical body once: a catch-all server returns the same index.html for
// every probed path (/.env, /.git/config, …), else each secret is reported once per path.
type contentSeen struct {
	mu   sync.Mutex
	seen map[uint64]bool
}

func (s *contentSeen) firstTime(text string) bool {
	const off, prime = uint64(1469598103934665603), uint64(1099511628211)
	h := off
	for i := 0; i < len(text); i++ {
		h = (h ^ uint64(text[i])) * prime
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen[h] {
		return false
	}
	s.seen[h] = true
	return true
}

func (f *textFetcher) fetchAll(ctx context.Context, ch chan<- model.Item, urls []string, source string, b *budget, conc int, bodyDedup *contentSeen, required map[string]bool) {
	if required == nil {
		required = map[string]bool{}
	}
	if conc < 1 {
		conc = 1
	}
	var wg sync.WaitGroup
	redirectedMaps := map[string]bool{}
	scheduled := map[string]bool{}
	depths := map[string]int{}
	for _, u := range urls {
		scheduled[u] = true
	}
	schedule := func(u string, depth int, mandatory bool) {
		if scheduled[u] {
			return
		}
		if depth > 4 || len(scheduled) >= 2048 {
			model.Note(ctx, "web_reference_limit", u, true)
			return
		}
		scheduled[u] = true
		depths[u] = depth
		if mandatory {
			required[u] = true
		}
		urls = append(urls, u)
	}
	type result struct {
		content fetchedText
		err     error
	}
	type pendingFetch struct {
		url    string
		result chan result
	}
	// Keep at most conc admitted, unconsumed responses. Faster later requests cannot choose the
	// duplicate body's path or free a slot ahead of a slower earlier request.
	pending := make([]pendingFetch, 0, min(conc, len(urls)))
	next := 0
	stopped := false
	admit := func() bool {
		if stopped || next == len(urls) || ctx.Err() != nil {
			return false
		}
		u := urls[next]
		if !b.take() {
			stopped = true
			sendItem(ctx, ch, model.Item{Source: source, Path: u, Error: errors.New("domain asset budget exhausted")})
			return false
		}
		next++
		job := pendingFetch{url: u, result: make(chan result, 1)}
		pending = append(pending, job)
		wg.Add(1)
		go func() {
			defer wg.Done()
			content, err := f.getDocument(ctx, u)
			job.result <- result{content: content, err: err}
		}()
		return true
	}
	for len(pending) < conc && admit() {
	}
	emit := func(u string, fetched result) bool {
		content := fetched.content
		if fetched.err != nil {
			if !sendItem(ctx, ch, model.Item{Source: source, Path: content.url, Error: fetched.err}) {
				return false
			}
			if content.present && content.text != "" && bodyDedup.firstTime(content.text) {
				return sendItem(ctx, ch, model.Item{Text: content.text, Source: source, Path: content.url})
			}
			return true
		}
		if !content.present && required[u] {
			return sendItem(ctx, ch, model.Item{Source: source, Path: u, Error: fmt.Errorf("referenced asset is unavailable")})
		}
		if content.present && content.url != u {
			original, err := url.Parse(u)
			if err == nil && strings.HasSuffix(strings.ToLower(original.Path), ".js") {
				// A completed JS redirect can publish its map beside the final bundle URL.
				for _, candidate := range withSourceMaps([]string{content.url})[1:] {
					if !scheduled[candidate] {
						redirectedMaps[candidate] = true
					}
				}
			}
		}
		if content.present && content.text != "" {
			if bodyDedup.firstTime(content.text) && !sendItem(ctx, ch, model.Item{Text: content.text, Source: source, Path: content.url}) {
				return false
			}
			parsed, _ := url.Parse(content.url)
			if parsed != nil && strings.HasSuffix(strings.ToLower(parsed.Path), ".map") && sourceMapVersion(content.text) == 3 {
				emitSourceMap(ctx, ch, content.url, content.text, b)
			}
			if parsed != nil && (path.Ext(parsed.Path) == ".js" || path.Ext(parsed.Path) == ".mjs" || path.Ext(parsed.Path) == ".cjs") {
				refs := mappingRef.FindAllStringSubmatch(content.text, 33)
				if len(refs) > 32 {
					model.Note(ctx, "web_reference_limit", content.url, true)
					refs = refs[:32]
				}
				for _, ref := range refs {
					if strings.HasPrefix(ref[1], "data:") {
						if decoded, ok := decodeInlineMap(ref[1]); ok {
							emitSourceMap(ctx, ch, content.url+"!/inline.map", decoded, b)
						} else {
							model.Note(ctx, "source_map_invalid", content.url, true)
						}
					} else if nextURL, ok := sameOriginRef(content.url, ref[1]); ok {
						schedule(nextURL, depths[u]+1, true)
					}
				}
				importsFound := imports.FindAllStringSubmatch(content.text, 257)
				if len(importsFound) > 256 {
					model.Note(ctx, "web_reference_limit", content.url, true)
					importsFound = importsFound[:256]
				}
				for _, ref := range importsFound {
					if strings.HasPrefix(ref[1], ".") || strings.HasPrefix(ref[1], "/") || strings.HasPrefix(ref[1], "https://") || strings.HasPrefix(ref[1], "http://") {
						if nextURL, ok := sameOriginRef(content.url, ref[1]); ok {
							schedule(nextURL, depths[u]+1, true)
						}
					}
				}
			}
		}
		return true
	}
	for len(pending) > 0 {
		job := pending[0]
		var fetched result
		select {
		case fetched = <-job.result:
		case <-ctx.Done():
			wg.Wait()
			return
		}
		pending[0] = pendingFetch{}
		pending = pending[1:]
		if !emit(job.url, fetched) {
			wg.Wait()
			return
		}
		admit()
	}
	wg.Wait()
	if len(redirectedMaps) > 0 && ctx.Err() == nil {
		maps := make([]string, 0, len(redirectedMaps))
		for candidate := range redirectedMaps {
			maps = append(maps, candidate)
		}
		sort.Strings(maps)
		// Guessed maps remain optional and share the original discovery budget. Their .map paths
		// do not trigger another JS follow-up pass, even if the map itself redirects elsewhere.
		f.fetchAll(ctx, ch, maps, source, b, conc, bodyDedup, nil)
	}
}

func withSourceMaps(urls []string) []string {
	out := make([]string, 0, len(urls)*2)
	for _, u := range urls {
		out = append(out, u)
		parsed, err := url.Parse(u)
		if err == nil && strings.HasSuffix(strings.ToLower(parsed.Path), ".js") {
			parsed.Path += ".map"
			if parsed.RawPath != "" {
				parsed.RawPath += ".map"
			}
			parsed.Fragment, parsed.RawFragment = "", ""
			out = append(out, parsed.String()) // Keep query parameters selecting the bundle revision.
			if parsed.RawQuery != "" || parsed.ForceQuery {
				parsed.RawQuery, parsed.ForceQuery = "", false
				out = append(out, parsed.String()) // Some servers publish maps only without selectors.
			}
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
