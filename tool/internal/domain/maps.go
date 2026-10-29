package domain

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/Lercas/prowl/tool/internal/model"
)

var mappingRef = regexp.MustCompile(`(?m)(?://[#@]|/\*[#@])\s*sourceMappingURL\s*=\s*([^\s*]+)`)
var imports = regexp.MustCompile(`(?m)(?:\b(?:import|export)\s+(?:[^;\n]{0,200}?\s+from\s+)?|\bimport\s*\(\s*)["']([^"'\s]+)["']`)

type asset struct {
	URL      string
	Depth    int
	Optional bool
}

// walkAssets follows only literal, same-origin references, never evaluated code.
func walkAssets(ctx context.Context, ch chan<- model.Item, c *http.Client, urls []string, source string, b *budget, bodyDedup *contentSeen) {
	fetcher := newTextFetcher(c)
	queue := make([]asset, 0, len(urls))
	for _, u := range dedup(urls) {
		queue = append(queue, asset{URL: u})
	}
	seen := map[string]bool{}
	for len(queue) > 0 {
		if ctx.Err() != nil {
			return
		}
		if b.done() {
			model.Note(ctx, "web_asset_limit", "", true)
			return
		}
		a := queue[0]
		queue = queue[1:]
		if seen[a.URL] {
			continue
		}
		seen[a.URL] = true
		if !b.take() {
			model.Note(ctx, "web_asset_limit", a.URL, true)
			return
		}
		fetchCtx := ctx
		var optionalCoverage *model.Coverage
		if a.Optional {
			optionalCoverage = model.NewCoverage()
			fetchCtx = model.WithCoverage(ctx, optionalCoverage)
		}
		text, present, fetchErr := fetcher.getText(fetchCtx, a.URL)
		ok := present && fetchErr == nil
		mapConfirmed := !a.Optional || sourceMapVersion(text) == 3
		if optionalCoverage != nil {
			_, _, diagnostics := optionalCoverage.Snapshot()
			for _, diagnostic := range diagnostics {
				model.Note(ctx, diagnostic.Code, diagnostic.Path, ok && mapConfirmed && diagnostic.Incomplete)
			}
		}
		if !ok {
			if !a.Optional {
				model.Note(ctx, "web_asset_unavailable", a.URL, true)
			}
			continue
		}
		// Keep every locator even for identical bundles; repeated observations carry provenance.
		meta := map[string]any{"source_url": a.URL}
		sum := sha256.Sum256([]byte(text))
		meta["digest"] = hex.EncodeToString(sum[:])
		if !sendItem(ctx, ch, model.Item{Text: text, Path: a.URL, Source: source, Meta: meta}) {
			return
		}
		if strings.HasSuffix(strings.Split(a.URL, "?")[0], ".map") {
			if mapConfirmed {
				emitSourceMap(ctx, ch, a.URL, text, b)
			} else {
				model.Note(ctx, "optional_map_not_found", a.URL, false)
			}
			continue
		}
		refs := mappingRef.FindAllStringSubmatch(text, 33)
		if len(refs) > 32 {
			model.Note(ctx, "web_reference_limit", a.URL, true)
			refs = refs[:32]
		}
		for _, r := range refs {
			if strings.HasPrefix(r[1], "data:") {
				if len(r[1]) > maxBodyBytes {
					model.Note(ctx, "inline_map_limit", a.URL, true)
					continue
				}
				if decoded, ok := decodeInlineMap(r[1]); ok {
					emitSourceMap(ctx, ch, a.URL+"!/inline.map", decoded, b)
				} else {
					model.Note(ctx, "source_map_invalid", a.URL, true)
				}
				continue
			}
			if u, ok := sameOriginRef(a.URL, r[1]); ok {
				if a.Depth >= 4 {
					model.Note(ctx, "web_depth_limit", a.URL, true)
				} else {
					queue = append(queue, asset{URL: u, Depth: a.Depth + 1})
				}
			} else {
				model.Note(ctx, "external_reference", a.URL, false)
			}
		}
		js := strings.ToLower(path.Ext(strings.Split(a.URL, "?")[0]))
		if js == ".js" || js == ".mjs" || js == ".cjs" {
			if len(refs) == 0 {
				queue = append(queue, asset{URL: strings.Split(a.URL, "?")[0] + ".map", Depth: a.Depth, Optional: true})
			}
			moduleRefs := imports.FindAllStringSubmatch(text, 257)
			if len(moduleRefs) > 256 {
				model.Note(ctx, "web_reference_limit", a.URL, true)
				moduleRefs = moduleRefs[:256]
			}
			for _, r := range moduleRefs {
				// A bare module specifier is a package name, whereas a bare map name is a URL.
				if !strings.HasPrefix(r[1], ".") && !strings.HasPrefix(r[1], "/") && !strings.HasPrefix(r[1], "https://") && !strings.HasPrefix(r[1], "http://") {
					continue
				}
				if u, ok := sameOriginRef(a.URL, r[1]); ok {
					if a.Depth >= 4 {
						model.Note(ctx, "web_depth_limit", a.URL, true)
					} else {
						queue = append(queue, asset{URL: u, Depth: a.Depth + 1})
					}
				}
			}
		}
		if len(queue) > 2048 {
			model.Note(ctx, "web_queue_limit", a.URL, true)
			queue = queue[:2048]
		}
	}
}

func sourceMapVersion(text string) int {
	var header struct {
		Version int `json:"version"`
	}
	if json.Unmarshal([]byte(text), &header) != nil {
		return 0
	}
	return header.Version
}
func sameOriginRef(base, ref string) (string, bool) {
	b, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	r, err := url.Parse(ref)
	if err != nil {
		return "", false
	}
	u := b.ResolveReference(r)
	u.Fragment = ""
	return u.String(), u.User == nil && u.Scheme == b.Scheme && u.Host == b.Host
}
func decodeInlineMap(raw string) (string, bool) {
	head, body, ok := strings.Cut(raw, ",")
	if !ok || !strings.HasPrefix(head, "data:application/json") {
		return "", false
	}
	if strings.HasSuffix(head, ";base64") {
		b, err := base64.StdEncoding.DecodeString(body)
		return string(b), err == nil && len(b) <= maxBodyBytes
	}
	s, err := url.PathUnescape(body)
	return s, err == nil && len(s) <= maxBodyBytes
}
func emitSourceMap(ctx context.Context, ch chan<- model.Item, locator, text string, b *budget) {
	var m struct {
		Version        int       `json:"version"`
		Sources        []string  `json:"sources"`
		SourcesContent []*string `json:"sourcesContent"`
	}
	if json.Unmarshal([]byte(text), &m) != nil || m.Version != 3 || len(m.Sources) != len(m.SourcesContent) || len(m.Sources) > 256 {
		model.Note(ctx, "source_map_invalid", locator, true)
		return
	}
	for i, content := range m.SourcesContent {
		if content == nil {
			model.Note(ctx, "source_map_content_missing", locator, true)
			continue
		}
		if len(*content) > maxBodyBytes {
			model.Note(ctx, "source_map_content_limit", locator, true)
			continue
		}
		if !b.take() {
			model.Note(ctx, "web_asset_limit", locator, true)
			return
		}
		name := model.SafeLocator(m.Sources[i])
		if len(name) > 1024 {
			model.Note(ctx, "source_map_name_limit", locator, true)
			continue
		}
		p := model.SafeLocator(locator) + "!/sources/" + url.PathEscape(name)
		sum := sha256.Sum256([]byte(*content))
		if !sendItem(ctx, ch, model.Item{Text: *content, Path: p, Source: "code", Meta: map[string]any{"source_map": model.SafeLocator(locator), "original_source": name, "digest": hex.EncodeToString(sum[:])}}) {
			return
		}
	}
}
