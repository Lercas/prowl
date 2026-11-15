package domain

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Lercas/prowl/tool/internal/jsonstrict"
	"github.com/Lercas/prowl/tool/internal/model"
)

var mappingRef = regexp.MustCompile(`(?m)(?://[#@]|/\*[#@])\s*sourceMappingURL\s*=\s*([^\s*]+)`)
var imports = regexp.MustCompile(`(?m)(?:\b(?:import|export)\s+(?:[^;\n]{0,200}?\s+from\s+)?|\bimport\s*\(\s*)["']([^"'\s]+)["']`)

func sourceMapVersion(text string) int {
	var header struct {
		Version int `json:"version"`
	}
	if jsonstrict.UnmarshalContext(context.Background(), []byte(text), &header) != nil {
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
	from, err := originOf(b.String())
	if err != nil {
		return "", false
	}
	to, err := originOf(u.String())
	return u.String(), err == nil && u.User == nil && from == to
}
func decodeInlineMap(raw string) (string, bool) {
	if len(raw) > maxBodyBytes {
		return "", false
	}
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
	if jsonstrict.UnmarshalContext(ctx, []byte(text), &m) != nil || m.Version != 3 || m.Sources == nil || len(m.Sources) != len(m.SourcesContent) || len(m.Sources) > 256 {
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
		it := model.Item{Text: *content, Path: p, Source: "code", Meta: map[string]any{"source_map": model.SafeLocator(locator), "original_source": name, "digest": hex.EncodeToString(sum[:]), "source_url": model.SafeLocator(locator), "source_transform": "source-map-content"}}
		parent, kind := locator, "sources"
		if response, ok := ctx.Value(responseOriginKey{}).(responseOrigin); ok {
			parent = response.url
		}
		if inline, ok := ctx.Value(inlineMapKey{}).(int); ok {
			kind = "inline-map-" + strconv.Itoa(inline)
		}
		webViewIdentity(&it, parent, kind, name, i+1)
		if !sendItem(ctx, ch, it) {
			return
		}
	}
}
