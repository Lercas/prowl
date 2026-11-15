package domain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strconv"

	"github.com/Lercas/prowl/tool/internal/model"
)

type responseOriginKey struct{}
type responseOrigin struct {
	url, digest string
}
type inlineMapKey struct{}

func textDigest(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func responseContext(ctx context.Context, content fetchedText) context.Context {
	return context.WithValue(ctx, responseOriginKey{}, responseOrigin{content.url, content.digest})
}

func responseItem(content fetchedText, source string, complete bool) model.Item {
	transform := "web-response"
	if !complete {
		transform = "web-response-prefix"
	}
	return model.Item{Text: content.text, Source: source, Path: content.url, Meta: map[string]any{
		"digest": content.digest, "source_transform": transform,
	}}
}

// Web view URIs distinguish a declared extraction from an actual network resource.
// Request query selectors survive only in private keyed identity material.
func webViewIdentity(it *model.Item, sourceURL, kind, label string, ordinal int) {
	u, err := url.Parse(sourceURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return
	}
	u.Fragment, u.RawFragment = kind+"/"+strconv.Itoa(ordinal)+"/"+label, ""
	u.Scheme = "web+" + u.Scheme
	it.IdentityPath = u.String()
	u.User, u.RawQuery, u.ForceQuery = nil, "", false
	it.ArtifactURI = u.String()
}

func attachWebProvenance(ctx context.Context, it *model.Item) {
	meta := make(map[string]any, len(it.Meta)+3)
	for k, v := range it.Meta {
		meta[k] = v
	}
	if it.Error == nil {
		if _, ok := meta["digest"]; !ok {
			meta["digest"] = textDigest(it.Text)
		}
	}
	if response, ok := ctx.Value(responseOriginKey{}).(responseOrigin); ok {
		meta["source_url"] = model.SafeLocator(response.url)
		if it.Error == nil && response.digest != "" {
			meta["container_digest"] = response.digest
		}
	} else if _, ok := meta["source_url"]; !ok {
		meta["source_url"] = model.SafeLocator(it.Path)
	}
	it.Meta = meta
	if it.ArtifactURI != "" {
		return
	}
	if u, err := url.Parse(it.Path); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		it.IdentityPath = it.Path
		it.ArtifactURI = model.SafeLocator(it.Path)
	}
}
