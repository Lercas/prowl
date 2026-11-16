package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/model"
)

type bucketOriginKey struct{}
type bucketOrigin struct {
	paths  repositoryOrigin
	target string
}

// ValidateBucketTarget treats object keys literally, rather than interpreting '?' or '#' as URL
// query/fragment delimiters. Authentication belongs to the cloud CLI, never the bucket authority.
func ValidateBucketTarget(raw string) error {
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok || (scheme != "s3" && scheme != "gs") || !utf8.ValidString(raw) || strings.ContainsRune(raw, 0) {
		// Keep the released 1.4 wording, but never echo the raw target: it may carry credentials.
		return errors.New("unsupported bucket URI (use s3://bucket/prefix or gs://bucket/prefix)")
	}
	host, _, _ := strings.Cut(rest, "/")
	if host == "" || strings.ContainsAny(host, "@?#\\ \t\r\n") {
		return errors.New("bucket authority must be a bucket name without credentials or URL parameters")
	}
	return nil
}

// BucketArtifactURI encodes literal cloud object keys for URI consumers without decoding percent
// signs or reinterpreting key bytes as URL parameters.
func BucketArtifactURI(display string) string {
	scheme, rest, ok := strings.Cut(display, "://")
	if !ok || (scheme != "s3" && scheme != "gs") {
		return ""
	}
	host, key, hasKey := strings.Cut(rest, "/")
	u := &url.URL{Scheme: scheme, Host: host}
	if hasKey {
		u.Path = "/" + key
	}
	address := u.String()
	if _, err := url.Parse(address); err != nil {
		return ""
	}
	return address
}
func (o bucketOrigin) relative(path string) (string, bool) {
	if strings.HasPrefix(path, "s3://") || strings.HasPrefix(path, "gs://") {
		return "", false
	}
	if relative, ok := o.paths.relative(path); ok {
		return relative, true
	}
	if !filepath.IsAbs(path) {
		if absolute, err := filepath.Abs(path); err == nil {
			return o.paths.relative(absolute)
		}
	}
	return "", false
}

func (o bucketOrigin) locator(path string) string {
	if relative, ok := o.relative(path); ok {
		if relative == "" {
			return o.target
		}
		return strings.TrimRight(o.target, "/") + "/" + relative
	}
	return path
}

// BucketContext describes the observed local download. It does not invent an ETag, object version,
// listing completeness or provider identity beyond the operator-selected bucket target.
func BucketContext(ctx context.Context, dir, target string, budget, maxBytes int64, exclude []string) (context.Context, error) {
	if err := ValidateBucketTarget(target); err != nil {
		return ctx, err
	}
	roots := []string{filepath.Clean(dir)}
	if absolute, err := filepath.Abs(dir); err == nil && absolute != roots[0] {
		roots = append(roots, absolute)
	}
	if physical, err := filepath.EvalSymlinks(dir); err == nil && physical != roots[0] {
		roots = append(roots, physical)
	}
	origin := bucketOrigin{paths: repositoryOrigin{roots: roots}, target: target}
	ctx = context.WithValue(ctx, repositoryOriginKey{}, struct{}{})
	ctx = context.WithValue(ctx, bucketOriginKey{}, origin)
	ctx = model.WithSourceLocator(ctx, origin.locator)
	ctx = model.WithProvenance(model.WithoutProvenance(ctx), map[string]any{"source_url": "", "url": ""})
	model.CoverageFrom(ctx).RegisterScope("bucket", target, struct {
		Revision         string
		Budget, MaxBytes int64
		Exclude          []string
	}{"1.5.0-bucket-v1", budget, maxBytes, exclude})
	return ctx, nil
}

func bucketObjectContext(ctx context.Context, path string, raw []byte) context.Context {
	origin, ok := ctx.Value(bucketOriginKey{}).(bucketOrigin)
	if !ok {
		return ctx
	}
	if _, inside := origin.relative(path); !inside {
		model.Note(ctx, "bucket_object_unscoped", path, true)
		return ctx
	}
	location := BucketArtifactURI(origin.locator(path))
	if location == "" {
		location = origin.locator(path)
	}
	sum := sha256.Sum256(raw)
	return model.WithProvenance(ctx, map[string]any{"source_url": location, "url": "", "digest": hex.EncodeToString(sum[:])})
}

func attachBucketOrigin(ctx context.Context, it *model.Item) {
	origin, ok := ctx.Value(bucketOriginKey{}).(bucketOrigin)
	if !ok {
		return
	}
	it.ArtifactURI = BucketArtifactURI(origin.locator(it.Path))
	if url, _ := it.Meta["source_url"].(string); url == "" {
		copied := make(map[string]any, len(it.Meta)+1)
		for key, value := range it.Meta {
			copied[key] = value
		}
		copied["source_url"] = it.ArtifactURI
		it.Meta = copied
	}
}
