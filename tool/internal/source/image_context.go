package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/Lercas/prowl/tool/internal/jsonstrict"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type imageOriginKey struct{}
type imageLayerExpectedKey struct{}
type imageOrigin struct {
	base             url.URL
	selection, label string
	slot             int
	scope            *model.ImageScope
}

func imageBoundary(ctx context.Context) context.Context {
	ctx = mobileBoundary(ctx)
	ctx = context.WithValue(ctx, imageLayerExpectedKey{}, struct{}{})
	return context.WithValue(ctx, imageOriginKey{}, struct{}{})
}

func imageContext(ctx context.Context, arg string, requested ImageInput, maxBytes int64, timeout time.Duration, exclude []string) (context.Context, ImageInput, error) {
	kind := effectiveImageKind(arg, requested)
	origin := imageOrigin{selection: arg}
	if len(arg) > 32768 || strings.ContainsRune(arg, 0) {
		return nil, kind, errors.New("invalid image source")
	}
	switch kind {
	case ImageTar, ImageOCIDir:
		absolute, err := filepath.Abs(arg)
		if err != nil {
			return nil, kind, errors.New("invalid local image source")
		}
		absolute = filepath.ToSlash(absolute)
		if !strings.HasPrefix(absolute, "/") {
			absolute = "/" + absolute
		}
		scheme := "image+file"
		if kind == ImageOCIDir {
			scheme = "image+oci"
		}
		origin.base = url.URL{Scheme: scheme, Path: absolute}
		origin.selection = origin.base.String()
	case ImageStdin:
		origin.base = url.URL{Scheme: "image+stdin", Path: "/payload"}
	case ImageRef:
		ref, err := name.ParseReference(arg)
		if err != nil {
			return nil, kind, errors.New("invalid registry image reference")
		}
		origin.base = url.URL{Scheme: "image+ref", Path: "/" + ref.Name()}
		origin.selection = ref.Name()
	default:
		return nil, kind, errors.New("invalid image input kind")
	}
	ctx = imageBoundary(ctx)
	ctx = context.WithValue(ctx, imageOriginKey{}, origin)
	ctx = model.WithSourceLocator(ctx, origin.locator)
	model.CoverageFrom(ctx).RegisterScope("image", origin.base.String(), struct {
		Revision, Selection string
		Requested, Resolved ImageInput
		MaxBytes            int64
		Timeout             time.Duration
		Exclude             []string
	}{"1.5.0-image-source-v1", origin.selection, requested, kind, maxBytes, timeout, exclude})
	return ctx, kind, nil
}

func (o imageOrigin) locator(p string) string {
	u := o.base
	u.Fragment = fmt.Sprintf("image/%d", o.slot)
	if _, idx, name, ok := parseLayerPath(p); ok && strings.HasPrefix(p, o.label+"|") {
		u.Fragment += fmt.Sprintf("/layer/%d/%s", idx, name)
	} else if suffix, ok := strings.CutPrefix(p, o.label+"|image:config/"); ok {
		u.Fragment += "/config/" + suffix
	}
	return u.String()
}

func withImageOrigin(ctx context.Context, label string, slot int, fi *FinalIndex) context.Context {
	o, ok := ctx.Value(imageOriginKey{}).(imageOrigin)
	if !ok {
		return ctx
	}
	o.label, o.slot, o.scope = label, slot, fi.scope
	ctx = context.WithValue(ctx, imageOriginKey{}, o)
	return model.WithSourceLocator(ctx, o.locator)
}

func attachImageOrigin(ctx context.Context, it *model.Item) {
	o, ok := ctx.Value(imageOriginKey{}).(imageOrigin)
	if !ok {
		return
	}
	it.ArtifactURI = o.locator(it.Path)
	it.IdentityPath = it.ArtifactURI + "\x00selection\x00" + o.selection
	it.ImageScope, it.ImagePath = o.scope, it.Path
	meta := make(map[string]any, len(it.Meta)+1)
	for k, v := range it.Meta {
		meta[k] = v
	}
	meta["source_url"] = it.ArtifactURI
	it.Meta = meta
}

func imageBytesDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Keep readable content if metadata cannot be established; the error makes the
// acquisition incomplete and prevents final-layer/remediation claims.
func imageMetadataContext(ctx context.Context, ch chan<- model.Item, img v1.Image, label string, fi *FinalIndex, cfg *v1.ConfigFile, cfgErr error) (context.Context, *v1.ConfigFile) {
	meta := map[string]any{}
	var manifest v1.Manifest
	raw, err := img.RawManifest()
	if err != nil || int64(len(raw)) > maxImageMetadataBytes || jsonstrict.UnmarshalContext(ctx, raw, &manifest) != nil || manifest.SchemaVersion != 2 {
		imageSourceError(ctx, ch, fi, label+"|image:manifest", errors.New("image manifest metadata unavailable"))
	} else {
		meta["image_digest"] = imageBytesDigest(raw)
	}
	if cfgErr == nil && cfg != nil {
		raw, err = img.RawConfigFile()
		if err == nil && int64(len(raw)) <= maxImageMetadataBytes {
			var parsed v1.ConfigFile
			if jsonstrict.UnmarshalContext(ctx, raw, &parsed) == nil {
				cfg = &parsed
				meta["config_digest"] = imageBytesDigest(raw)
				if manifest.Config.Digest.Algorithm == "sha256" && manifest.Config.Digest.Hex != meta["config_digest"] {
					imageSourceError(ctx, ch, fi, label+"|image:config-metadata", errors.New("image config digest mismatch"))
				}
			} else {
				err = errors.New("invalid raw image config")
			}
		} else {
			err = errors.New("image config metadata unavailable")
		}
		if err != nil {
			imageSourceError(ctx, ch, fi, label+"|image:config-metadata", errors.New("image config metadata unavailable"))
		}
	}
	return model.WithProvenance(ctx, meta), cfg
}

// ImageLocator is safe to log, including when a malformed reference contained
// accidentally pasted URL credentials or signed query parameters.
func ImageLocator(arg string, kind ImageInput) string {
	ctx, _, err := imageContext(context.Background(), arg, kind, 0, 0, nil)
	if err != nil {
		return "<invalid image source>"
	}
	origin := ctx.Value(imageOriginKey{}).(imageOrigin)
	return origin.base.String()
}

// ImageFailure preserves failed acquisition coverage without reflecting raw
// registry/OS errors, credentials or temporary stdin spool names.
func ImageFailure(ctx context.Context, arg string, kind ImageInput, maxBytes int64, timeout time.Duration, exclude []string) <-chan model.Item {
	ch := make(chan model.Item, 1)
	local, _, err := imageContext(ctx, arg, kind, maxBytes, timeout, exclude)
	if err == nil {
		o := local.Value(imageOriginKey{}).(imageOrigin)
		model.Note(local, "image_acquisition_failed", o.base.String(), true)
		emitSourceError(local, ch, o.base.String(), errors.New("image acquisition failed"))
	} else {
		local = imageBoundary(ctx)
		model.CoverageFrom(local).RegisterScope("image", "<invalid image source>", "1.5.0-image-source-v1")
		model.Note(local, "image_acquisition_failed", "<image>", true)
		emitSourceError(local, ch, "<image>", errors.New("image acquisition failed"))
	}
	close(ch)
	return ch
}
