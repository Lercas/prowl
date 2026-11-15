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

type mobileOriginKey struct{}
type mobileEntryKey struct{}
type mobileOrigin struct {
	base               url.URL
	display, selection string
}

func mobileContext(ctx context.Context, name string, borrowed bool, opts MobileOptions) (context.Context, error) {
	if !utf8.ValidString(opts.Origin) || len(name) > 32768 || len(opts.Origin) > 32768 || strings.ContainsRune(name, 0) || strings.ContainsRune(opts.Origin, 0) {
		return nil, errors.New("invalid mobile source locator")
	}
	origin := mobileOrigin{display: filepath.Base(name)}
	if borrowed {
		origin.display = model.SafeLocator(name)
	}
	if opts.Origin != "" {
		u, err := url.Parse(opts.Origin)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Opaque != "" {
			return nil, errors.New("invalid mobile acquisition URL")
		}
		u.Fragment, u.RawFragment = "", ""
		origin.selection = u.String()
		u.User = nil
		u.RawQuery = ""
		u.ForceQuery = false
		u.Scheme = "mobile+" + u.Scheme
		origin.base = *u
	} else if borrowed {
		origin.base = url.URL{Scheme: "mobile+payload", Path: "/" + model.SafeLocator(name)}
		origin.selection = name
	} else {
		absolute, err := filepath.Abs(name)
		if err != nil {
			return nil, errors.New("resolve mobile source locator")
		}
		absolute = filepath.ToSlash(absolute)
		if !strings.HasPrefix(absolute, "/") {
			absolute = "/" + absolute
		}
		origin.base = url.URL{Scheme: "mobile+file", Path: absolute}
		origin.selection = origin.base.String()
	}
	ctx = mobileBoundary(ctx)
	ctx = context.WithValue(ctx, mobileOriginKey{}, origin)
	ctx = model.WithProvenance(model.WithoutProvenance(ctx), map[string]any{"source_url": origin.base.String(), "url": ""})
	ctx = model.WithSourceLocator(ctx, origin.locator)
	// Coverage retains only the policy digest. Request credentials/query selectors
	// are never stored in the public target or member URI.
	model.CoverageFrom(ctx).RegisterScope("mobile", origin.base.String(), struct {
		Revision, Selection string
		MaxBytes            int64
		Exclude             []string
		Strings             bool
		MinRun              int
	}{"1.5.0-mobile-source-v1", origin.selection, opts.MaxBytes, opts.Exclude, opts.Strings, opts.MinRun})
	return ctx, nil
}

func mobileBoundary(ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, mobileOriginKey{}, struct{}{})
	ctx = context.WithValue(ctx, mobileEntryKey{}, 0)
	ctx = context.WithValue(ctx, filesystemOriginKey{}, struct{}{})
	ctx = context.WithValue(ctx, repositoryOriginKey{}, struct{}{})
	ctx = context.WithValue(ctx, bucketOriginKey{}, struct{}{})
	ctx = model.WithProvenance(model.WithoutProvenance(ctx), map[string]any{"source_url": "", "url": ""})
	return model.WithSourceLocator(ctx, func(path string) string { return path })
}

func (o mobileOrigin) locator(path string) string {
	u := o.base
	if strings.HasPrefix(path, o.display+"!/") {
		u.Fragment = "/" + strings.TrimPrefix(path, o.display+"!/")
	}
	return u.String()
}

func mobileMemberContext(ctx context.Context, body []byte) context.Context {
	if _, ok := ctx.Value(mobileOriginKey{}).(mobileOrigin); !ok {
		return ctx
	}
	sum := sha256.Sum256(body)
	return model.WithProvenance(ctx, map[string]any{"digest": hex.EncodeToString(sum[:])})
}

// MobileFailure preserves the failed acquisition's scope without exposing an
// operating-system or HTTP error that could contain request credentials.
func MobileFailure(ctx context.Context, name string, opts MobileOptions) <-chan model.Item {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = maxMobileEntryBytes
	}
	ch := make(chan model.Item, 1)
	local, err := mobileContext(ctx, name, false, opts)
	if err == nil {
		o := local.Value(mobileOriginKey{}).(mobileOrigin)
		model.Note(local, "mobile_acquisition_failed", o.display, true)
		emitSourceError(local, ch, o.display, errors.New("mobile acquisition failed"))
	} else {
		ctx = mobileBoundary(ctx)
		model.Note(ctx, "mobile_acquisition_failed", "<mobile>", true)
		send(ctx, ch, model.Item{Source: mobileSource, Path: "<mobile>", Error: errors.New("mobile acquisition failed")})
	}
	close(ch)
	return ch
}

func attachMobileOrigin(ctx context.Context, it *model.Item) {
	o, ok := ctx.Value(mobileOriginKey{}).(mobileOrigin)
	if !ok {
		return
	}
	it.ArtifactURI = o.locator(it.Path)
	it.IdentityPath = it.ArtifactURI + "\x00acquisition\x00" + o.selection
	it.MobileEntry, _ = ctx.Value(mobileEntryKey{}).(int)
	meta := make(map[string]any, len(it.Meta)+1)
	for k, v := range it.Meta {
		meta[k] = v
	}
	meta["source_url"] = it.ArtifactURI
	it.Meta = meta
}
