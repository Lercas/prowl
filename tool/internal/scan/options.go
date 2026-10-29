package scan

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/semantic"
)

type Options struct {
	Reconstruct    bool
	Semantic       bool
	SemanticEngine *semantic.Engine
	VerifyAll      bool
	IdentityKey    []byte
	literals       *literalDocument
}
type optionsKey struct{}

func WithOptions(ctx context.Context, o Options) context.Context {
	o.IdentityKey = append([]byte(nil), o.IdentityKey...)
	return context.WithValue(ctx, optionsKey{}, o)
}
func optionsFrom(ctx context.Context) Options { o, _ := ctx.Value(optionsKey{}).(Options); return o }
func annotateIdentity(ctx context.Context, f *model.Finding, raw string, it model.Item) {
	o := optionsFrom(ctx)
	if len(o.IdentityKey) >= 32 {
		mac := hmac.New(sha256.New, o.IdentityKey)
		_, _ = mac.Write([]byte(raw))
		f.SecretID = hex.EncodeToString(mac.Sum(nil))
		scope := sha256.Sum256(o.IdentityKey)
		f.IdentityScope = hex.EncodeToString(scope[:8])
		mac = hmac.New(sha256.New, o.IdentityKey)
		_, _ = fmt.Fprintf(mac, "fingerprint\x00%s\x00%s\x00%s", f.Type, it.Path, raw)
		f.Fingerprint = hex.EncodeToString(mac.Sum(nil))
	}
	for _, k := range []string{"blob", "commit", "run_id", "artifact_id", "digest", "layer_digest", "source_url", "source_map", "original_source", "git_index"} {
		if v, ok := it.Meta[k]; ok {
			value := model.SafeLocator(fmt.Sprint(v))
			if len(value) > 2048 {
				model.Note(ctx, "provenance_limit", it.Path, true)
				continue
			}
			if (k == "blob" || k == "commit" || k == "digest" || k == "layer_digest") && !model.ValidImmutableMetadata(k, value) {
				continue
			}
			if f.Provenance == nil {
				f.Provenance = map[string]string{}
			}
			f.Provenance[k] = value
		}
	}
	f.Path = model.SafeLocator(f.Path)
	f.URL = model.SafeLocator(f.URL)
	annotateOccurrence(ctx, f)
}

func annotateOccurrence(ctx context.Context, f *model.Finding) {
	key := optionsFrom(ctx).IdentityKey
	if f.SecretID == "" || len(key) < 32 {
		return
	}
	mac := hmac.New(sha256.New, key)
	_, _ = fmt.Fprintf(mac, "%s\x00%s\x00%s\x00%d\x00%d", f.SecretID, f.Source, f.Path, f.Line, f.Col)
	for _, k := range []string{"blob", "commit", "digest", "layer_digest", "run_id", "artifact_id"} {
		_, _ = fmt.Fprintf(mac, "\x00%s\x00%s", k, f.Provenance[k])
	}
	// A shared physical alias can expand into different logical occurrences. Its original-source
	// proof distinguishes those paths without storing any credential or synthetic document bytes.
	for _, e := range f.Evidence {
		_, _ = fmt.Fprintf(mac, "\x00evidence\x00%s\x00%d\x00%d\x00%s", e.Path, e.Start, e.End, e.Transform)
	}
	f.OccurrenceID = hex.EncodeToString(mac.Sum(nil))
}

func RefreshOccurrence(ctx context.Context, f *model.Finding) { annotateOccurrence(ctx, f) }
