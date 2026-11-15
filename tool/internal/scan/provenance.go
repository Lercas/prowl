package scan

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/Lercas/prowl/tool/internal/model"
)

func (p *Pipeline) annotateIdentity(ctx context.Context, f *model.Finding, raw string, it model.Item) {
	o := p.options
	if len(o.IdentityKey) >= 32 {
		mac := hmac.New(sha256.New, o.IdentityKey)
		_, _ = mac.Write([]byte(raw))
		f.SecretID = hex.EncodeToString(mac.Sum(nil))
		scope := sha256.Sum256(o.IdentityKey)
		f.IdentityScope = hex.EncodeToString(scope[:8])
		f.Fingerprint = p.reportFingerprint(f.Type, privateIdentityPath(it), raw)
		if it.IdentityPath != "" {
			sourceMAC := hmac.New(sha256.New, o.IdentityKey)
			_, _ = fmt.Fprintf(sourceMAC, "producer-source\x00%s", it.IdentityPath)
			f.SourceIdentity = hex.EncodeToString(sourceMAC.Sum(nil))
		}
	}
	for _, k := range []string{"blob", "commit", "run_id", "artifact_id", "digest", "container_digest", "layer_digest", "image_digest", "config_digest", "layer_diff_id", "source_url", "source_version", "page_id", "issue_id", "history_id", "comment_id", "source_map", "original_source", "source_transform", "git_index"} {
		if v, ok := it.Meta[k]; ok {
			value := model.SafeLocator(fmt.Sprint(v))
			if len(value) > 2048 {
				model.Note(ctx, "provenance_limit", it.Path, true)
				continue
			}
			if (k == "blob" || k == "commit" || k == "digest" || k == "container_digest" || k == "layer_digest" || k == "image_digest" || k == "config_digest" || k == "layer_diff_id") && !model.ValidImmutableMetadata(k, value) {
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
	p.annotateOccurrence(f)
}

func (p *Pipeline) reportFingerprint(typ, path, raw string) string {
	if len(p.options.IdentityKey) < 32 {
		return model.ComputeFingerprint(typ, path, raw)
	}
	mac := hmac.New(sha256.New, p.options.IdentityKey)
	_, _ = fmt.Fprintf(mac, "fingerprint\x00%s\x00%s\x00%s", typ, path, raw)
	return hex.EncodeToString(mac.Sum(nil))
}

func (p *Pipeline) annotateOccurrence(f *model.Finding) {
	model.UpdateOccurrenceIdentity(f, p.options.IdentityKey)
}
