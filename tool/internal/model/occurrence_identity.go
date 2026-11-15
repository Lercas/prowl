package model

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// UpdateOccurrenceIdentity recomputes an occurrence after producer finalization.
func UpdateOccurrenceIdentity(f *Finding, key []byte) {
	if f.SecretID == "" || len(key) < 32 {
		return
	}
	mac := hmac.New(sha256.New, key)
	_, _ = fmt.Fprintf(mac, "%s\x00%s\x00%s\x00%d\x00%d", f.SecretID, f.Source, f.Path, f.Line, f.Col)
	for _, k := range []string{"blob", "commit", "digest", "layer_digest", "run_id", "artifact_id"} {
		_, _ = fmt.Fprintf(mac, "\x00%s\x00%s", k, f.Provenance[k])
	}
	// Repeated TAR entries share visible coordinates but are distinct physical
	// observations. Keep their ordinal private while separating report IDs.
	if f.ImageEntry > 0 {
		_, _ = fmt.Fprintf(mac, "\x00image-entry\x00%d", f.ImageEntry)
	}
	if f.SourceIdentity != "" {
		_, _ = fmt.Fprintf(mac, "\x00producer-source\x00%s", f.SourceIdentity)
	}
	if digest := f.Provenance["container_digest"]; digest != "" {
		_, _ = fmt.Fprintf(mac, "\x00container-digest\x00%s", digest)
	}
	for _, k := range []string{"image_digest", "config_digest", "layer_diff_id"} {
		if v := f.Provenance[k]; v != "" {
			_, _ = fmt.Fprintf(mac, "\x00%s\x00%s", k, v)
		}
	}
	if f.MobileEntry > 0 {
		_, _ = fmt.Fprintf(mac, "\x00mobile-entry\x00%d", f.MobileEntry)
	}
	// A shared physical alias can expand into different logical occurrences. Its original-source
	// proof distinguishes those paths without storing any credential or synthetic document bytes.
	for _, e := range f.Evidence {
		_, _ = fmt.Fprintf(mac, "\x00evidence\x00%s\x00%d\x00%d\x00%s", e.Path, e.Start, e.End, e.Transform)
	}
	f.OccurrenceID = hex.EncodeToString(mac.Sum(nil))
}
