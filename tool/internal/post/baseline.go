// Package post holds post-processing: baseline suppression, dedup, etc.
package post

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // Required for compatibility with legacy baseline fingerprints.
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/jsonstrict"
	"github.com/Lercas/prowl/tool/internal/localfile"
	"github.com/Lercas/prowl/tool/internal/model"
)

// Baseline is a set of accepted-finding fingerprints to suppress on future runs (detect-secrets/
// gitleaks style). Fingerprint excludes the line number so it survives code shifting.
type Baseline struct{ fps map[string]bool }

// Fingerprint returns a finding's stable identity, preferring the collision-free scan-time fingerprint
// (model.Finding.Fingerprint) and falling back, when absent, to the legacy hash over the redacted form.
func Fingerprint(f model.Finding) string {
	if f.Fingerprint != "" {
		return f.Fingerprint
	}
	h := sha1.Sum([]byte(f.Type + "|" + f.Path + "|" + f.Redacted)) //nolint:gosec // Compatibility identifier, not cryptography.
	return hex.EncodeToString(h[:])
}

// LoadBaseline reads a complete, bounded fingerprint list. The caller owns optional discovery;
// a selected file must be readable and valid before any suppression is applied.
func LoadBaseline(path string) (*Baseline, error) {
	b := &Baseline{fps: map[string]bool{}}
	data, err := localfile.ReadRegular(path, maxSuppressionBytes)
	if err != nil {
		return nil, fmt.Errorf("baseline read: %w", err)
	}
	if err := jsonstrict.ValidateEncoding(data); err != nil {
		return nil, fmt.Errorf("baseline encoding: %w", err)
	}
	// Older writers encode an empty baseline as null. Keep that no-op representation readable.
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return b, nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	token, err := dec.Token()
	if err != nil || token != json.Delim('[') {
		return nil, fmt.Errorf("baseline must be a fingerprint array")
	}
	for entries := 0; dec.More(); entries++ {
		if entries >= maxSuppressionEntries {
			return nil, fmt.Errorf("baseline exceeds %d entries", maxSuppressionEntries)
		}
		var f string
		if err := dec.Decode(&f); err != nil {
			return nil, fmt.Errorf("baseline fingerprint: %w", err)
		}
		// encoding/json turns a null array element into an empty string. Neither is a fingerprint.
		if strings.TrimSpace(f) == "" {
			return nil, fmt.Errorf("baseline contains an empty fingerprint")
		}
		b.fps[f] = true
	}
	return b, nil
}

// WriteBaseline writes the deduplicated fingerprints atomically (temp file + rename in the same dir),
// so a Ctrl-C mid-write can't leave a half-written baseline.
func WriteBaseline(path string, fs []model.Finding) error {
	return WriteBaselineContext(context.Background(), path, fs)
}

// WriteBaselineContext refuses cancellation during post-processing or before atomic commit.
func WriteBaselineContext(ctx context.Context, path string, fs []model.Finding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	seen := map[string]bool{}
	var list []string
	for _, f := range fs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if model.IsIncompleteFinding(f) {
			return fmt.Errorf("cannot write a baseline from incomplete scan results")
		}
		fp := Fingerprint(f)
		if strings.TrimSpace(fp) == "" {
			return fmt.Errorf("baseline contains an empty fingerprint")
		}
		if !utf8.ValidString(fp) {
			return fmt.Errorf("baseline fingerprint must be valid UTF-8")
		}
		if !seen[fp] {
			if len(list) >= maxSuppressionEntries {
				return fmt.Errorf("baseline exceeds %d entries", maxSuppressionEntries)
			}
			seen[fp] = true
			list = append(list, fp)
		}
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("baseline marshal: %w", err)
	}
	if len(data) > maxSuppressionBytes {
		return fmt.Errorf("baseline exceeds %d bytes", maxSuppressionBytes)
	}

	if err := localfile.WriteAtomicContext(ctx, path, 0o644, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	}); err != nil {
		return fmt.Errorf("baseline write: %w", err)
	}
	return nil
}

// Suppress drops findings already accepted in the baseline.
func (b *Baseline) Suppress(fs []model.Finding) []model.Finding {
	if b == nil || len(b.fps) == 0 {
		return fs
	}
	out := fs[:0]
	for _, f := range fs {
		if model.IsIncompleteFinding(f) || !b.fps[Fingerprint(f)] {
			out = append(out, f)
		}
	}
	return out
}
