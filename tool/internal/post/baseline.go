// Package post holds post-processing: baseline suppression, dedup, etc.
package post

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Lercas/prowl/tool/internal/logx"
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
	h := sha1.Sum([]byte(f.Type + "|" + f.Path + "|" + f.Redacted))
	return hex.EncodeToString(h[:])
}

// LoadBaseline reads a fingerprint list. A read miss yields an empty (no-op) baseline; a malformed file
// is logged rather than silently treated as empty, so a corrupt --baseline doesn't suppress nothing quietly.
func LoadBaseline(path string) *Baseline {
	b := &Baseline{fps: map[string]bool{}}
	data, err := os.ReadFile(path)
	if err != nil {
		return b
	}
	var list []string
	if err := json.Unmarshal(data, &list); err != nil {
		logx.Error("baseline parse failed — suppressing nothing", "path", path, "err", err)
		return b
	}
	for _, f := range list {
		b.fps[f] = true
	}
	return b
}

// WriteBaseline writes the deduplicated fingerprints atomically (temp file + rename in the same dir),
// so a Ctrl-C mid-write can't leave a half-written baseline.
func WriteBaseline(path string, fs []model.Finding) error {
	seen := map[string]bool{}
	var list []string
	for _, f := range fs {
		fp := Fingerprint(f)
		if !seen[fp] {
			seen[fp] = true
			list = append(list, fp)
		}
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("baseline marshal: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".prowl-baseline-*.tmp")
	if err != nil {
		return fmt.Errorf("baseline temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed; cleans up on any failure path

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("baseline write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("baseline close: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("baseline chmod: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("baseline rename: %w", err)
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
		if !b.fps[Fingerprint(f)] {
			out = append(out, f)
		}
	}
	return out
}
