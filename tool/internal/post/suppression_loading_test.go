package post

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestBaselineRejectsMalformedPolicy(t *testing.T) {
	for name, raw := range map[string]string{
		"empty": "", "object": `{}`, "number": `42`, "element": `[42]`,
		"empty-fingerprint": `[""]`, "null-element": `[null]`, "trailing": `["owned"] []`,
		"surrogate": `["\ud800"]`, "utf8": "[\"\xff\"]",
		"entry-budget": `[` + strings.Repeat(`"owned",`, maxSuppressionEntries) + `"owned"]`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "baseline.json")
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if b, err := LoadBaseline(path); err == nil || b != nil {
				t.Fatal("invalid baseline returned a usable suppressor")
			}
		})
	}
}

func TestEmptyBaselinesRemainReadable(t *testing.T) {
	for _, raw := range []string{"[]", "null"} {
		path := filepath.Join(t.TempDir(), "baseline.json")
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		b, err := LoadBaseline(path)
		if err != nil || len(b.fps) != 0 {
			t.Fatalf("empty legacy baseline refused: %v", err)
		}
	}
}

func TestIgnoreRejectsPartialAndMalformedPolicy(t *testing.T) {
	for name, suffix := range map[string]string{
		"long-line": strings.Repeat("x", maxIgnoreLineBytes+1),
		"malformed": "not-a-fingerprint", "no-file": ":rule:1", "no-rule": "a.env::1",
		"negative-line": "a.env:rule:-1", "utf8": "a.env:\xff:1",
		"entry-budget": strings.Repeat("a.env:rule:1\n", maxSuppressionEntries),
	} {
		t.Run(name, func(t *testing.T) {
			// A valid prefix must not survive a failed suffix as a partially usable policy.
			path := writeIgnore(t, "a.env:rule:1\n"+suffix)
			if g, err := LoadGitleaksIgnore(path); err == nil || g != nil {
				t.Fatal("invalid ignore returned a partial suppressor")
			}
		})
	}
}

func TestSuppressionLoadersBoundedRegularFiles(t *testing.T) {
	loaders := map[string]func(string) error{
		"baseline": func(p string) error { _, err := LoadBaseline(p); return err },
		"ignore":   func(p string) error { _, err := LoadGitleaksIgnore(p); return err },
	}
	for name, load := range loaders {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for _, path := range []string{dir, filepath.Join(dir, "missing")} {
				if err := load(path); err == nil {
					t.Fatal("wrong type or selected missing file accepted")
				}
			}
			path := filepath.Join(dir, "too-large")
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			truncateErr, closeErr := f.Truncate(maxSuppressionBytes+1), f.Close()
			if truncateErr != nil || closeErr != nil {
				t.Fatalf("fixture: %v %v", truncateErr, closeErr)
			}
			if err := load(path); err == nil {
				t.Fatal("oversized policy accepted")
			}
		})
	}
}

func TestBaselineWriterRefusesUnreadableSizeBeforeReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	previous := `[]`
	if err := os.WriteFile(path, []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}
	// A synthetic identity exercises the write/read size contract without retaining secret values.
	if err := WriteBaseline(path, []model.Finding{{Fingerprint: strings.Repeat("x", maxSuppressionBytes)}}); err == nil {
		t.Fatal("writer created a baseline its loader cannot read")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != previous {
		t.Fatal("failed baseline write changed previous policy")
	}
}
