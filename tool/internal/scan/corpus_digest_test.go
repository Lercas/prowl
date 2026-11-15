package scan

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

// A performance-only change must preserve full findings and coverage, not merely
// the number of matches. The digest discloses no corpus content or credentials.
func TestFindingsCorpusDigest(t *testing.T) {
	root := os.Getenv("PROWL_BENCH_CORPUS")
	if root == "" {
		t.Skip("set PROWL_BENCH_CORPUS for source-to-source equivalence")
	}
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := rules.Load(filepath.Join("..", "..", "rules"))
	if err != nil {
		t.Fatal(err)
	}
	pipeline := New(Options{Detector: detect.New(tax), Rules: engine})
	digest := sha256.New()
	files, findings, incomplete := 0, 0, 0
	var total int64
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 10<<20 {
			return nil
		}
		text, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if int64(len(text)) != info.Size() {
			t.Fatal("corpus changed during read")
		}
		coverage := model.NewCoverage()
		fs := pipeline.Findings(model.WithCoverage(context.Background(), coverage), model.Item{Source: "code", Path: path, Text: string(text)})
		result := model.NewResult(fs, coverage)
		raw, err := json.Marshal(result)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		// Filesystem paths and JSON cannot contain a raw NUL separator.
		_, _ = digest.Write([]byte(filepath.ToSlash(rel)))
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write(raw)
		_, _ = digest.Write([]byte{0})
		files++
		total += int64(len(text))
		findings += len(fs)
		if !result.Complete {
			incomplete++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 1000 || total < 64<<20 {
		t.Fatal("corpus is too small for equivalence qualification")
	}
	t.Logf("corpus-digest files=%d bytes=%d findings=%d incomplete=%d sha256=%x", files, total, findings, incomplete, digest.Sum(nil))
}
