package rules

import (
	"crypto/sha256"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// This deeper check is opt-in because the standalone reference runs every rule
// without keyword or regex-window acceleration. It never logs matched values.
func TestWordIndexCorpusParity(t *testing.T) {
	root := os.Getenv("PROWL_BENCH_CORPUS")
	if root == "" {
		t.Skip("set PROWL_BENCH_CORPUS for full template/word-index corpus parity")
	}
	e, err := Load(filepath.Join("..", "..", "rules"))
	if err != nil {
		t.Fatal(err)
	}
	var files, hits, bytes int
	digest := sha256.New()
	encode := json.NewEncoder(digest)
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
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(raw)
		want, wantLimited := referenceWordHits(e, text, MaxEngineMatches)
		got, gotLimited := e.MatchN(text, MaxEngineMatches)
		if !reflect.DeepEqual(got, want) || gotLimited != wantLimited {
			t.Fatalf("template results differ for %s: hits=%d/%d truncated=%v/%v", path, len(got), len(want), gotLimited, wantLimited)
		}
		if err := encode.Encode(got); err != nil {
			return err
		}
		files++
		bytes += len(raw)
		hits += len(got)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("empty corpus cannot establish parity")
	}
	t.Logf("files=%d bytes=%d hits=%d digest=%x", files, bytes, hits, digest.Sum(nil))
}
