package rules

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// TestWindowedEqualsWholeText runs the bundled templates over a corpus twice — line-windowed and
// whole-text — and requires identical hits. It defaults to this module's own sources and rule files;
// point PROWL_BENCH_CORPUS at any directory for a deeper check.
func TestWindowedEqualsWholeText(t *testing.T) {
	roots := []string{filepath.Join("..", "..", "rules"), ".."}
	if root := os.Getenv("PROWL_BENCH_CORPUS"); root != "" {
		roots = []string{root}
	}
	e, err := Load(filepath.Join("..", "..", "rules"))
	if err != nil {
		t.Fatal(err)
	}
	e.index.Do(e.buildIndex)
	planned := 0
	for i := 0; i < e.win.Len(); i++ {
		if e.win.Plan(i) != nil {
			planned++
		}
	}
	if planned < e.win.Len()/2 {
		t.Fatalf("only %d of %d template regexes are line-windowed", planned, e.win.Len())
	}
	defer wholeTextOnly.Store(false)
	var files, diffs, hits int
	var tw, tf time.Duration
	walk := func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if de.IsDir() {
			return nil
		}
		info, err := de.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 10<<20 {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if len(raw) != int(info.Size()) {
			t.Fatalf("corpus file changed during acquisition: %s", p)
		}
		text := string(raw)
		files++
		wholeTextOnly.Store(false)
		t0 := time.Now()
		got, gotTrunc := e.MatchN(text, MaxEngineMatches)
		tw += time.Since(t0)
		wholeTextOnly.Store(true)
		t0 = time.Now()
		want, wantTrunc := e.MatchN(text, MaxEngineMatches)
		tf += time.Since(t0)
		hits += len(want)
		if gotTrunc != wantTrunc || !reflect.DeepEqual(got, want) {
			diffs++
			if diffs <= 5 {
				t.Errorf("%s: windowed %d hits, whole-text %d", p, len(got), len(want))
				for _, h := range want {
					t.Logf("  whole:    %s [%d,%d) %q", h.RuleID, h.Start, h.End, h.Value)
				}
				for _, h := range got {
					t.Logf("  windowed: %s [%d,%d) %q", h.RuleID, h.Start, h.End, h.Value)
				}
			}
		}
		return nil
	}
	for _, root := range roots {
		if err := filepath.WalkDir(root, walk); err != nil {
			t.Fatal(err)
		}
	}
	if files == 0 {
		t.Fatal("empty corpus cannot establish equivalence")
	}
	t.Logf("files=%d hits=%d diffs=%d regexes=%d planned=%d windowed=%.1fs whole=%.1fs",
		files, hits, diffs, e.win.Len(), planned, tw.Seconds(), tf.Seconds())
}
