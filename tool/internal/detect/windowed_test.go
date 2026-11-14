package detect

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// TestWindowedEqualsWholeText scans a corpus twice — line-windowed and whole-text — and requires
// identical matches. It defaults to this module's own sources and rule files; point
// PROWL_BENCH_CORPUS at any directory (a large checkout, a secret-rich dataset) for a deeper check.
func TestWindowedEqualsWholeText(t *testing.T) {
	roots := []string{filepath.Join("..", "..", "rules"), ".."}
	if root := os.Getenv("PROWL_BENCH_CORPUS"); root != "" {
		roots = []string{root}
	}
	d := newDetector(t)
	planned := 0
	for i := range d.types {
		if d.win.Plan(i) != nil {
			planned++
		}
	}
	if planned < len(d.types)/2 {
		t.Fatalf("only %d of %d built-in types are line-windowed", planned, len(d.types))
	}
	defer wholeTextOnly.Store(false)
	var files, diffs, matches int
	var tw, tf time.Duration
	walk := func(p string, de fs.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil || len(raw) == 0 || len(raw) > 10<<20 {
			return nil
		}
		text := string(raw)
		files++
		wholeTextOnly.Store(false)
		t0 := time.Now()
		got, gotTrunc := d.ScanCtxWithStatus(t.Context(), text)
		tw += time.Since(t0)
		wholeTextOnly.Store(true)
		t0 = time.Now()
		want, wantTrunc := d.ScanCtxWithStatus(t.Context(), text)
		tf += time.Since(t0)
		matches += len(want)
		if gotTrunc != wantTrunc || !reflect.DeepEqual(got, want) {
			diffs++
			if diffs <= 5 {
				t.Errorf("%s: windowed %d matches, whole-text %d", p, len(got), len(want))
				for _, m := range want {
					found := false
					for _, g := range got {
						found = found || g == m
					}
					if !found {
						t.Logf("  missing: %s [%d,%d) %q", m.Type, m.Start, m.End, m.Value)
					}
				}
				for _, g := range got {
					found := false
					for _, m := range want {
						found = found || g == m
					}
					if !found {
						t.Logf("  extra:   %s [%d,%d) %q", g.Type, g.Start, g.End, g.Value)
					}
				}
			}
		}
		return nil
	}
	for _, root := range roots {
		_ = filepath.WalkDir(root, walk)
	}
	t.Logf("files=%d matches=%d diffs=%d windowed=%.1fs whole=%.1fs", files, matches, diffs, tw.Seconds(), tf.Seconds())
}
