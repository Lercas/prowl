package scan

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

// BenchmarkFindingsCorpus measures the real per-item pipeline (cascade + bundled rule templates) over
// an on-disk tree, single-threaded. Unlike detect.BenchmarkScanClean it includes files that contain
// secret-ish keywords, so it reflects throughput on a real repository rather than the best case.
//
//	PROWL_BENCH_CORPUS=$(go env GOROOT)/src go test ./internal/scan -run '^$' \
//	    -bench FindingsCorpus -benchtime 1x -cpuprofile cpu.prof
//
// PROWL_BENCH_NORULES=1 runs the cascade alone (no rule templates).
func BenchmarkFindingsCorpus(b *testing.B) {
	root := os.Getenv("PROWL_BENCH_CORPUS")
	if root == "" {
		b.Skip("set PROWL_BENCH_CORPUS to a directory to run")
	}
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		b.Fatal(err)
	}
	det := detect.New(tax)
	var eng *rules.Engine
	if os.Getenv("PROWL_BENCH_NORULES") == "" {
		eng, err = rules.Load(filepath.Join("..", "..", "rules"))
		if err != nil {
			b.Fatal(err)
		}
	}
	var items []model.Item
	var total int64
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil || len(raw) == 0 || len(raw) > 10<<20 {
			return nil
		}
		items = append(items, model.Item{Text: string(raw), Source: "code", Path: p})
		total += int64(len(raw))
		return nil
	})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	pipeline := New(Options{Detector: det, Rules: eng})
	b.SetBytes(total)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, it := range items {
			pipeline.Findings(ctx, it)
		}
	}
}
