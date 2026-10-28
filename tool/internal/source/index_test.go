package source

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestIndexUsesStagedBytesAndNames(t *testing.T) {
	dir, git := gitRepo(t)
	names := []string{"partially-staged.txt", "секрет\nname.txt"}
	staged := "token = \x73k_live_Q5t7U9i2O4p6A8s0D3f5G7h9\n"
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(staged), 0600); err != nil {
			t.Fatal(err)
		}
	}
	git("add", "--", names[0], names[1])
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("clean working copy\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	c := model.NewCoverage()
	ctx := model.WithCoverage(context.Background(), c)
	got := map[string]bool{}
	for it := range GitIndexFiles(ctx, names, nil, 1024) {
		if it.Text != staged {
			t.Fatal("read working-tree bytes")
		}
		if it.Meta["git_index"] != true || it.Meta["blob"] == "" {
			t.Fatal("missing immutable provenance")
		}
		got[it.Path] = true
	}
	if len(got) != len(names) {
		t.Fatalf("missing index entries: %v", got)
	}
	if complete, _, ds := c.Snapshot(); !complete {
		t.Fatalf("unexpected diagnostics %v", ds)
	}
}
func TestIndexOversizeIsIncomplete(t *testing.T) {
	dir, git := gitRepo(t)
	if err := os.WriteFile(filepath.Join(dir, "large.txt"), []byte("large payload"), 0600); err != nil {
		t.Fatal(err)
	}
	git("add", "large.txt")
	t.Chdir(dir)
	c := model.NewCoverage()
	for item := range GitIndexFiles(model.WithCoverage(context.Background(), c), []string{"large.txt"}, nil, 2) {
		if item.Error == nil || item.Text != "" {
			t.Fatal("oversized content was emitted without an error")
		}
	}
	if complete, _, ds := c.Snapshot(); complete || len(ds) == 0 || ds[0].Code != "max_size" {
		t.Fatalf("silent skip: %v %v", complete, ds)
	}
}
func TestFilesystemCompleteness(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "large.txt")
	if err := os.WriteFile(p, []byte("too large"), 0600); err != nil {
		t.Fatal(err)
	}
	c := model.NewCoverage()
	for range Filesystem(model.WithCoverage(context.Background(), c), []string{p, filepath.Join(dir, "missing")}, nil, 2) {
	}
	complete, _, ds := c.Snapshot()
	if complete || len(ds) != 2 {
		t.Fatalf("silently incomplete scan %v %v", complete, ds)
	}
}
