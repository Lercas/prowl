package source

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os/exec"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/Lercas/prowl/tool/internal/model"
)

// makeLayer builds an in-memory image layer from path->content files (no registry pull needed).
func makeLayer(t *testing.T, files map[string]string) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Size: int64(len(content)), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	body := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return layer
}

// TestImageLayerExcludeGlob: a `*.lock` glob exclude must skip secrets.lock while keeping app.py, and a
// skipExt extension (.png) is dropped, matching the filesystem scan.
func TestImageLayerExcludeGlob(t *testing.T) {
	layer := makeLayer(t, map[string]string{
		"app/app.py":       `KEY = "value"`,
		"app/secrets.lock": "TOKEN = leakme",
		"app/icon.png":     "binaryish-but-text",
	})

	ch := make(chan model.Item, 8)
	go func() {
		defer close(ch)
		emitLayer(context.Background(), ch, "", 0, layer, 1<<20, []string{"*.lock"}, &imageBudget{}, newFinalIndex(), "")
	}()

	got := map[string]bool{}
	for it := range ch {
		got[filepath.Base(it.Path)] = true
	}
	if !got["app.py"] {
		t.Error("app.py should be scanned")
	}
	if got["secrets.lock"] {
		t.Error("secrets.lock should be excluded by glob --exclude '*.lock' (raw strings.Contains never matched a glob)")
	}
	if got["icon.png"] {
		t.Error(".png should be skipped via skipExt (mirrors the filesystem scan)")
	}
}

// TestGitHistoryExcludeAndSkipExt: --history must honour --exclude and skipExt — a committed file
// matching the exclude glob (or a binary extension) is not yielded, while an ordinary source file is.
func TestGitHistoryExcludeAndSkipExt(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "t@t.t")
	run("config", "user.name", "t")
	write(t, filepath.Join(dir, "keep.py"), `K = "keepme"`)
	write(t, filepath.Join(dir, "deps.lock"), `LOCKED = "secret"`)
	write(t, filepath.Join(dir, "blob.jar"), `JARRED = "secret"`) // skipExt extension
	run("add", "-A")
	run("commit", "-qm", "one")

	got := drainHist(GitHistoryBlobs(context.Background(), dir, []string{"*.lock"}, 1<<20))
	if !got["keep.py"] {
		t.Error("keep.py should be scanned in history")
	}
	if got["deps.lock"] {
		t.Error("deps.lock should be excluded by --exclude '*.lock' in history scan")
	}
	if got["blob.jar"] {
		t.Error(".jar should be skipped via skipExt in history scan (mirrors working-tree scan)")
	}
}

func drainHist(ch <-chan model.Item) map[string]bool {
	out := map[string]bool{}
	for it := range ch {
		out[filepath.Base(it.Path)] = true
	}
	return out
}
