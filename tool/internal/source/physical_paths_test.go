package source

import (
	"archive/zip"
	"bytes"
	"context"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func physicalPathFixture(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "real", "deep", "clean.txt"), "clean")
	write(t, filepath.Join(dir, "real", "out", "nested", "prod.env"), "physical credential snapshot")
	write(t, filepath.Join(dir, "out", "nested", "prod.env"), strings.Repeat("lexical neighbour ", 1000))
	write(t, filepath.Join(dir, "real", "prod.env"), "physical credential snapshot")
	write(t, filepath.Join(dir, "prod.env"), "different lexical neighbour")
	if err := os.Symlink(filepath.Join("real", "deep"), filepath.Join(dir, "alias")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	return dir, filepath.Join(dir, "alias") + string(filepath.Separator) + ".."
}

func localURIPath(t *testing.T, uri string) string {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "file" || u.RawQuery != "" || u.Fragment != "" {
		t.Fatalf("not a physical file URI: %q (%v)", uri, err)
	}
	p := u.Path
	if runtime.GOOS == "windows" {
		if u.Host != "" {
			p = "//" + u.Host + p
		} else if len(p) >= 3 && p[0] == '/' && p[2] == ':' {
			p = p[1:]
		}
	} else if u.Host != "" {
		t.Fatal("local path became a network authority")
	}
	for _, part := range strings.Split(p, "/") {
		if part == "." || part == ".." {
			t.Fatal("physical URI still contains dot segments")
		}
	}
	return filepath.FromSlash(p)
}

func TestFilesystemParentAfterSymlinkTraversesPhysicalTree(t *testing.T) {
	dir, parent := physicalPathFixture(t)
	root := parent + string(filepath.Separator) + "out"
	items := archiveItems(Filesystem(context.Background(), []string{root}, nil, 1024))
	if len(items) != 1 || items[0].Error != nil || items[0].Text != "physical credential snapshot" {
		t.Fatalf("physical nested file was skipped or metadata came from its lexical neighbour: %+v", items)
	}
	wantLabel := root + string(filepath.Separator) + filepath.Join("nested", "prod.env")
	if items[0].Path != wantLabel {
		t.Fatalf("chosen root identity was cleaned into another path: %q", items[0].Path)
	}
	actual := localURIPath(t, items[0].ArtifactURI)
	info, err := os.Stat(actual)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.Stat(filepath.Join(dir, "real", "out", "nested", "prod.env"))
	if err != nil || !os.SameFile(info, want) {
		t.Fatal("URI denotes another file")
	}
}

func TestFilesystemParentAfterSymlinkFileLocator(t *testing.T) {
	dir, parent := physicalPathFixture(t)
	root := parent + string(filepath.Separator) + "prod.env"
	items := archiveItems(Filesystem(context.Background(), []string{root}, nil, 1024))
	if len(items) != 1 || items[0].Text != "physical credential snapshot" || items[0].Path != root {
		t.Fatalf("direct-file identity/content changed: %+v", items)
	}
	data, err := os.ReadFile(localURIPath(t, items[0].ArtifactURI))
	if err != nil || string(data) != items[0].Text {
		t.Fatal("reported URI cannot recover the scanned content")
	}
	if items := archiveItems(Filesystem(context.Background(), []string{root}, []string{root}, 1024)); len(items) != 0 {
		t.Fatal("physical locator bypassed the chosen-path exclusion")
	}
	if err := os.Symlink(filepath.Join(dir, "real", "prod.env"), filepath.Join(dir, "real", "out", "in-tree.env")); err != nil {
		t.Fatal(err)
	}
	items = archiveItems(Filesystem(context.Background(), []string{parent + string(filepath.Separator) + "out"}, nil, 1024))
	if len(items) != 1 || strings.Contains(items[0].Path, "in-tree.env") {
		t.Fatal("in-tree symlink scope guard was lost")
	}
}

func TestFilesystemParentOriginSurvivesEmbeddedPayload(t *testing.T) {
	dir, parent := physicalPathFixture(t)
	var data bytes.Buffer
	w := zip.NewWriter(&data)
	f, err := w.Create("app/prod#?%20.env")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("physical embedded snapshot")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "real", "pack.zip"), data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	root := parent + string(filepath.Separator) + "pack.zip"
	items := archiveItems(Filesystem(context.Background(), []string{root}, nil, 4096))
	if len(items) != 1 || items[0].Text != "physical embedded snapshot" || items[0].Path != root+"!/app/prod#?%20.env" {
		t.Fatalf("embedded identity was lost: %+v", items)
	}
	p := localURIPath(t, items[0].ArtifactURI)
	canonical, err := filepath.EvalSymlinks(filepath.Join(dir, "real", "pack.zip"))
	if err != nil || p != canonical+filepath.FromSlash("!/app/prod#?%20.env") {
		t.Fatalf("embedded locator lost its physical container: %q", p)
	}
}

func TestListedParentFileRetainsPhysicalOrigin(t *testing.T) {
	_, parent := physicalPathFixture(t)
	root := parent + string(filepath.Separator) + "prod.env"
	items := archiveItems(FilesFromList(context.Background(), []string{root}, 1024))
	if len(items) != 1 || items[0].Error != nil || items[0].Path != root {
		t.Fatalf("listed file was lost: %+v", items)
	}
	data, err := os.ReadFile(localURIPath(t, items[0].ArtifactURI))
	if err != nil || string(data) != items[0].Text {
		t.Fatal("listed URI does not denote the acquired snapshot")
	}
}

func TestFilesystemParentErrorsAndSubsequentRoot(t *testing.T) {
	dir, parent := physicalPathFixture(t)
	root := parent + string(filepath.Separator) + "prod.env"
	plain := filepath.Join(dir, "normal.env")
	write(t, plain, "normal")
	items := archiveItems(Filesystem(context.Background(), []string{root, plain}, nil, 8))
	if len(items) != 2 || items[0].Error == nil || items[1].Error != nil || items[1].Path != plain || items[1].ArtifactURI != "" {
		t.Fatalf("origin escaped its root or the size diagnostic was lost: %+v", items)
	}
	if _, err := os.Stat(localURIPath(t, items[0].ArtifactURI)); err != nil {
		t.Fatal("incomplete marker lost its known physical origin")
	}
}
