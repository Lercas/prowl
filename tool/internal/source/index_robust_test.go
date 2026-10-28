package source

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitIndexFilesPreservesNamesAndBytes(t *testing.T) {
	dir, git := gitRepo(t)
	names := []string{"plain.env", " spaced.env ", "new\nline.env", "-option.env", "colon:tab\t秘密.env"}
	for _, name := range names {
		write(t, filepath.Join(dir, name), "indexed content\n")
	}
	git("add", "-A")
	for _, name := range names {
		write(t, filepath.Join(dir, name), "working-tree content\n")
	}
	child := filepath.Join(dir, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(child)
	items := archiveItems(GitIndexFiles(context.Background(), names, nil, 1024))
	if len(items) != len(names) {
		t.Fatalf("items = %+v, want all indexed files", items)
	}
	found := map[string]bool{}
	for _, item := range items {
		found[item.Path] = true
		if item.Error != nil || item.Text != "indexed content\n" || item.Meta["git_index"] != true {
			t.Errorf("incorrect staged item: %+v", item)
		}
	}
	for _, name := range names {
		if !found[name] {
			t.Errorf("lost filename %q", name)
		}
	}
}

func TestGitIndexFilesReadsSymlinkText(t *testing.T) {
	dir, git := gitRepo(t)
	outside := filepath.Join(t.TempDir(), "outside.env")
	write(t, outside, "outside content must not be read\n")
	link := filepath.Join(dir, "link.env")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	git("add", "-A")
	t.Chdir(dir)
	items := archiveItems(GitIndexFiles(context.Background(), []string{"link.env"}, nil, 1024))
	if len(items) != 1 || items[0].Error != nil || items[0].Text != outside {
		t.Fatalf("staged symlink must contain its link text: %+v", items)
	}
}

func TestGitIndexFilesArchiveAndExclusions(t *testing.T) {
	dir, git := gitRepo(t)
	writeZIPFile(t, filepath.Join(dir, "bundle.zip"), map[string][]byte{
		"keep.env": []byte("indexed archive content\n"),
		"skip.env": []byte("excluded archive content\n"),
	})
	write(t, filepath.Join(dir, "skip.env"), "excluded outer content\n")
	git("add", "-A")
	write(t, filepath.Join(dir, "bundle.zip"), "different working-tree content\n")
	t.Chdir(dir)
	items := archiveItems(GitIndexFiles(context.Background(), []string{"bundle.zip", "skip.env"}, []string{"skip.env"}, 1<<20))
	if len(items) != 1 || items[0].Error != nil || items[0].Path != "bundle.zip!/keep.env" || items[0].Text != "indexed archive content\n" {
		t.Fatalf("staged archive expansion/exclusions failed: %+v", items)
	}
}

func TestGitIndexFilesReportsMissingAndOversizeEntries(t *testing.T) {
	dir, git := gitRepo(t)
	write(t, filepath.Join(dir, "large.env"), "too large for this budget\n")
	write(t, filepath.Join(dir, "keep.env"), "ok\n")
	git("add", "-A")
	t.Chdir(dir)
	items := archiveItems(GitIndexFiles(context.Background(), []string{"large.env", "keep.env", "missing.env"}, nil, 4))
	errors := map[string]bool{}
	kept := false
	for _, item := range items {
		if item.Error != nil {
			errors[item.Path] = true
		} else if item.Path == "keep.env" && item.Text == "ok\n" {
			kept = true
		}
	}
	if !errors["large.env"] || !errors["missing.env"] || !kept {
		t.Fatalf("source errors or following blob lost: items = %+v", items)
	}
}

func TestGitChangedFilesIncludesTypeChanges(t *testing.T) {
	dir, git := gitRepo(t)
	write(t, filepath.Join(dir, "changed.env"), "regular file\n")
	write(t, filepath.Join(dir, "target.env"), "target content\n")
	git("add", "-A")
	git("commit", "-qm", "base files")
	if err := os.Rename(filepath.Join(dir, "changed.env"), filepath.Join(dir, "original.env")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target.env", filepath.Join(dir, "changed.env")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	git("add", "changed.env")
	t.Chdir(dir)
	files, err := GitChangedFiles(context.Background(), "staged", "")
	if err != nil || len(files) != 1 || files[0] != "changed.env" {
		t.Fatalf("type change omitted: files=%q err=%v", files, err)
	}
}

func TestGitIndexFilesReportsUnresolvedEntries(t *testing.T) {
	dir, _ := gitRepo(t)
	hash := exec.Command("git", "hash-object", "-w", "--stdin")
	hash.Dir = dir
	hash.Stdin = strings.NewReader("conflicting content\n")
	out, err := hash.Output()
	if err != nil {
		t.Fatal(err)
	}
	sha := strings.TrimSpace(string(out))
	cmd := exec.Command("git", "update-index", "--index-info")
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader("100644 " + sha + " 1\tunmerged.env\n100644 " + sha + " 2\tunmerged.env\n100644 " + sha + " 3\tunmerged.env\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("index fixture: %v: %s", err, out)
	}
	t.Chdir(dir)
	files, err := GitChangedFiles(context.Background(), "staged", "")
	if err != nil || len(files) != 1 || files[0] != "unmerged.env" {
		t.Fatalf("unresolved path missing from selection: %q, err=%v", files, err)
	}
	items := archiveItems(GitIndexFiles(context.Background(), files, nil, 1024))
	if len(items) != 1 || items[0].Error == nil || items[0].Path != "unmerged.env" {
		t.Fatalf("unresolved index must be an error, not empty/clean: %+v", items)
	}
}
