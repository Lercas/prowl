package source

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/credentialset"
)

func TestWorkingTreeComponentsSelectedFilesAndNestedRepositories(t *testing.T) {
	dir, _ := gitRepo(t)
	for _, path := range []string{"key.json", "account.json", "unchanged.json", "nested/key.json", "nested/account.json"} {
		write(t, filepath.Join(dir, path), `{"account":"tenant_a"}`)
	}
	if err := os.Mkdir(filepath.Join(dir, "nested", ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	paths := []string{"key.json", "nested/key.json", "account.json", "nested/account.json"}
	seen := map[string]*credentialset.Scope{}
	for it := range GitWorktreeFilesIn(WithCredentialScopes(t.Context()), dir, paths, nil, 1024) {
		if it.Error != nil || it.CredentialScope == nil || it.Meta["git_worktree"] != true {
			t.Fatal("selected file lost its acquisition", it.Error)
		}
		seen[it.Path] = it.CredentialScope
	}
	if len(seen) != 4 || seen["key.json"] != seen["account.json"] || seen["nested/key.json"] != seen["nested/account.json"] || seen["key.json"] == seen["nested/key.json"] {
		t.Fatal("selected roots or nested repositories shared the wrong scope")
	}
	for it := range GitWorktreeFilesIn(WithCredentialScopes(t.Context()), dir, paths[:1], nil, 1024) {
		if it.CredentialScope == nil || it.CredentialScope == seen[it.Path] {
			t.Fatal("separate working-tree acquisitions reused credentials")
		}
	}
	for it := range GitWorktreeFilesIn(context.Background(), dir, paths[:1], nil, 1024) {
		if it.CredentialScope != nil || it.Meta["git_worktree"] != nil {
			t.Fatal("ordinary working-tree reader changed")
		}
	}
}

func TestWorkingTreeComponentsUseWorkingBytesAndExcludeArchivesAndAliases(t *testing.T) {
	dir, git := gitRepo(t)
	write(t, filepath.Join(dir, "key.json"), `{"account":"committed"}`)
	git("add", "--all")
	git("commit", "-qm", "owned fixture")
	write(t, filepath.Join(dir, "key.json"), `{"account":"working"}`)
	writeZIPFile(t, filepath.Join(dir, "bundle.zip"), map[string][]byte{"inner.json": []byte(`{"account":"archived"}`)})
	if err := os.Symlink("key.json", filepath.Join(dir, "alias.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(".", filepath.Join(dir, "linked-directory")); err != nil {
		t.Fatal(err)
	}
	paths := []string{"key.json", "alias.json", "bundle.zip", "linked-directory/key.json"}
	count := 0
	for it := range GitWorktreeFilesIn(WithCredentialScopes(t.Context()), dir, paths, nil, 1<<20) {
		if it.Error != nil {
			t.Fatal(it.Error)
		}
		if it.Path == "key.json" {
			if it.CredentialScope == nil || it.Text != `{"account":"working"}` {
				t.Fatal("working selection read index/HEAD content")
			}
		} else if it.CredentialScope != nil {
			t.Fatal("archive or symlink alias lent a credential")
		}
		count++
	}
	if count != 4 {
		t.Fatal("ordinary alias/archive payload was lost", count)
	}
}

func TestWorkingTreeComponentsRejectIncompleteAndInvalidSelection(t *testing.T) {
	dir, _ := gitRepo(t)
	write(t, filepath.Join(dir, "key.json"), `{"account":"working"}`)
	for _, paths := range [][]string{{"key.json", "missing.json"}, {"../outside.json"}, {".."}, {"key.json", "key.json"}, {"./key.json"}, {""}} {
		errors := 0
		for it := range GitWorktreeFilesIn(WithCredentialScopes(t.Context()), dir, paths, nil, 1024) {
			if it.Error != nil {
				errors++
			}
		}
		if errors != 1 {
			t.Fatal("invalid selection did not emit an intake error", paths, errors)
		}
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "outside")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	items := archiveItems(GitWorktreeFilesIn(WithCredentialScopes(t.Context()), dir, []string{"outside/file.json"}, nil, 1024))
	if len(items) != 1 || items[0].Error == nil {
		t.Fatal("external alias certified a working-tree acquisition")
	}
}

func TestWorkingTreeComponentsPreserveLiteralPathBytes(t *testing.T) {
	dir, _ := gitRepo(t)
	paths := []string{"space name.json", "ユニコード.json"}
	if runtime.GOOS != "windows" {
		paths = append(paths, " padded.json ", "tab\tfile.json", `literal\name.json`)
	}
	for _, path := range paths {
		write(t, filepath.Join(dir, path), `{"account":"working"}`)
	}
	items := archiveItems(GitWorktreeFilesIn(WithCredentialScopes(t.Context()), dir, paths, nil, 1024))
	if len(items) != len(paths) {
		t.Fatal("literal path selection lost files")
	}
	for i, it := range items {
		if it.Path != paths[i] || it.Error != nil || it.CredentialScope == nil {
			t.Fatal("literal path bytes changed", paths[i], it.Error)
		}
	}
}

func TestWorkingTreeComponentsRespectExclusionAndReadLimit(t *testing.T) {
	dir, _ := gitRepo(t)
	write(t, filepath.Join(dir, "key.json"), `{"account":"working"}`)
	items := archiveItems(GitWorktreeFilesIn(WithCredentialScopes(t.Context()), dir, []string{"key.json", "excluded.json"}, []string{"excluded.json"}, 1024))
	if len(items) != 1 || items[0].Error != nil {
		t.Fatal("excluded selection was read")
	}
	items = archiveItems(GitWorktreeFilesIn(WithCredentialScopes(t.Context()), dir, []string{"key.json"}, nil, 1))
	if len(items) != 1 || items[0].Error == nil {
		t.Fatal("size-limited selection certified inventory")
	}
}

func TestWorkingTreeComponentsBoundTotalItemsAndBytes(t *testing.T) {
	dir, _ := gitRepo(t)
	paths := make([]string, maxComponentRepositoryItems+1)
	for i := range paths {
		paths[i] = fmt.Sprintf("%05d.json", i)
	}
	items := archiveItems(GitWorktreeFilesIn(WithCredentialScopes(t.Context()), dir, paths, nil, 1<<20))
	if len(items) != 1 || items[0].Error == nil {
		t.Fatal("item bound did not reject selection before reading")
	}
	for _, path := range []string{"one.txt", "two.txt"} {
		write(t, filepath.Join(dir, path), strings.Repeat("x", 17<<20))
	}
	items = archiveItems(GitWorktreeFilesIn(WithCredentialScopes(t.Context()), dir, []string{"one.txt", "two.txt"}, nil, 20<<20))
	if len(items) != 2 || items[0].Error != nil || items[1].Error == nil {
		t.Fatal("aggregate raw byte bound did not stop the acquisition")
	}
}
