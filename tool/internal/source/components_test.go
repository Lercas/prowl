package source

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/credentialset"
)

func TestFilesystemCredentialScopesSeparateRootsRepositoriesAndArchives(t *testing.T) {
	root, other := t.TempDir(), t.TempDir()
	write(t, filepath.Join(root, "one.json"), `{"key":"owned"}`)
	write(t, filepath.Join(root, "two.json"), `{"secret":"owned"}`)
	write(t, filepath.Join(other, "one.json"), `{"secret":"foreign"}`)
	nested := filepath.Join(root, "nested")
	if err := os.MkdirAll(filepath.Join(nested, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(nested, "one.json"), `{"secret":"nested"}`)
	writeZIPFile(t, filepath.Join(root, "bundle.zip"), map[string][]byte{"inner.json": []byte(`{"secret":"archive"}`)})
	items := archiveItems(Filesystem(WithCredentialScopes(t.Context()), []string{root, other}, nil, 1<<20))
	seen := map[string]*credentialset.Scope{}
	for _, it := range items {
		if it.Error != nil {
			t.Fatal(it.Error)
		}
		seen[it.Path] = it.CredentialScope
	}
	a, b := seen[filepath.Join(root, "one.json")], seen[filepath.Join(root, "two.json")]
	if a == nil || a != b {
		t.Fatal("same root lost its scope")
	}
	for _, p := range []string{filepath.Join(other, "one.json"), filepath.Join(nested, "one.json")} {
		if seen[p] == nil || seen[p] == a {
			t.Fatal("foreign root/repository shares credentials")
		}
	}
	if scope, ok := seen[filepath.Join(root, "bundle.zip")+"!/inner.json"]; !ok || scope != nil {
		t.Fatal("archive member borrowed filesystem scope")
	}
	for _, it := range archiveItems(Filesystem(context.Background(), []string{root}, nil, 1<<20)) {
		if it.CredentialScope != nil {
			t.Fatal("default scan enabled cross-file roles")
		}
	}
}

func TestFilesystemCredentialScopeFollowsExplicitRootWithoutBorrowingAlias(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "one.json"), `{"key":"owned"}`)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	items := archiveItems(Filesystem(WithCredentialScopes(t.Context()), []string{root, alias}, nil, 1<<20))
	if len(items) != 2 || items[0].CredentialScope == nil || items[1].CredentialScope == nil || items[0].CredentialScope == items[1].CredentialScope {
		t.Fatal("explicit roots aliased their acquisition")
	}
}
