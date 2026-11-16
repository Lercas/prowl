package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/credentialset"
)

func TestGitIndexCredentialAcquisitionPinsListingAndSeparatesRuns(t *testing.T) {
	dir, git := gitRepo(t)
	var paths []string
	for i := 0; i < 80; i++ {
		name := fmt.Sprintf("%03d.json", i)
		paths = append(paths, name)
		write(t, filepath.Join(dir, name), `{"account":"indexed"}`)
	}
	git("add", "--all")
	listing, err := gitCmd(t.Context(), dir, "ls-files", "--stage", "-z").Output()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(listing)
	wantSnapshot := hex.EncodeToString(digest[:])
	var first *credentialset.Scope
	count := 0
	for it := range GitIndexFilesIn(WithCredentialScopes(t.Context()), dir, paths, nil, 1024) {
		if it.Error != nil {
			t.Fatal(it.Error)
		}
		if count == 0 {
			first = it.CredentialScope
			// Editing the live index after the first emission cannot change the captured IDs.
			write(t, filepath.Join(dir, paths[79]), `{"account":"later-index"}`)
			git("add", "--", paths[79])
		}
		if first == nil || it.CredentialScope != first || it.Text != `{"account":"indexed"}` || it.Meta["git_index_snapshot"] != wantSnapshot {
			t.Fatal("mixed index listing, blob values or acquisition scopes")
		}
		count++
	}
	if count != len(paths) {
		t.Fatal("lost selected staged entries")
	}
	for it := range GitIndexFilesIn(WithCredentialScopes(t.Context()), dir, paths[79:], nil, 1024) {
		if it.Error != nil || it.Text != `{"account":"later-index"}` || it.CredentialScope == nil || it.CredentialScope == first || it.Meta["git_index_snapshot"] == wantSnapshot {
			t.Fatal("new index acquisition reused old scope or snapshot")
		}
	}
	for it := range GitIndexFilesIn(context.Background(), dir, paths[:1], nil, 1024) {
		if it.CredentialScope != nil || it.Meta["git_index_snapshot"] != nil || it.Meta["git_mode"] != nil {
			t.Fatal("default index reader retained cross-file metadata")
		}
	}
}

func TestGitIndexCredentialScopeExcludesSymlinkAndArchiveContent(t *testing.T) {
	dir, git := gitRepo(t)
	write(t, filepath.Join(dir, "a.json"), `{"key":"regular"}`)
	writeZIPFile(t, filepath.Join(dir, "bundle.zip"), map[string][]byte{"inner.json": []byte(`{"account":"archive"}`)})
	if err := os.Symlink("account=tenant_a", filepath.Join(dir, "link.env")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	git("add", "--all")
	seen := map[string]bool{}
	for it := range GitIndexFilesIn(WithCredentialScopes(t.Context()), dir, []string{"a.json", "link.env", "bundle.zip"}, nil, 1<<20) {
		if it.Error != nil {
			t.Fatal(it.Error)
		}
		seen[it.Path] = true
		if it.Path == "a.json" {
			if it.CredentialScope == nil {
				t.Fatal("regular staged file lost its scope")
			}
		} else if it.CredentialScope != nil {
			t.Fatal("non-regular or embedded content borrowed the index scope")
		}
	}
	if len(seen) != 3 || !seen["bundle.zip!/inner.json"] || !seen["link.env"] {
		t.Fatal("boundary exclusion discarded the ordinary scan payload")
	}
}
