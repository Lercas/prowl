package source

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/credentialset"
	"github.com/Lercas/prowl/tool/internal/model"
)

func TestRepositoryCredentialFilesKeepPinnedCommitAndAcquisition(t *testing.T) {
	dir, git := gitRepo(t)
	write(t, filepath.Join(dir, "key.json"), `{"accessKeyId":"original"}`)
	write(t, filepath.Join(dir, "account.json"), `{"account":"tenant_a"}`)
	git("add", "--all")
	git("commit", "-qm", "first revision")
	ctx, err := RepositoryContext(t.Context(), dir, CloneOpts{URL: "https://owned.invalid/app.git"})
	if err != nil {
		t.Fatal(err)
	}
	revision := ctx.Value(repositoryOriginKey{}).(repositoryOrigin).revision
	write(t, filepath.Join(dir, "account.json"), `{"account":"tenant_b"}`)
	git("add", "--all")
	git("commit", "-qm", "second revision")
	write(t, filepath.Join(dir, "account.json"), `{"account":"uncommitted"}`)
	var first *credentialset.Scope
	count := 0
	for it := range RepositoryCredentialFiles(ctx, dir, nil, 1024) {
		if it.Error != nil {
			t.Fatal(it.Error)
		}
		if first == nil {
			first = it.CredentialScope
		}
		if first == nil || it.CredentialScope != first || it.Meta["commit"] != revision || !model.ValidImmutableMetadata("blob", it.Meta["blob"].(string)) || strings.Contains(it.Text, "tenant_b") || strings.Contains(it.Text, "uncommitted") {
			t.Fatal("pinned repository snapshot changed during acquisition")
		}
		count++
	}
	if count != 2 {
		t.Fatal("lost snapshot files")
	}
	for it := range RepositoryCredentialFiles(ctx, dir, nil, 1024) {
		if it.Error != nil || it.CredentialScope == nil || it.CredentialScope == first {
			t.Fatal("separate acquisitions share component scope")
		}
	}
}

func TestRepositoryCredentialFilesRequirePinnedMetadata(t *testing.T) {
	dir, git := gitRepo(t)
	write(t, filepath.Join(dir, "a.env"), "account=tenant_a")
	git("add", "--all")
	git("commit", "-qm", "snapshot")
	for _, ctx := range []context.Context{t.Context(), func() context.Context {
		ctx, err := RepositoryContext(t.Context(), dir, CloneOpts{URL: "https://owned.invalid/app.git", Full: true})
		if err != nil {
			t.Fatal(err)
		}
		return ctx
	}()} {
		items := archiveItems(RepositoryCredentialFiles(ctx, dir, nil, 1024))
		if len(items) != 1 || items[0].Error == nil || items[0].Text != "" {
			t.Fatal("unqualified collection gained repository companions")
		}
	}
	empty, _ := gitRepo(t)
	ctx, err := RepositoryContext(t.Context(), empty, CloneOpts{URL: "https://owned.invalid/empty.git"})
	if err != nil {
		t.Fatal(err)
	}
	if items := archiveItems(RepositoryCredentialFiles(ctx, empty, nil, 1024)); len(items) != 0 {
		t.Fatal("empty pinned repository became an error")
	}
}

func TestRepositoryCredentialFilesExcludeEmbeddedAndNonregularRoles(t *testing.T) {
	dir, git := gitRepo(t)
	write(t, filepath.Join(dir, "a.env"), "account=regular")
	if err := os.Symlink("account=symlink", filepath.Join(dir, "link.env")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	writeZIPFile(t, filepath.Join(dir, "bundle.zip"), map[string][]byte{"account.env": []byte("account=archive")})
	git("add", "--all")
	git("commit", "-qm", "source boundaries")
	ctx, err := RepositoryContext(t.Context(), dir, CloneOpts{URL: "https://owned.invalid/app.git"})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for it := range RepositoryCredentialFiles(ctx, dir, nil, 1<<20) {
		if it.Error != nil {
			t.Fatal(it.Error)
		}
		seen[it.Path] = true
		if it.Path == "a.env" {
			if it.CredentialScope == nil {
				t.Fatal("regular file lost scope")
			}
		} else if it.CredentialScope != nil {
			t.Fatal("link or member borrowed repository credentials")
		}
	}
	if len(seen) != 3 || !seen["bundle.zip!/account.env"] || !seen["link.env"] {
		t.Fatal("boundary handling discarded L1 input")
	}
}

func TestRepositoryCredentialSourceBoundsBeforeCompleteInventory(t *testing.T) {
	for _, which := range []string{"items", "bytes"} {
		t.Run(which, func(t *testing.T) {
			dir, _ := gitRepo(t)
			gitData := func(input string, args ...string) string {
				t.Helper()
				cmd := gitCmd(t.Context(), dir, args...)
				cmd.Stdin = strings.NewReader(input)
				data, err := cmd.Output()
				if err != nil {
					t.Fatal(err)
				}
				return strings.TrimSpace(string(data))
			}
			payload, count := "ordinary text", maxComponentRepositoryItems+1
			if which == "bytes" {
				payload = strings.Repeat("x", maxComponentRepositoryBytes/2+1)
				count = 2
			}
			blob := gitData(payload, "hash-object", "-w", "--stdin")
			var tree strings.Builder
			for i := 0; i < count; i++ {
				fmt.Fprintf(&tree, "100644 blob %s\t%05d.txt\n", blob, i)
			}
			treeID := gitData(tree.String(), "mktree")
			commit := gitData("bounded fixture\n", "commit-tree", treeID)
			gitData("", "update-ref", "HEAD", commit)
			coverage := model.NewCoverage()
			ctx, err := RepositoryContext(model.WithCoverage(t.Context(), coverage), dir, CloneOpts{URL: "https://owned.invalid/bounded.git"})
			if err != nil {
				t.Fatal(err)
			}
			seen, failures := 0, 0
			for it := range RepositoryCredentialFiles(ctx, dir, nil, maxComponentRepositoryBytes) {
				if it.Error != nil {
					failures++
				} else {
					seen++
				}
			}
			complete, _, diagnostics := coverage.Snapshot()
			if complete || failures != 1 || seen != count-1 || len(diagnostics) != 1 || diagnostics[0].Code != "cross_file_repository_read_failed" {
				t.Fatal("bounded repository intake certified a partial inventory")
			}
		})
	}
}

func TestRepositoryCredentialFilesRejectDuplicateTreeEntries(t *testing.T) {
	dir, _ := gitRepo(t)
	gitData := func(input string, args ...string) string {
		t.Helper()
		cmd := gitCmd(t.Context(), dir, args...)
		cmd.Stdin = strings.NewReader(input)
		data, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(data))
	}
	blob := gitData("account=tenant_a\n", "hash-object", "-w", "--stdin")
	raw, err := hex.DecodeString(blob)
	if err != nil {
		t.Fatal(err)
	}
	entry := "100644 a.env\x00" + string(raw)
	tree := gitData(entry+entry, "hash-object", "-w", "--literally", "-t", "tree", "--stdin")
	commit := gitData("duplicate tree fixture\n", "commit-tree", tree)
	gitData("", "update-ref", "HEAD", commit)
	coverage := model.NewCoverage()
	ctx, err := RepositoryContext(model.WithCoverage(t.Context(), coverage), dir, CloneOpts{URL: "https://owned.invalid/duplicate.git"})
	if err != nil {
		t.Fatal(err)
	}
	failures := 0
	for it := range RepositoryCredentialFiles(ctx, dir, nil, 1024) {
		if it.Error != nil {
			failures++
		}
	}
	complete, _, _ := coverage.Snapshot()
	if failures != 1 || complete {
		t.Fatal("ambiguous physical tree paths certified a complete composite inventory")
	}
}
