package source

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/credentialset"
	"github.com/Lercas/prowl/tool/internal/model"
)

func TestCredentialHistoryKeepsCommitTreesSeparateAndIgnoresWorkingCopy(t *testing.T) {
	dir, git := gitRepo(t)
	write(t, filepath.Join(dir, "key.json"), `{"key":"same-primary"}`)
	write(t, filepath.Join(dir, "account.json"), `{"account":"first"}`)
	git("add", "--all")
	git("commit", "-qm", "first")
	first, err := timelineOutput(t.Context(), dir, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	git("branch", "owned-first")
	write(t, filepath.Join(dir, "account.json"), `{"account":"second"}`)
	git("add", "--all")
	git("commit", "-qm", "second")
	write(t, filepath.Join(dir, "account.json"), `{"account":"uncommitted"}`)
	ctx, err := RepositoryContext(t.Context(), dir, CloneOpts{URL: "https://owned.invalid/app.git", Full: true})
	if err != nil {
		t.Fatal(err)
	}
	scopes := map[string]*credentialset.Scope{}
	counts := map[string]int{}
	for it := range GitCredentialHistory(ctx, dir, nil, 1024) {
		commit, ok := it.Meta["commit"].(string)
		if it.Error != nil || !ok || !model.ValidImmutableMetadata("commit", commit) || it.CredentialScope == nil || it.Text == `{"account":"uncommitted"}` {
			t.Fatal("history lost immutable commit metadata or scope", it.Error)
		}
		if previous := scopes[commit]; previous != nil && previous != it.CredentialScope {
			t.Fatal("one commit tree received separate scopes")
		}
		scopes[commit] = it.CredentialScope
		counts[commit]++
	}
	if len(scopes) != 2 {
		t.Fatal("unchanged primary blob lost a historical revision")
	}
	var previous *credentialset.Scope
	for commit, scope := range scopes {
		if counts[commit] != 2 || scope == previous {
			t.Fatal("distinct commit trees shared credentials")
		}
		previous = scope
	}
	// Detached HEAD remains selected even when no ref points at the second commit.
	detached, err := timelineOutput(t.Context(), dir, "commit-tree", "HEAD^{tree}", "-p", "HEAD", "-m", "detached commit")
	if err != nil {
		t.Fatal(err)
	}
	git("checkout", "--detach", "-q", strings.TrimSpace(string(detached)))
	commits, _, err := credentialHistoryCommits(t.Context(), dir)
	if err != nil || len(commits) != 3 || len(first) == 0 {
		t.Fatal("detached HEAD or referenced history lost", err)
	}
}

func TestCredentialHistoryUnbornAndShallowState(t *testing.T) {
	dir, git := gitRepo(t)
	commits, digest, err := credentialHistoryCommits(t.Context(), dir)
	if err != nil || len(commits) != 0 || len(digest) != 64 {
		t.Fatal("unborn history was not a complete empty collection", err)
	}
	write(t, filepath.Join(dir, "key.json"), `{"key":"primary"}`)
	git("add", "--all")
	git("commit", "-qm", "owned")
	head, err := timelineOutput(t.Context(), dir, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	// Mark this disposable fixture shallow without changing any shared repository.
	if err := os.WriteFile(filepath.Join(dir, ".git", "shallow"), head, 0600); err != nil {
		t.Fatal(err)
	}
	items := archiveItems(GitCredentialHistory(context.Background(), dir, nil, 1024))
	if len(items) != 1 || items[0].Error == nil {
		t.Fatal("shallow history certified complete component acquisition")
	}
}

func TestCredentialHistoryRejectsMalformedCommitListings(t *testing.T) {
	head := strings.Repeat("a", 40)
	other := strings.Repeat("b", 40)
	for _, raw := range []string{"", head, head + "\n" + head + "\n", other + "\n", head + " extra\n", head + "\n\n", strings.Repeat(head+"\n", maxTimelineCommits+1)} {
		if _, _, err := parseCredentialHistoryCommits([]byte(raw), head); err == nil {
			t.Fatal("invalid history listing accepted")
		}
	}
	var valid strings.Builder
	for i := range maxTimelineCommits {
		fmt.Fprintf(&valid, "%040x\n", i+1)
	}
	if commits, _, err := parseCredentialHistoryCommits([]byte(valid.String()), fmt.Sprintf("%040x", maxTimelineCommits)); err != nil || len(commits) != maxTimelineCommits {
		t.Fatal("valid bounded listing rejected", err)
	}
}

func TestCredentialHistoryBoundsBytesAcrossCommitTrees(t *testing.T) {
	dir, git := gitRepo(t)
	write(t, filepath.Join(dir, "large.txt"), strings.Repeat("x", 17<<20))
	git("add", "--all")
	git("commit", "-qm", "owned large first tree")
	git("commit", "--allow-empty", "-qm", "same blob in another revision")
	items := archiveItems(GitCredentialHistory(t.Context(), dir, nil, 20<<20))
	if len(items) != 2 || items[0].Error != nil || items[1].Error == nil {
		t.Fatal("history byte budget reset for each commit")
	}
}

func TestCredentialHistoryUsesLiteralObjectsWithReplaceRefs(t *testing.T) {
	dir, git := gitRepo(t)
	write(t, filepath.Join(dir, "account.json"), `{"account":"first"}`)
	git("add", "--all")
	git("commit", "-qm", "literal first")
	first, err := timelineOutput(t.Context(), dir, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "account.json"), `{"account":"second"}`)
	git("add", "--all")
	git("commit", "-qm", "literal second")
	second, err := timelineOutput(t.Context(), dir, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	git("replace", strings.TrimSpace(string(first)), strings.TrimSpace(string(second)))
	graft := filepath.Join(dir, ".git", "info", "grafts")
	if err := os.WriteFile(graft, second, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_GRAFT_FILE", graft)
	seen := map[string]string{}
	for it := range GitCredentialHistory(t.Context(), dir, nil, 1024) {
		if it.Error != nil {
			t.Fatal(it.Error)
		}
		seen[it.Meta["commit"].(string)] = it.Text
	}
	if len(seen) != 2 || seen[strings.TrimSpace(string(first))] != `{"account":"first"}` || seen[strings.TrimSpace(string(second))] != `{"account":"second"}` {
		t.Fatal("replace refs redefined a recorded immutable commit")
	}
}
