package source

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestCredentialTimelineSharesGraphAndLogicalPathAcrossCommitTrees(t *testing.T) {
	dir, git := gitRepo(t)
	write(t, filepath.Join(dir, "key.json"), `{"key":"unchanged"}`)
	write(t, filepath.Join(dir, "account.json"), `{"account":"first"}`)
	git("add", "--all")
	git("commit", "-qm", "first")
	write(t, filepath.Join(dir, "account.json"), `{"account":"second"}`)
	git("add", "--all")
	git("commit", "-qm", "second")
	var graph *model.GitHistoryGraph
	identities := map[string]bool{}
	count := 0
	for it := range GitCredentialTimeline(t.Context(), dir, nil, 1024) {
		record, _ := it.Meta["git_history"].(*model.GitRecord)
		if it.Error != nil || record == nil || it.CredentialScope == nil || it.TimelineIdentityPath != it.Path || !strings.Contains(it.IdentityPath, "\x00history-commit\x00") {
			t.Fatal("timeline tree lost scope, graph or identity", it.Error)
		}
		if graph != nil && graph != record.Graph {
			t.Fatal("one acquisition produced separate graphs")
		}
		graph = record.Graph
		if record.Object.Path != it.Path || record.Object.Blob != it.Meta["blob"] {
			t.Fatal("timeline object metadata changed")
		}
		if it.Path == "key.json" {
			identities[it.IdentityPath] = true
		}
		count++
	}
	if count != 4 || len(identities) != 2 || graph == nil || !graph.Complete || len(graph.Commits) != 2 {
		t.Fatal("timeline collapsed immutable commit observations")
	}
}

func TestCredentialTimelineEmptyAndShallowHistory(t *testing.T) {
	dir, git := gitRepo(t)
	if items := archiveItems(GitCredentialTimeline(t.Context(), dir, nil, 1024)); len(items) != 0 {
		t.Fatal("unborn timeline was not empty")
	}
	write(t, filepath.Join(dir, "key.json"), `{"key":"owned"}`)
	git("add", "--all")
	git("commit", "-qm", "owned")
	head, err := timelineOutput(t.Context(), dir, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "shallow"), head, 0600); err != nil {
		t.Fatal(err)
	}
	items := archiveItems(GitCredentialTimeline(t.Context(), dir, nil, 1024))
	if len(items) != 1 || items[0].Error == nil {
		t.Fatal("shallow timeline emitted usable component trees")
	}
}
