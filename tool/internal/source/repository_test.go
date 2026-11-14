package source

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/Lercas/prowl/tool/internal/model"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryLocatorPreservesResourcesWithoutAuthentication(t *testing.T) {
	for raw, want := range map[string]string{
		"https://user:private@owned.invalid/a.git?access_token=private#private": "https://owned.invalid/a.git",
		"ssh://user:private@owned.invalid/a.git?private=1":                      "ssh://owned.invalid/a.git",
		"git@owned.invalid:group/a.git":                                         "git@owned.invalid:group/a.git",
		"git@[::1]:group/a.git":                                                 "git@[::1]:group/a.git",
	} {
		if got := RepositoryLocator(raw); got != want {
			t.Errorf("locator=%q want=%q", got, want)
		}
	}
}

func TestRepositorySCPAndAbsoluteSSHRemainDistinct(t *testing.T) {
	if RepositoryLocator("git@owned.invalid:group/a.git") == RepositoryLocator("ssh://git@owned.invalid/group/a.git") {
		t.Fatal("home-relative SCP and absolute SSH resources collapsed")
	}
}

func TestRepositorySnapshotAndHistoryProvenance(t *testing.T) {
	dir, git := gitRepo(t)
	write(t, filepath.Join(dir, "prod.env"), "AWS=AKIANAFGYOEYPXU1DSYP")
	git("add", "prod.env")
	git("commit", "-qm", "owned snapshot")
	for _, history := range []bool{false, true} {
		coverage := model.NewCoverage()
		ctx, err := RepositoryContext(model.WithCoverage(context.Background(), coverage), dir, CloneOpts{URL: "https://u:private@owned.invalid/app.git?token=private", Full: history})
		if err != nil {
			t.Fatal(err)
		}
		var items []model.Item
		if history {
			items = archiveItems(GitHistoryBlobs(ctx, dir, nil, 4096))
		} else {
			items = archiveItems(Filesystem(ctx, []string{dir}, nil, 4096))
		}
		if len(items) != 1 || items[0].Meta["source_url"] != "https://owned.invalid/app.git" || strings.Contains(items[0].ArtifactURI, dir) {
			t.Fatalf("lost stable source metadata: %+v", items)
		}
		commit, _ := items[0].Meta["commit"].(string)
		if (!history && !model.ValidImmutableMetadata("commit", commit)) || (history && commit != "") {
			t.Fatal("HEAD was missing or incorrectly assigned to historical blobs")
		}
		result := model.NewResult(nil, coverage)
		if !result.Complete || len(result.Scope) != 2 {
			t.Fatalf("snapshot selection not registered: %+v", result)
		}
		data, _ := json.Marshal(result)
		if bytes.Contains(data, []byte(dir)) || bytes.Contains(data, []byte("private")) {
			t.Fatal("temporary checkout or transport authentication leaked")
		}
	}
}

func TestRepositoryHistoryScopePinsAllRefs(t *testing.T) {
	dir, git := gitRepo(t)
	write(t, filepath.Join(dir, "prod.env"), "ordinary text")
	git("add", ".")
	git("commit", "-qm", "first")
	snapshot := func() string {
		c := model.NewCoverage()
		_, err := RepositoryContext(model.WithCoverage(context.Background(), c), dir, CloneOpts{URL: "https://owned.invalid/app.git", Full: true})
		if err != nil {
			t.Fatal(err)
		}
		return model.NewResult(nil, c).Scope[0].Policy
	}
	first := snapshot()
	git("branch", "other")
	if first == snapshot() {
		t.Fatal("history scope ignored a changed ref set")
	}
}

func TestEmptyRepositoryIsAnExplicitSnapshot(t *testing.T) {
	dir, _ := gitRepo(t)
	c := model.NewCoverage()
	ctx, err := RepositoryContext(model.WithCoverage(context.Background(), c), dir, CloneOpts{URL: "https://owned.invalid/empty.git"})
	if err != nil {
		t.Fatal(err)
	}
	if items := archiveItems(Filesystem(ctx, []string{dir}, nil, 4096)); len(items) != 0 {
		t.Fatal("empty repository produced content")
	}
	if !model.NewResult(nil, c).Complete {
		t.Fatal("valid unborn empty repository became incomplete")
	}
}

func TestRepositoryDataLimitCancelsAndDoesNotRetainExcess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out bytes.Buffer
	writer := repositoryDataWriter{&out, 4, cancel}
	if _, err := writer.Write([]byte("over-limit")); err == nil || ctx.Err() == nil || out.Len() != 0 {
		t.Fatal("metadata limit was not enforced before retaining data")
	}
}

func TestRepositoryInvalidHeadStillReturnsUsableContentContext(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "prod.env"), "AWS=AKIANAFGYOEYPXU1DSYP")
	c := model.NewCoverage()
	ctx, err := RepositoryContext(model.WithCoverage(context.Background(), c), dir, CloneOpts{URL: "https://owned.invalid/unpinned.git"})
	if err == nil {
		t.Fatal("non-repository got a pinned revision")
	}
	items := archiveItems(Filesystem(ctx, []string{dir}, nil, 4096))
	if len(items) != 1 || items[0].Meta["commit"] != "" {
		t.Fatal("available content disappeared or got invented commit")
	}
	if complete, _, _ := c.Snapshot(); complete {
		t.Fatal("unpinned checkout certified complete")
	}
}
