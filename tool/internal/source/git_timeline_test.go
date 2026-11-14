package source

import (
	"context"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestGitTimelineTracksAliasesAndFirstParentChanges(t *testing.T) {
	dir, run := gitRepo(t)
	// A newline would split rev-list's legacy path framing; raw -z preserves it.
	path := "odd\nname.env"
	if runtime.GOOS == "windows" {
		path = "odd-name.env"
	}
	write(t, filepath.Join(dir, path), "AWS=AKIANAFGYOEYPXU1DSYP\n")
	write(t, filepath.Join(dir, "alias.env"), "AWS=AKIANAFGYOEYPXU1DSYP\n")
	run("add", "-A")
	run("commit", "-qm", "first")
	write(t, filepath.Join(dir, path), "no credential here\n")
	run("add", "-A")
	run("commit", "-qm", "second")
	graph, objects, err := readTimelineGraph(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !graph.Complete || len(graph.Commits) != 2 || len(objects) != 3 {
		t.Fatalf("unexpected graph: commits=%d objects=%d", len(graph.Commits), len(objects))
	}
	if graph.Head != graph.Commits[1].Hash || graph.Commits[1].Parents[0] != graph.Commits[0].Hash {
		t.Fatal("head or parent linkage lost")
	}
	if graph.Commits[0].Author == "" || graph.Commits[0].AuthoredAt.IsZero() {
		t.Fatal("author provenance lost")
	}
	seen := map[string]int{}
	for item := range GitTimelineBlobs(t.Context(), dir, nil, 1024) {
		if item.Error != nil {
			t.Fatal(item.Error)
		}
		record, ok := item.Meta["git_history"].(*model.GitRecord)
		if !ok || record.Object.Path != item.Path {
			t.Fatal("blob provenance lost")
		}
		seen[item.Path]++
	}
	if seen[path] != 2 || seen["alias.env"] != 1 {
		t.Fatal("path aliases or newline path lost")
	}
	for item := range GitTimelineBlobs(t.Context(), dir, []string{"alias.env"}, 1) {
		if item.Error == nil || item.Path == "alias.env" {
			t.Fatal("oversized or excluded content emitted")
		}
	}
	// Keep file mutations confined to the disposable fixture; no worktree read is needed.
	if err := os.WriteFile(filepath.Join(dir, "alias.env"), []byte("uncommitted"), 0600); err != nil {
		t.Fatal(err)
	}
	for item := range GitTimelineBlobs(t.Context(), dir, nil, 1024) {
		if strings.Contains(item.Text, "uncommitted") {
			t.Fatal("read mutable worktree")
		}
	}
}

func TestTimelineRawDiffPreservesPathsAndSubmoduleDeletion(t *testing.T) {
	z := strings.Repeat("0", 40)
	sha := strings.Repeat("a", 40)
	raw := []byte(":000000 100644 " + z + " " + sha + " A\x00 file\n.env \x00:100644 160000 " + sha + " " + sha + " T\x00nested\x00")
	changes, err := parseTimelineChanges(raw)
	if err != nil || changes[" file\n.env "] != sha || changes["nested"] != "" {
		t.Fatal("raw diff framing or submodule handling failed")
	}
	if _, err := parseTimelineChanges([]byte("malformed\x00path\x00")); err == nil {
		t.Fatal("malformed raw diff accepted")
	}
	for _, raw := range []string{"\x00path\x00", ":000000 100644 " + z + " " + sha + " A"} {
		if _, err := parseTimelineChanges([]byte(raw)); err == nil {
			t.Fatal("empty or unterminated raw diff accepted")
		}
	}
}

func TestGitTimelineShallowAndCancellationRemainIncomplete(t *testing.T) {
	dir, run := gitRepo(t)
	for _, text := range []string{"first", "second"} {
		write(t, filepath.Join(dir, "a.env"), text)
		run("add", "-A")
		run("commit", "-qm", "fixture")
	}
	clone := filepath.Join(t.TempDir(), "shallow")
	originPath := filepath.ToSlash(dir)
	if len(originPath) > 1 && originPath[1] == ':' {
		originPath = "/" + originPath
	}
	origin := url.URL{Scheme: "file", Path: originPath}
	cmd := exec.CommandContext(t.Context(), "git", "clone", "-q", "--depth=1", origin.String(), clone)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixture clone: %v: %s", err, out)
	}
	diagnostic := false
	for item := range GitTimelineBlobs(t.Context(), clone, nil, 1024) {
		if item.Error != nil {
			diagnostic = true
		} else if item.Meta["git_history"].(*model.GitRecord).Graph.Complete {
			t.Fatal("shallow graph marked complete")
		}
	}
	if !diagnostic {
		t.Fatal("shallow history did not emit diagnostic")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := readTimelineGraph(ctx, dir); err == nil {
		t.Fatal("cancelled acquisition succeeded")
	}
}
