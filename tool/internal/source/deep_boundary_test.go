package source

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestChangedFilesTreatsStatusShapedNamesAsFiles(t *testing.T) {
	dir, git := gitRepo(t)
	for _, name := range []string{"R100", "a.env", "b.env"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("AWS_KEY=\x41KIANAFGYOEYPXU1DSYP\n"), 0600); err != nil {
			t.Fatal(err)
		}
		git("add", "--", name)
	}
	t.Chdir(dir)
	files, err := GitChangedFiles(context.Background(), "staged", "")
	if err != nil || len(files) != 3 {
		t.Fatalf("legitimate staged names lost: %v, %v", files, err)
	}
}

func TestUnmergedIndexCannotProduceCleanGate(t *testing.T) {
	dir, _ := gitRepo(t)
	t.Chdir(dir)
	cmd := exec.Command("git", "hash-object", "-w", "--stdin")
	cmd.Stdin = strings.NewReader("synthetic conflict\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	sha := strings.TrimSpace(string(out))
	cmd = exec.Command("git", "update-index", "--index-info")
	cmd.Stdin = strings.NewReader("100644 " + sha + " 1\tconflict.env\n100644 " + sha + " 2\tconflict.env\n100644 " + sha + " 3\tconflict.env\n")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	files, err := GitChangedFiles(context.Background(), "staged", "")
	if err != nil || len(files) != 1 || files[0] != "conflict.env" {
		t.Fatalf("unmerged input disappeared: %v %v", files, err)
	}
	c := model.NewCoverage()
	for range GitIndexFiles(model.WithCoverage(context.Background(), c), files, nil, 1024) {
	}
	if complete, _, _ := c.Snapshot(); complete {
		t.Fatal("unmerged index certified as complete")
	}
}

func TestNestedArchiveDepthIsVisibleInCoverage(t *testing.T) {
	data := []byte("AWS_KEY=\x41KIANAFGYOEYPXU1DSYP\n")
	name := "secret.env"
	for i := 0; i < 4; i++ {
		data = makeZIP(t, map[string][]byte{name: data})
		name = "nested.zip"
	}
	c := model.NewCoverage()
	for range Payload(model.WithCoverage(context.Background(), c), name, data, 1<<20) {
	}
	if complete, _, ds := c.Snapshot(); complete {
		t.Fatalf("depth cap returned clean coverage: %v", ds)
	}
}

func TestGitFramingRequiresTrailingNewline(t *testing.T) {
	_, err := consumeBlob(bufio.NewReader(strings.NewReader("abcX")), 3, 10)
	if err == nil {
		t.Fatal("invalid frame terminator accepted")
	}
}

func TestMalformedNamedArchiveRetainsVisibleEvidence(t *testing.T) {
	c := model.NewCoverage()
	items := archiveItems(Payload(model.WithCoverage(context.Background(), c), "corrupt.zip", []byte("AWS_KEY=\x41KIANAFGYOEYPXU1DSYP\n"), 1024))
	if complete, _, _ := c.Snapshot(); complete || len(items) != 2 || items[0].Error == nil || !strings.Contains(items[1].Text, "AKIA") {
		t.Fatal("malformed archive lost coverage or visible evidence")
	}
}

func TestStagedScanFromSubdirectoryUsesLocalPaths(t *testing.T) {
	dir, git := gitRepo(t)
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "key.env"), []byte("AWS_KEY=\x41KIANAFGYOEYPXU1DSYP\n"), 0600); err != nil {
		t.Fatal(err)
	}
	git("add", "sub/key.env")
	t.Chdir(sub)
	files, err := GitChangedFiles(context.Background(), "staged", "")
	if err != nil || len(files) != 1 || files[0] != "sub/key.env" {
		t.Fatalf("subdirectory selection failed: %v %v", files, err)
	}
	c := model.NewCoverage()
	items := archiveItems(GitIndexFiles(model.WithCoverage(context.Background(), c), files, nil, 1024))
	if complete, _, _ := c.Snapshot(); !complete || len(items) != 1 {
		t.Fatal("subdirectory index scan lost its staged blob")
	}
}
