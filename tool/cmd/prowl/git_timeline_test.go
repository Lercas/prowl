package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGitTimelineCLIJoinsRevisionsBeforeDedupe(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git unavailable")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(git, args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture git: %v: %s", err, out)
		}
	}
	run("init", "-q")
	run("config", "user.name", "Timeline fixture")
	run("config", "user.email", "fixture@example.invalid")
	file := filepath.Join(dir, "prod.env")
	for _, content := range []string{"AWS=AKIANAFGYOEYPXU1DSYP\n", "# ordinary edit\nAWS=AKIANAFGYOEYPXU1DSYP\n", "# removed credential\n"} {
		if err := os.WriteFile(file, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		run("add", "prod.env")
		run("commit", "-qm", "fixture")
	}
	t.Chdir(dir)
	t.Setenv("PROWL_HOME", t.TempDir())
	output := filepath.Join(t.TempDir(), "report.json")
	if code := cmdScan([]string{"--git-timeline", "--format", "json", "-o", output, "--silence"}); code != 0 {
		t.Fatalf("timeline scan code %d", code)
	}
	truncated, fs := readBucketReport(t, output)
	if truncated || len(fs) != 1 {
		t.Fatalf("unexpected report count %d incomplete=%v", len(fs), truncated)
	}
	a := fs[0].Git
	if a == nil || !a.Complete || a.InHEAD == nil || *a.InHEAD || len(a.Appearances) != 1 || len(a.Removals) != 1 || a.Appearances[0].Author != "Timeline fixture" {
		t.Fatal("lifecycle lost through CLI/dedup/JSON")
	}
	if fs[0].Redacted == "AKIANAFGYOEYPXU1DSYP" {
		t.Fatal("timeline enabled raw disclosure")
	}
	flags, _, err := parseCommand("scan", []string{"--git-timeline", "--staged"})
	if err != nil {
		t.Fatal(err)
	}
	if code := checkSourceModes(flags, nil); code != 2 {
		t.Fatal("timeline silently accepted staged mode")
	}
}

func TestOrgGitTimelinePreservesRepositoryNamespaces(t *testing.T) {
	fakeRepoClone(t)
	t.Chdir(t.TempDir())
	orgAPI(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"clone_url":"https://owned.invalid/a.git"},{"clone_url":"https://owned.invalid/b.git"}]`)
	})
	if code := cmdOrg([]string{"github:owned", "--git-timeline", "--format", "json", "-o", "timeline.json", "--silence"}); code != 0 {
		t.Fatalf("org timeline code %d", code)
	}
	truncated, fs := readBucketReport(t, "timeline.json")
	if truncated || len(fs) != 4 {
		t.Fatal("organization timeline missing aliases")
	}
	present, absent := 0, 0
	for _, f := range fs {
		if f.Git == nil || !f.Git.Complete || f.Git.InHEAD == nil {
			t.Fatal("mapped paths lost inspection evidence")
		}
		if *f.Git.InHEAD {
			present++
		} else {
			absent++
			if len(f.Git.Removals) != 1 {
				t.Fatal("replacement removal missing")
			}
		}
	}
	if present != 2 || absent != 2 {
		t.Fatal("cross-repository lifecycle isolation failed")
	}
}
