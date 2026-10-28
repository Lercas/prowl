package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func fakeRepoClone(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("local Git wrapper is POSIX-only")
	}
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git unavailable")
	}
	origin := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command(realGit, args...)
		cmd.Dir = origin
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture git %v: %v: %s", args, err, out)
		}
	}
	git("init", "-q")
	git("config", "user.name", "Owned fixture")
	git("config", "user.email", "fixture@example.invalid")
	for _, key := range []string{"AKIANAFGYOEYPXU1DSYP", "AKIA4ZX9QJ7K2MNPL3RS"} {
		if err := os.WriteFile(filepath.Join(origin, "prod.env"), []byte("AWS=\""+key+"\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		git("add", "prod.env")
		git("commit", "-qm", "fixture")
	}
	t.Setenv("PROWL_REAL_GIT", realGit)
	t.Setenv("PROWL_LOCAL_REPO", origin)
	dir := t.TempDir()
	script := "#!/bin/sh\nclone=no\nfor arg do\n  [ \"$arg\" = clone ] && clone=yes\n  dest=\"$arg\"\ndone\nif [ \"$clone\" = yes ]; then exec \"$PROWL_REAL_GIT\" clone --quiet --local \"$PROWL_LOCAL_REPO\" \"$dest\"; fi\nexec \"$PROWL_REAL_GIT\" \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PROWL_HOME", t.TempDir())
}

func TestRepoRelativeOutputSurvivesCheckoutCleanup(t *testing.T) {
	fakeRepoClone(t)
	t.Chdir(t.TempDir())
	if code := cmdRepo([]string{"https://owned.invalid/project.git", "--format", "json", "--output", "report.json", "--silence"}); code != 0 {
		t.Fatalf("repository scan returned %d", code)
	}
	truncated, fs := readBucketReport(t, "report.json")
	if truncated || len(fs) != 1 || fs[0].Path != "prod.env" {
		t.Fatalf("repository result changed: truncated=%v findings=%+v", truncated, fs)
	}
}

func TestRepoModesAndOperatorConfigUseExplicitCheckout(t *testing.T) {
	fakeRepoClone(t)
	t.Chdir(t.TempDir())
	for _, mode := range []string{"history", "since", "staged"} {
		args := []string{"https://owned.invalid/project.git", "--format", "json", "--output", mode + ".json", "--silence"}
		switch mode {
		case "history":
			args = append(args, "--history")
		case "since":
			args = append(args, "--since", "HEAD~1")
		case "staged":
			args = append(args, "--staged")
		}
		if code := cmdRepo(args); code != 0 {
			t.Fatalf("repository mode %s returned %d", mode, code)
		}
		truncated, fs := readBucketReport(t, mode+".json")
		count := 0
		for _, f := range fs {
			if f.Type == "aws_access_key_id" {
				count++
			}
		}
		want := map[string]int{"history": 2, "since": 1, "staged": 0}[mode]
		if truncated || count != want {
			t.Fatalf("repository mode %s: truncated=%v findings=%+v", mode, truncated, fs)
		}
	}
	if err := os.WriteFile("operator.yaml", []byte("version: 1\nallowlist:\n  paths: ['prod.env']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := cmdRepo([]string{"https://owned.invalid/project.git", "--config", "operator.yaml", "--format", "json", "--output", "config.json", "--silence"}); code != 0 {
		t.Fatalf("relative operator configuration failed: %d", code)
	}
	if truncated, fs := readBucketReport(t, "config.json"); truncated || len(fs) != 0 {
		t.Fatalf("operator configuration was ignored: %+v", fs)
	}
	if code := cmdRepo([]string{"https://owned.invalid/project.git", "--history", "--staged", "--silence"}); code != 2 {
		t.Fatal("conflicting repository source modes were accepted")
	}
}
