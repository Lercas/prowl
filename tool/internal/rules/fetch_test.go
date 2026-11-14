package rules

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestUpdateDoesNotFallBackFromABrokenRequestedSubdir(t *testing.T) {
	for _, kind := range []string{"file", "broken-link"} {
		t.Run(kind, func(t *testing.T) {
			source := t.TempDir()
			writeRuleFile(t, source, "owned.yaml", minimalRule("owned"))
			path := filepath.Join(source, "rules")
			if kind == "file" {
				if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Symlink("missing", path); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			target := filepath.Join(t.TempDir(), "not-created")
			if _, err := Update(UpdateOpts{Source: source, Subdir: "rules", Target: target}); err == nil {
				t.Fatal("broken requested subdir silently selected the parent library")
			}
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatal("broken subdir installed the wrong library")
			}
		})
	}
}

func TestUpdateSubdirCannotSelectOutsideTheSource(t *testing.T) {
	parent := t.TempDir()
	source, outside := filepath.Join(parent, "source"), filepath.Join(parent, "outside")
	for _, dir := range []string{source, outside} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeRuleFile(t, outside, "owned.yaml", minimalRule("outside"))
	for _, subdir := range []string{"../outside", outside} {
		target := filepath.Join(t.TempDir(), "not-created")
		if _, err := Update(UpdateOpts{Source: source, Subdir: subdir, Target: target}); err == nil {
			t.Fatalf("outside subdir accepted: %q", subdir)
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatal("outside subdir created the target")
		}
	}
	if err := os.Symlink(outside, filepath.Join(source, "rules")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	target := filepath.Join(t.TempDir(), "not-created")
	if _, err := Update(UpdateOpts{Source: source, Subdir: "rules", Target: target}); err == nil {
		t.Fatal("source subdir alias escaped the source root")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("escaping source alias created the target")
	}
}

func fakeFetchGit(t *testing.T, script string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake shell git is POSIX-only")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte("#!/bin/sh\n"+script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestRulesFetchBoundsGitDiagnostics(t *testing.T) {
	fakeFetchGit(t, "head -c 1048576 /dev/zero\nexit 4\n")
	_, _, _, err := fetch(context.Background(), "https://owned.invalid/templates.git", "rules")
	if err == nil || !errors.Is(err, ErrSourceUnavailable) || len(err.Error()) > (64<<10)+512 || !strings.Contains(err.Error(), "[command output truncated]") {
		t.Fatalf("unbounded or missing clone diagnostics: %v", func() any {
			if err == nil {
				return nil
			}
			return len(err.Error())
		}())
	}
}

func TestRulesFetchCancellationDoesNotWaitForChildPipes(t *testing.T) {
	dir := t.TempDir()
	started, release := filepath.Join(dir, "started"), filepath.Join(dir, "release")
	t.Setenv("PROWL_FETCH_CHILD_STARTED", started)
	t.Setenv("PROWL_FETCH_CHILD_RELEASE", release)
	fakeFetchGit(t, "(printf started > \"$PROWL_FETCH_CHILD_STARTED\"; while [ ! -f \"$PROWL_FETCH_CHILD_RELEASE\" ]; do sleep 0.01; done) &\nwhile :; do sleep 1; done\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, _, err := fetch(ctx, "https://owned.invalid/templates.git", "rules")
		done <- err
	}()
	deadline := time.After(5 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		select {
		case <-deadline:
			cancel()
			_ = os.WriteFile(release, nil, 0o600)
			t.Fatal("fake git did not reach child barrier")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrSourceUnavailable) {
			t.Fatal("cancelled fetch was not classified as caller cancellation")
		}
	case <-time.After(2 * time.Second):
		// Release the owned child so the failing implementation cannot leave it behind.
		_ = os.WriteFile(release, nil, 0o600)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("fake git did not terminate after releasing its child")
		}
		t.Fatal("cancellation waited for a surviving child to close inherited pipes")
	}
}

func TestRulesFetchRefusesUnknownOrInvalidGitRevision(t *testing.T) {
	for _, value := range []string{"failure", "unknown", "", "abc1234\nforged", strings.Repeat("a", (64<<10)+1)} {
		t.Run(fmt.Sprintf("revision-%d", len(value)), func(t *testing.T) {
			source := t.TempDir()
			writeRuleFile(t, source, "owned.yaml", minimalRule("owned"))
			t.Setenv("PROWL_FETCH_LIBRARY", source)
			t.Setenv("PROWL_FETCH_REVISION", value)
			fakeFetchGit(t, "case \"$*\" in *rev-parse*) if [ \"$PROWL_FETCH_REVISION\" = failure ]; then exit 3; fi; printf '%s' \"$PROWL_FETCH_REVISION\"; exit 0;; esac\nfor dest do :; done\ncp -R \"$PROWL_FETCH_LIBRARY/.\" \"$dest\"\n")
			target := filepath.Join(t.TempDir(), "not-created")
			_, err := Update(UpdateOpts{Source: "https://owned.invalid/templates.git", Target: target})
			if err == nil || errors.Is(err, ErrSourceUnavailable) {
				t.Fatal("unreadable revision accepted or mislabeled as an unavailable source")
			}
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatal("unreadable revision created target")
			}
		})
	}
}

func TestRulesRemoteCheckKeepsItsCapturedLibraryAfterCloneCleanup(t *testing.T) {
	source := t.TempDir()
	writeRuleFile(t, source, "rules/nested/owned.yaml", minimalRule("owned"))
	t.Setenv("PROWL_FETCH_LIBRARY", source)
	fakeFetchGit(t, "case \"$*\" in *rev-parse*) printf 'abc1234\\n'; exit 0;; esac\nfor dest do :; done\ncp -R \"$PROWL_FETCH_LIBRARY/.\" \"$dest\"\n")
	res, err := Update(UpdateOpts{Source: "https://owned.invalid/templates.git", Target: filepath.Join(t.TempDir(), "not-created"), Check: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := res.Close(); err != nil {
			t.Error(err)
		}
	})
	if res.Manifest.Version != "abc1234" || res.Manifest.Count != 1 {
		t.Fatal("remote check lost revision or rules")
	}
	raw, err := os.ReadFile(filepath.Join(res.StagedDir, "nested/owned.yaml"))
	if err != nil || string(raw) != minimalRule("owned") {
		t.Fatalf("remote check returned an already removed or changed library: %v", err)
	}
}

func TestSourceSelectionSupportsStandaloneAndInRootAliases(t *testing.T) {
	source := t.TempDir()
	writeRuleFile(t, source, "owned.yaml", minimalRule("owned"))
	for _, subdir := range []string{"", "rules", "."} {
		dir, cleanup, _, err := fetch(context.Background(), source, subdir)
		cleanup()
		if err != nil || filepath.Clean(dir) != source {
			t.Fatalf("standalone source with %q: dir=%q err=%v", subdir, dir, err)
		}
	}
	writeRuleFile(t, source, "library/owned.yaml", minimalRule("owned"))
	if err := os.Symlink("library", filepath.Join(source, "rules")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	res, err := Update(UpdateOpts{Source: source, Subdir: "rules", Target: t.TempDir()})
	if err != nil || res.Manifest.Count != 1 {
		t.Fatalf("in-root source alias refused: %v", err)
	}
}
