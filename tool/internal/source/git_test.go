package source

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestGitChangedFilesStatusShapedNames(t *testing.T) {
	dir, run := gitRepo(t)
	names := []string{"C090", "R100", "a.txt", "b.txt"}
	for _, name := range names {
		write(t, filepath.Join(dir, name), "tracked content\n")
	}
	run("add", "-A")
	t.Chdir(dir)
	files, err := GitChangedFiles(context.Background(), "staged", "")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, file := range files {
		got[file] = true
	}
	for _, name := range names {
		if !got[name] {
			t.Errorf("changed file %q missing from %q", name, files)
		}
	}
}

func TestProcessBlobPreservesPathWhitespace(t *testing.T) {
	const sha = "0123456789012345678901234567890123456789"
	for _, path := range []string{" file.txt ", "\tfile.txt\t", "file.txt\r"} {
		t.Run(path, func(t *testing.T) {
			ch := make(chan model.Item, 1)
			br := bufio.NewReader(strings.NewReader(sha + " blob 5\nhello\n"))
			var requests strings.Builder
			if !processBlob(context.Background(), ch, br, &requests, sha+" "+path+"\n", nil, 1024) {
				t.Fatal("blob processing failed")
			}
			select {
			case item := <-ch:
				if item.Path != path || item.Text != "hello" {
					t.Fatalf("item = %+v, want path %q and original text", item, path)
				}
			default:
				t.Fatal("blob was not emitted")
			}
		})
	}
}

func TestGitHistoryPreservesPathWhitespace(t *testing.T) {
	dir, run := gitRepo(t)
	paths := []string{" padded.txt ", "tabbed.txt\t", "carriage.txt\r"}
	for i, path := range paths {
		write(t, filepath.Join(dir, path), strings.Repeat("content", i+1))
	}
	run("add", "-A")
	run("commit", "-qm", "path fixtures")
	got := map[string]bool{}
	for item := range GitHistoryBlobs(context.Background(), dir, nil, 1024) {
		got[item.Path] = true
	}
	for _, path := range paths {
		if !got[path] {
			t.Errorf("history lost original path %q: got %v", path, got)
		}
	}
}

// TestGitChangedFilesRejectsOptionRev: a "since" rev shaped like a git option (--output=<path>) must be
// rejected before exec and must not cause `git diff` to write to the attacker-chosen path.
func TestGitChangedFilesRejectsOptionRev(t *testing.T) {
	pwned := filepath.Join(t.TempDir(), "pwned")
	if _, err := os.Stat(pwned); err == nil {
		t.Fatalf("precondition: %s already exists", pwned)
	}
	malicious := []string{
		"--output=" + pwned,
		"--since=--output=" + pwned,
		"-O" + pwned,
		"--",
	}
	for _, rev := range malicious {
		files, err := GitChangedFiles(context.Background(), "since", rev)
		if err == nil {
			t.Errorf("GitChangedFiles(since, %q) = nil error, want rejection", rev)
		}
		if files != nil {
			t.Errorf("GitChangedFiles(since, %q) returned files %v, want none", rev, files)
		}
		if _, statErr := os.Stat(pwned); statErr == nil {
			t.Fatalf("rev %q caused file %s to be created (argument injection not blocked)", rev, pwned)
		}
	}
}

// TestGitChangedFilesSinceWorks confirms a legitimate rev still lists files changed since a real commit.
func TestGitChangedFilesSinceWorks(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "t@t.t")
	run("config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "f.txt")
	run("commit", "-qm", "one")
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("a\nb\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "f.txt")
	run("commit", "-qm", "two")

	// Resolve the parent commit, then run GitChangedFiles from within the repo dir.
	revCmd := exec.Command("git", "rev-parse", "HEAD~1")
	revCmd.Dir = dir
	revOut, err := revCmd.Output()
	if err != nil {
		t.Fatalf("rev-parse: %v", err)
	}
	rev := strings.TrimSpace(string(revOut))

	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	files, err := GitChangedFiles(context.Background(), "since", rev)
	if err != nil {
		t.Fatalf("GitChangedFiles(since, %q): unexpected err %v", rev, err)
	}
	if len(files) != 1 || files[0] != "f.txt" {
		t.Fatalf("GitChangedFiles(since, %q) = %v, want [f.txt]", rev, files)
	}
}

// TestGitChangedFilesNonASCIINames: a file with non-ASCII bytes in its name ("café.txt", a CJK+emoji
// name) must be returned as the raw filesystem path, not git's C-quoted form.
func TestGitChangedFilesNonASCIINames(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "t@t.t")
	run("config", "user.name", "t")
	// Force quoting on so the bug would reproduce regardless of the dev's global git config.
	run("config", "core.quotepath", "true")

	cafe := "café.txt" // non-ASCII (Latin-1 accent)
	cjk := "秘密🔑.txt"   // CJK + emoji, exercises multi-byte UTF-8
	for _, name := range []string{cafe, cjk} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`key = "`+"\x41"+`KIA4MNQ2RST7UVWX9YZ"`+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("add", "-A")

	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	files, err := GitChangedFiles(context.Background(), "staged", "")
	if err != nil {
		t.Fatalf("GitChangedFiles(staged): unexpected err %v", err)
	}
	got := map[string]bool{}
	for _, f := range files {
		got[f] = true
		// A C-quoted path begins and ends with a double quote; the raw path must not.
		if strings.HasPrefix(f, `"`) {
			t.Errorf("path %q is C-quoted (the -z fix is missing); os.Lstat would silently drop it", f)
		}
		// Every returned path must actually exist on disk (the whole point of the fix).
		if _, statErr := os.Stat(f); statErr != nil {
			t.Errorf("returned path %q does not stat: %v (quoted/bogus path)", f, statErr)
		}
	}
	for _, want := range []string{cafe, cjk} {
		if !got[want] {
			t.Errorf("staged file %q not returned (got %v)", want, files)
		}
	}
}

// gitRepo spins up a throwaway git repo and returns a run() helper plus the dir. Shared by the
// rename-gate tests below.
func gitRepo(t *testing.T) (dir string, run func(args ...string)) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir = t.TempDir()
	run = func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "t@t.t")
	run("config", "user.name", "t")
	return dir, run
}

// TestGitChangedFilesRenameWithSecretStaged: a secret added to a renamed file (`git mv x y && add -A`)
// must be caught by the --staged gate, returning the new path (never the old); a normal added file in
// the same staging is still returned.
func TestGitChangedFilesRenameWithSecretStaged(t *testing.T) {
	dir, run := gitRepo(t)
	// A multi-line file so git's rename detection recognizes the move as a rename, not add+delete.
	body := "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\n"
	if err := os.WriteFile(filepath.Join(dir, "old.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-qm", "one")

	// Rename + append a secret to the new path, plus add an ordinary new file alongside it.
	run("mv", "old.txt", "new.txt")
	if err := os.WriteFile(filepath.Join(dir, "new.txt"), []byte(body+`key = "`+"\x41"+`KIA4MNQ2RST7UVWX9YZ"`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "added.txt"), []byte("plain\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")

	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	files, err := GitChangedFiles(context.Background(), "staged", "")
	if err != nil {
		t.Fatalf("GitChangedFiles(staged): %v", err)
	}
	got := map[string]bool{}
	for _, f := range files {
		got[f] = true
	}
	if !got["new.txt"] {
		t.Errorf("renamed file with secret (new.txt) not returned under --staged (got %v) — the --diff-filter R fix is missing", files)
	}
	if got["old.txt"] {
		t.Errorf("old (pre-rename) path returned (got %v); the OLD path no longer exists and must not be scanned", files)
	}
	if !got["added.txt"] {
		t.Errorf("normal added file not returned (got %v) — over-correction broke the plain add case", files)
	}
}

// TestGitChangedFilesRenameWithSecretSince: same at the "since" site — a secret in a renamed file is
// caught by the --since gate (new path returned), and a normal modified file too.
func TestGitChangedFilesRenameWithSecretSince(t *testing.T) {
	dir, run := gitRepo(t)
	body := "alpha\nbeta\ngamma\ndelta\nepsilon\nzeta\neta\ntheta\niota\nkappa\n"
	if err := os.WriteFile(filepath.Join(dir, "old.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-qm", "base")

	run("mv", "old.txt", "new.txt")
	if err := os.WriteFile(filepath.Join(dir, "new.txt"), []byte(body+`tok = "`+"\x41"+`KIA4MNQ2RST7UVWX9YZ"`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("v1\nv2\n"), 0o644); err != nil { // plain modify
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-qm", "rename+secret")

	revCmd := exec.Command("git", "rev-parse", "HEAD~1")
	revCmd.Dir = dir
	revOut, err := revCmd.Output()
	if err != nil {
		t.Fatalf("rev-parse: %v", err)
	}
	rev := strings.TrimSpace(string(revOut))

	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	files, err := GitChangedFiles(context.Background(), "since", rev)
	if err != nil {
		t.Fatalf("GitChangedFiles(since): %v", err)
	}
	got := map[string]bool{}
	for _, f := range files {
		got[f] = true
	}
	if !got["new.txt"] {
		t.Errorf("renamed file with secret (new.txt) not returned under --since (got %v)", files)
	}
	if got["old.txt"] {
		t.Errorf("old (pre-rename) path returned under --since (got %v); must use the new path", files)
	}
	if !got["keep.txt"] {
		t.Errorf("normal modified file not returned under --since (got %v)", files)
	}
}

// TestGitChangedFilesPureRenameNoCrash proves a pure rename with NO content change is handled cleanly
// (the new path is returned, never the old, and nothing panics/errors).
func TestGitChangedFilesPureRenameNoCrash(t *testing.T) {
	dir, run := gitRepo(t)
	body := "one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten\n"
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-qm", "one")
	run("mv", "a.txt", "b.txt") // pure rename, identical content
	run("add", "-A")

	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	files, err := GitChangedFiles(context.Background(), "staged", "")
	if err != nil {
		t.Fatalf("GitChangedFiles(staged) on pure rename: %v", err)
	}
	for _, f := range files {
		if f == "a.txt" {
			t.Errorf("pure rename returned the OLD path a.txt (got %v); only the new path b.txt should appear", files)
		}
		if _, statErr := os.Stat(f); statErr != nil {
			t.Errorf("returned path %q does not exist on disk: %v", f, statErr)
		}
	}
	// b.txt (the new path) is the only path that exists; it should be the one returned.
	if len(files) != 1 || files[0] != "b.txt" {
		t.Errorf("pure rename = %v, want [b.txt] (new path only)", files)
	}
}

func TestCheckRev(t *testing.T) {
	bad := []string{"-x", "--output=/tmp/x", "--since=--output=/x", "-O/tmp/x", "--"}
	for _, r := range bad {
		if err := checkRev(r); err == nil {
			t.Errorf("checkRev(%q) = nil, want error", r)
		}
	}
	good := []string{"HEAD~1", "main", "abc123", "v1.2.3", "origin/main", "HEAD"}
	for _, r := range good {
		if err := checkRev(r); err != nil {
			t.Errorf("checkRev(%q) = %v, want nil", r, err)
		}
	}
}

func TestParseCatFileHeader(t *testing.T) {
	const sha = "0123456789012345678901234567890123456789"
	cases := []struct {
		name     string
		line     string
		wantType string
		wantSize int64
		wantOK   bool
	}{
		{"blob", sha + " blob 12\n", "blob", 12, true},
		{"blob no trailing newline", sha + " blob 7", "blob", 7, true},
		{"zero size ok", sha + " blob 0\n", "blob", 0, true},
		{"tree", sha + " tree 33\n", "tree", 33, true},
		{"missing object", sha + " missing\n", "", 0, false},
		{"negative size rejected", sha + " blob -1\n", "", 0, false}, // would panic make([]byte,-1)
		{"non-numeric size", sha + " blob notanum\n", "", 0, false},
		{"too few fields", sha + " blob\n", "", 0, false},
		{"too many fields", sha + " blob 12 extra\n", "", 0, false},
		{"empty", "\n", "", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			typ, size, ok := parseCatFileHeader(c.line)
			if ok != c.wantOK || typ != c.wantType || size != c.wantSize {
				t.Fatalf("parseCatFileHeader(%q) = (%q,%d,%v), want (%q,%d,%v)",
					c.line, typ, size, ok, c.wantType, c.wantSize, c.wantOK)
			}
		})
	}
}

// frame mimics one `git cat-file --batch` body frame: `size` bytes of payload + a trailing '\n'.
func frame(payload string) string { return payload + "\n" }

func TestConsumeBlobFraming(t *testing.T) {
	// Two back-to-back frames; consuming the first must leave the reader exactly at the second so
	// the --batch stream stays aligned for the next object.
	stream := frame("hello") + frame("world")
	br := bufio.NewReader(strings.NewReader(stream))

	body, err := consumeBlob(br, int64(len("hello")), 1<<20)
	if err != nil {
		t.Fatalf("consumeBlob first frame: unexpected err %v", err)
	}
	if string(body) != "hello" {
		t.Fatalf("first body = %q, want %q", body, "hello")
	}
	// Reader must now be aligned on the second frame's first byte.
	rest, _ := br.ReadString('\n')
	if rest != "world\n" {
		t.Fatalf("after first frame, next read = %q, want %q (stream desynced)", rest, "world\n")
	}
}

func TestConsumeBlobOversizeSkips(t *testing.T) {
	// An oversize blob must be fully discarded (body nil, no error) and leave the reader aligned on
	// the following frame, never buffering the big body.
	big := strings.Repeat("A", 100)
	stream := frame(big) + frame("next")
	br := bufio.NewReader(strings.NewReader(stream))

	body, err := consumeBlob(br, int64(len(big)), 10) // maxBytes=10 < 100 -> skip
	if err != nil {
		t.Fatalf("oversize consumeBlob: unexpected err %v", err)
	}
	if body != nil {
		t.Fatalf("oversize body should be nil (discarded), got %d bytes", len(body))
	}
	rest, _ := br.ReadString('\n')
	if rest != "next\n" {
		t.Fatalf("after oversize skip, next read = %q, want %q", rest, "next\n")
	}
}

func TestConsumeBlobShortReadPropagates(t *testing.T) {
	// Declared size exceeds the bytes present: io.ReadFull fails and the error must propagate
	// (unrecoverable stream), not be swallowed with a Discard(1) realign.
	br := bufio.NewReader(strings.NewReader("short")) // claim 50, only 5 available
	body, err := consumeBlob(br, 50, 1<<20)
	if err == nil {
		t.Fatalf("short read should return an error, got body=%q", body)
	}
	if body != nil {
		t.Fatalf("short read should retain no body, got %d bytes", len(body))
	}
}

func TestConsumeBlobMissingTrailingNewline(t *testing.T) {
	// Body present but the trailing '\n' git appends is missing: Discard(1) hits EOF and surfaces
	// as an error (still unrecoverable framing), so the caller stops rather than mis-frame onward.
	br := bufio.NewReader(strings.NewReader("hello")) // exactly size bytes, no trailing newline
	_, err := consumeBlob(br, int64(len("hello")), 1<<20)
	if err == nil {
		t.Fatal("missing trailing newline should surface as an error")
	}
}

func TestConsumeBlobRejectsWrongTerminator(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("helloXnext\n"))
	if _, err := consumeBlob(br, 5, 1024); err == nil {
		t.Fatal("invalid frame terminator must fail rather than desynchronize the next object")
	}
}

func TestGitHistoryCommandFailureIsIncomplete(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture requires POSIX")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\ncase \"$1\" in\nrev-list) exit 7;;\ncat-file) while IFS= read -r line; do :; done;;\nesac\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	items := archiveItems(GitHistoryBlobs(ctx, dir, nil, 1024))
	if ctx.Err() != nil || len(items) != 1 || items[0].Error == nil {
		t.Fatalf("failed history command was clean or hung: items=%+v ctx=%v", items, ctx.Err())
	}
}

func TestGitHistoryEarlyFailureReapsBlockedProducer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture requires POSIX")
	}
	dir := t.TempDir()
	const sha = "0123456789012345678901234567890123456789"
	script := "#!/bin/sh\ncase \"$1\" in\nrev-list) while :; do printf '" + sha + " file.env\\n'; done;;\ncat-file) IFS= read -r line; printf '" + sha + " missing\\n'; exit 0;;\nesac\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	items := archiveItems(GitHistoryBlobs(ctx, dir, nil, 1024))
	if ctx.Err() != nil || len(items) != 1 || items[0].Error == nil {
		t.Fatalf("history abort did not stop/reap rev-list: items=%+v ctx=%v", items, ctx.Err())
	}
}
