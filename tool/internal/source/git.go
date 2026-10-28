package source

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/resilience"
)

// checkRev rejects an option-shaped revision (leading "-") that `git diff` would parse as a flag —
// e.g. "--output=/tmp/pwned" would write the diff to an attacker-chosen file. Callers also place a
// "--" separator before operands (mirroring CloneRepo) as defence in depth.
func checkRev(rev string) error {
	if strings.HasPrefix(rev, "-") {
		return fmt.Errorf("invalid git revision %q: must not begin with '-'", rev)
	}
	return nil
}

// IsGitRepo reports whether dir (or the current directory, when dir is "") is inside a git work tree.
func IsGitRepo(dir string) bool {
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	if dir != "" {
		cmd.Dir = dir
	}
	return cmd.Run() == nil
}

// GitChangedFiles lists files to scan from git: mode="staged" -> staged-for-commit; mode="since" with
// rev -> files changed since rev. Paths are repository-relative regardless of cwd or diff.relative.
// Includes additions, copies, modifications, renames, type changes and unresolved conflicts; deletes
// are excluded. For a rename only the new path is selected. Unresolved staged entries fail in the
// index reader instead of being omitted from the scan.
func GitChangedFiles(ctx context.Context, mode, rev string) ([]string, error) {
	return GitChangedFilesIn(ctx, "", mode, rev)
}

// GitChangedFilesIn selects a repository explicitly without changing the process working directory.
func GitChangedFilesIn(ctx context.Context, dir, mode, rev string) ([]string, error) {
	var args []string
	switch mode {
	case "staged":
		// -z: raw NUL-terminated paths. Without it git C-quotes non-ASCII names (café.txt ->
		// "caf\303\251.txt"), which os.Lstat can't find, so the file is silently dropped from the gate.
		args = []string{"diff", "--cached", "--name-only", "--diff-filter=ACMRTU", "--no-relative", "-z"}
	case "since":
		// rev is user-controlled: reject an option-shaped rev (the real guard; "--" alone wouldn't stop
		// "--output=" since git parses options before operands), then terminate operands with "--".
		if err := checkRev(rev); err != nil {
			return nil, err
		}
		// -z, same reason as "staged": raw NUL-separated paths, not git's C-quoted form.
		args = []string{"diff", rev, "--name-only", "--diff-filter=ACMRTU", "--no-relative", "-z", "--"}
	default:
		return nil, nil
	}
	out, err := gitCmd(ctx, dir, args...).Output()
	if err != nil {
		return nil, err
	}
	// Split on NUL and keep bytes verbatim (a path may contain spaces, so do NOT TrimSpace); only drop
	// empty segments. Every field in --name-only output is a path, even names such as R100.
	fields := strings.Split(string(out), "\x00")
	var files []string
	seen := map[string]bool{}
	for _, p := range fields {
		if p == "" {
			continue
		}
		if !seen[p] {
			files = append(files, p)
			seen[p] = true
		}
	}
	return files, nil
}

// GitHistoryBlobs streams every blob ever committed (full-history scan). It pipes
// `git rev-list --objects --all` into a long-lived `git cat-file --batch`, skipping anything larger
// than maxBytes before it lands in RAM. dir selects the repository (like `git -C dir`; empty = current
// dir), so a cloned checkout can be scanned without chdir-ing the process (lets `org` parallelise).
func GitHistoryBlobs(ctx context.Context, dir string, exclude []string, maxBytes int64) <-chan model.Item {
	actual := dir
	if actual == "" {
		actual = "."
	}
	actual, _ = filepath.Abs(actual)
	model.CoverageFrom(ctx).RegisterScope("git-history", actual, struct {
		Exclude  []string
		MaxBytes int64
	}{exclude, maxBytes})
	ch := make(chan model.Item, 64)
	go func() {
		defer close(ch)
		resilience.Guard(
			func() {
				if err := streamHistoryBlobs(ctx, ch, dir, exclude, maxBytes); err != nil {
					model.Note(ctx, "git_history_incomplete", dir, true)
					send(ctx, ch, model.Item{Source: "code", Error: err})
				}
			},
			func(r any) {
				model.Note(ctx, "git_history_incomplete", dir, true)
				logx.Warn("recovered git-history panic")
				send(ctx, ch, model.Item{Source: "code", Error: fmt.Errorf("git history reader failed")})
			},
		)
	}()
	return ch
}

// gitCmd builds a git command bound to ctx, running in dir when dir != "" (else the current dir).
func gitCmd(ctx context.Context, dir string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	return cmd
}

func streamHistoryBlobs(ctx context.Context, ch chan<- model.Item, dir string, exclude []string, maxBytes int64) (err error) {
	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	revList := gitCmd(processCtx, dir, "rev-list", "--objects", "--all")
	revOut, err := revList.StdoutPipe()
	if err != nil {
		return fmt.Errorf("git rev-list pipe: %w", err)
	}
	if err := revList.Start(); err != nil {
		_ = revOut.Close()
		return fmt.Errorf("git rev-list start: %w", err)
	}
	// Reap rev-list and surface a non-zero exit (e.g. run outside a git repo): otherwise a failed scan
	// yields zero blobs and exits 0, indistinguishable from a clean repo. ctx-cancellation kills are expected.
	defer func() {
		_ = revOut.Close()
		if err != nil {
			cancel() // an early abort can leave rev-list blocked on its unread output pipe
		}
		if werr := revList.Wait(); werr != nil && err == nil {
			err = fmt.Errorf("git rev-list: %w", werr)
		}
	}()

	// Single long-lived cat-file process fed sha-per-line on stdin, emitting framed blob bodies.
	cat := gitCmd(processCtx, dir, "cat-file", "--batch")
	catIn, err := cat.StdinPipe()
	if err != nil {
		return fmt.Errorf("git cat-file stdin pipe: %w", err)
	}
	catOut, err := cat.StdoutPipe()
	if err != nil {
		_ = catIn.Close()
		return fmt.Errorf("git cat-file stdout pipe: %w", err)
	}
	if err := cat.Start(); err != nil {
		_ = catIn.Close()
		_ = catOut.Close()
		return fmt.Errorf("git cat-file start: %w", err)
	}
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("git history reader failed")
		}
		_ = catIn.Close()
		if err != nil {
			cancel()
		}
		if werr := cat.Wait(); werr != nil && err == nil {
			err = fmt.Errorf("git cat-file: %w", werr)
		}
	}()

	br := bufio.NewReader(catOut)
	// Read rev-list with bufio.Reader.ReadString (no length cap), not bufio.Scanner: a crafted
	// over-long object path would make Scanner abort the whole scan, hiding every subsequent blob.
	rr := bufio.NewReader(revOut)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A partial final line (no trailing '\n') is still valid, so process it before the error.
		line, rlErr := rr.ReadString('\n')
		if line != "" {
			// processBlob returns false on an unrecoverable error (write/read failure, stream desync,
			// ctx done) — once --batch is mis-framed we can't realign, so stop the whole scan.
			if !processBlob(ctx, ch, br, catIn, line, exclude, maxBytes) {
				return fmt.Errorf("git history object read failed")
			}
		}
		if rlErr != nil {
			if rlErr != io.EOF {
				return fmt.Errorf("git rev-list read: %w", rlErr)
			}
			return nil
		}
	}
}

// processBlob frames the one rev-list line `raw` ("<sha> <path>") against the long-lived cat-file
// --batch stream: it writes the sha, reads the header, and consumes the framed body. It returns
// false only when the stream/context is unrecoverable (caller must stop); a per-blob skip
// (non-blob, oversize) returns true so scanning continues. Missing objects abort the incomplete stream.
func processBlob(ctx context.Context, ch chan<- model.Item, br *bufio.Reader, catIn io.Writer, raw string, exclude []string, maxBytes int64) bool {
	// Remove only the framing newline: whitespace is valid filename data.
	parts := strings.SplitN(strings.TrimSuffix(raw, "\n"), " ", 2)
	if len(parts) < 2 || parts[1] == "" {
		return true // only blobs carry a path on the rev-list line; skip trees/commits/tags
	}
	sha, path := parts[0], parts[1]

	// Mirror the filesystem scan's path filtering BEFORE requesting the body (skipExt + --exclude).
	// Never writing the sha keeps the --batch stream framed, since there's no body to consume for a
	// request we never sent. Without this, `prowl scan --history --exclude X` ignored the exclude.
	if skipByExtension(ctx, path) {
		return true
	}
	for _, ex := range exclude {
		if config.PathMatch(ex, path) {
			return true
		}
	}

	if _, err := io.WriteString(catIn, sha+"\n"); err != nil {
		model.Note(ctx, "git_history_incomplete", "", true)
		logx.Warn("git cat-file write failed", "err", err)
		return false
	}
	// Header line: "<sha> <type> <size>\n", or "<sha> missing\n".
	header, err := br.ReadString('\n')
	if err != nil {
		model.Note(ctx, "git_history_incomplete", "", true)
		logx.Warn("git cat-file read header failed", "err", err)
		return false
	}
	typ, size, ok := parseCatFileHeader(header)
	if !ok {
		logx.Warn("git cat-file returned a missing or malformed object header", "blob", sha, "path", path)
		return false // completeness and framing cannot be guaranteed
	}

	// Read the declared body + trailing newline, skipping an oversize blob without buffering it. A read
	// error here means the --batch stream is desynced and can't be realigned, so propagate it as fatal.
	body, readErr := consumeBlob(br, size, maxBytes)
	if readErr != nil {
		model.Note(ctx, "git_history_incomplete", "", true)
		logx.Warn("git cat-file blob read failed (stream desync)", "blob", sha, "path", path, "err", readErr)
		return false
	}
	if typ != "blob" {
		return true
	}
	if size > maxBytes {
		model.Note(ctx, "git_history_incomplete", "", true)
		logx.Warn("skipped: git blob exceeds max-size", "blob", sha, "path", path, "size", size, "limit", maxBytes)
		return send(ctx, ch, model.Item{Source: "code", Path: path, Error: fmt.Errorf("git history blob exceeds max-size")})
	}
	return emitPayload(ctx, ch, path, body, maxBytes, exclude, map[string]any{"blob": sha})
}

// parseCatFileHeader parses a `git cat-file --batch` header line into (type, size). ok=false for a
// "missing"/malformed line, which has no framed body to consume.
func parseCatFileHeader(line string) (typ string, size int64, ok bool) {
	f := strings.Fields(strings.TrimRight(line, "\n"))
	if len(f) != 3 {
		return "", 0, false // "<sha> missing" or unexpected shape
	}
	n, err := strconv.ParseInt(f[2], 10, 64)
	if err != nil || n < 0 {
		// Reject a negative size (a corrupt object DB) before it reaches make([]byte, size) and panics.
		return "", 0, false
	}
	return f[1], n, true
}

// consumeBlob advances br past one framed body (size bytes + the trailing newline), retaining the
// bytes only when size <= maxBytes. A read error is unrecoverable — the stream sits at an arbitrary
// offset with no way to realign — so it is propagated and the caller stops the scan.
func consumeBlob(br *bufio.Reader, size, maxBytes int64) ([]byte, error) {
	var body []byte
	if size <= maxBytes {
		buf := make([]byte, size)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		body = buf
	} else if _, err := io.CopyN(io.Discard, br, size); err != nil {
		return nil, err
	}
	terminator, err := br.ReadByte()
	if err != nil {
		return body, err
	}
	if terminator != '\n' {
		return nil, fmt.Errorf("invalid git cat-file frame terminator")
	}
	return body, nil
}

// FilesFromList yields Items for an explicit file list (used with GitChangedFiles).
func FilesFromList(ctx context.Context, paths []string, maxBytes int64) <-chan model.Item {
	return FilesFromListFiltered(ctx, paths, nil, maxBytes)
}

// FilesFromListFiltered is FilesFromList with the filesystem/archive path exclusions used by staged
// and since scans. Keeping the unfiltered wrapper preserves the small source API for direct callers.
func FilesFromListFiltered(ctx context.Context, paths, exclude []string, maxBytes int64) <-chan model.Item {
	ch := make(chan model.Item, 64)
	go func() {
		defer close(ch)
		resilience.Guard(
			func() {
				for _, p := range paths {
					if !emitFile(ctx, ch, p, maxBytes, exclude) {
						return
					}
				}
			},
			func(r any) { logx.Warn("recovered file-list panic", "err", r) },
		)
	}()
	return ch
}
