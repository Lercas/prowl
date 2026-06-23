package source

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/resilience"
)

// renameStatusToken matches a git `--name-status -z` rename/copy status field ("R100", "C074"). It is
// a defensive forward-guard: `--name-only -z` (what GitChangedFiles requests) never emits such a token.
// Anchored + score-digits so a real filename like "README" isn't misclassified as a status token.
var renameStatusToken = regexp.MustCompile(`^[RC][0-9]+$`)

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
// rev -> files changed since rev. Includes Added/Copied/Modified AND Renamed (R) entries (deletes
// excluded); renames must be included, else a secret added in `git mv x y && git add -A` slips a
// --diff-filter=ACM gate. For a rename the NEW path (the file that exists) is scanned, never the old.
func GitChangedFiles(ctx context.Context, mode, rev string) ([]string, error) {
	var args []string
	switch mode {
	case "staged":
		// -z: raw NUL-terminated paths. Without it git C-quotes non-ASCII names (café.txt ->
		// "caf\303\251.txt"), which os.Lstat can't find, so the file is silently dropped from the gate.
		args = []string{"diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"}
	case "since":
		// rev is user-controlled: reject an option-shaped rev (the real guard; "--" alone wouldn't stop
		// "--output=" since git parses options before operands), then terminate operands with "--".
		if err := checkRev(rev); err != nil {
			return nil, err
		}
		// -z, same reason as "staged": raw NUL-separated paths, not git's C-quoted form.
		args = []string{"diff", rev, "--name-only", "--diff-filter=ACMR", "-z", "--"}
	default:
		return nil, nil
	}
	out, err := exec.CommandContext(ctx, "git", args...).Output()
	if err != nil {
		return nil, err
	}
	// Split on NUL and keep bytes verbatim (a path may contain spaces, so do NOT TrimSpace); only drop
	// empty segments. `--name-only -z` already yields the new path for a rename; the rename-token branch
	// below is a forward-guard for a `--name-status`-style triple ("R<score>\0<old>\0<new>\0").
	fields := strings.Split(string(out), "\x00")
	var files []string
	for i := 0; i < len(fields); i++ {
		p := fields[i]
		if p == "" {
			continue
		}
		if renameStatusToken.MatchString(p) && i+2 < len(fields) {
			// "R<score>\0<old>\0<new>" — take the NEW path (fields[i+2]); skip the score + old path.
			if newPath := fields[i+2]; newPath != "" {
				files = append(files, newPath)
			}
			i += 2
			continue
		}
		files = append(files, p)
	}
	return files, nil
}

// GitHistoryBlobs streams every blob ever committed (full-history scan). It pipes
// `git rev-list --objects --all` into a long-lived `git cat-file --batch`, skipping anything larger
// than maxBytes before it lands in RAM. dir selects the repository (like `git -C dir`; empty = current
// dir), so a cloned checkout can be scanned without chdir-ing the process (lets `org` parallelise).
func GitHistoryBlobs(ctx context.Context, dir string, exclude []string, maxBytes int64) <-chan model.Item {
	ch := make(chan model.Item, 64)
	go func() {
		defer close(ch)
		resilience.Guard(
			func() { streamHistoryBlobs(ctx, ch, dir, exclude, maxBytes) },
			func(r any) { logx.Warn("recovered git-history panic", "err", r) },
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

func streamHistoryBlobs(ctx context.Context, ch chan<- model.Item, dir string, exclude []string, maxBytes int64) {
	revList := gitCmd(ctx, dir, "rev-list", "--objects", "--all")
	revOut, err := revList.StdoutPipe()
	if err != nil {
		logx.Warn("git rev-list pipe failed", "err", err)
		return
	}
	if err := revList.Start(); err != nil {
		logx.Warn("git rev-list start failed", "err", err)
		return
	}
	// Reap rev-list and surface a non-zero exit (e.g. run outside a git repo): otherwise a failed scan
	// yields zero blobs and exits 0, indistinguishable from a clean repo. ctx-cancellation kills are expected.
	defer func() {
		if werr := revList.Wait(); werr != nil && ctx.Err() == nil {
			logx.Warn("git rev-list failed (history scan may be incomplete)", "err", werr)
		}
	}()

	// Single long-lived cat-file process fed sha-per-line on stdin, emitting framed blob bodies.
	cat := gitCmd(ctx, dir, "cat-file", "--batch")
	catIn, err := cat.StdinPipe()
	if err != nil {
		logx.Warn("git cat-file stdin pipe failed", "err", err)
		return
	}
	catOut, err := cat.StdoutPipe()
	if err != nil {
		logx.Warn("git cat-file stdout pipe failed", "err", err)
		return
	}
	if err := cat.Start(); err != nil {
		logx.Warn("git cat-file start failed", "err", err)
		return
	}
	defer func() {
		_ = catIn.Close()
		_ = cat.Wait()
	}()

	br := bufio.NewReader(catOut)
	// Read rev-list with bufio.Reader.ReadString (no length cap), not bufio.Scanner: a crafted
	// over-long object path would make Scanner abort the whole scan, hiding every subsequent blob.
	rr := bufio.NewReader(revOut)
	for {
		if ctx.Err() != nil {
			return
		}
		// A partial final line (no trailing '\n') is still valid, so process it before the error.
		line, rlErr := rr.ReadString('\n')
		if line != "" {
			// processBlob returns false on an unrecoverable error (write/read failure, stream desync,
			// ctx done) — once --batch is mis-framed we can't realign, so stop the whole scan.
			if !processBlob(ctx, ch, br, catIn, line, exclude, maxBytes) {
				return
			}
		}
		if rlErr != nil {
			if rlErr != io.EOF {
				logx.Warn("git rev-list read error", "err", rlErr)
			}
			return
		}
	}
}

// processBlob frames the one rev-list line `raw` ("<sha> <path>") against the long-lived cat-file
// --batch stream: it writes the sha, reads the header, and consumes the framed body. It returns
// false only when the stream/context is unrecoverable (caller must stop); a per-blob skip
// (non-blob, oversize, missing object) returns true so scanning continues.
func processBlob(ctx context.Context, ch chan<- model.Item, br *bufio.Reader, catIn io.Writer, raw string, exclude []string, maxBytes int64) bool {
	parts := strings.SplitN(strings.TrimSpace(raw), " ", 2)
	if len(parts) < 2 || parts[1] == "" {
		return true // only blobs carry a path on the rev-list line; skip trees/commits/tags
	}
	sha, path := parts[0], parts[1]

	// Mirror the filesystem scan's path filtering BEFORE requesting the body (skipExt + --exclude).
	// Never writing the sha keeps the --batch stream framed, since there's no body to consume for a
	// request we never sent. Without this, `prowl scan --history --exclude X` ignored the exclude.
	if skipExt[strings.ToLower(filepath.Ext(path))] {
		return true
	}
	for _, ex := range exclude {
		if config.PathMatch(ex, path) {
			return true
		}
	}

	if _, err := io.WriteString(catIn, sha+"\n"); err != nil {
		logx.Warn("git cat-file write failed", "err", err)
		return false
	}
	// Header line: "<sha> <type> <size>\n", or "<sha> missing\n".
	header, err := br.ReadString('\n')
	if err != nil {
		logx.Warn("git cat-file read header failed", "err", err)
		return false
	}
	typ, size, ok := parseCatFileHeader(header)
	if !ok {
		return true // missing/ambiguous object: nothing framed to consume
	}

	// Read the declared body + trailing newline, skipping an oversize blob without buffering it. A read
	// error here means the --batch stream is desynced and can't be realigned, so propagate it as fatal.
	body, readErr := consumeBlob(br, size, maxBytes)
	if readErr != nil {
		logx.Warn("git cat-file blob read failed (stream desync)", "blob", sha, "path", path, "err", readErr)
		return false
	}
	if typ != "blob" {
		return true
	}
	if size > maxBytes {
		logx.Warn("skipped: git blob exceeds max-size", "blob", sha, "path", path, "size", size, "limit", maxBytes)
		return true
	}
	text, ok := scannableText(body)
	if !ok {
		logx.Debug("skipped: binary git blob", "blob", sha, "path", path)
		return true
	}
	return send(ctx, ch, model.Item{Text: string(text), Source: sourceForPath(path), Path: path,
		Meta: map[string]any{"blob": sha}})
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
	if _, err := br.Discard(1); err != nil { // trailing '\n'
		return body, err
	}
	return body, nil
}

// FilesFromList yields Items for an explicit file list (used with GitChangedFiles).
func FilesFromList(ctx context.Context, paths []string, maxBytes int64) <-chan model.Item {
	ch := make(chan model.Item, 64)
	go func() {
		defer close(ch)
		resilience.Guard(
			func() {
				for _, p := range paths {
					if !emitFile(ctx, ch, p, maxBytes) {
						return
					}
				}
			},
			func(r any) { logx.Warn("recovered file-list panic", "err", r) },
		)
	}()
	return ch
}
