package rules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ManifestName is the version/provenance file written into a rules directory by `rules update`.
const ManifestName = ".prowl-rules.json"

// cloneTimeout bounds a single `rules update` git clone so a hung/hostile `--source` can't wedge it.
const cloneTimeout = 2 * time.Minute

// maxCloneBytes caps a fetched checkout's on-disk size, refusing a disk-filling source. Backstops the
// `--filter=blob:limit` git already applies.
const maxCloneBytes = 64 << 20 // 64 MiB

// Manifest records what rule set is installed and where it came from.
type Manifest struct {
	Source    string            `json:"source"`
	Version   string            `json:"version"`
	UpdatedAt string            `json:"updated_at"`
	Count     int               `json:"count"`
	Files     map[string]string `json:"files"` // relpath -> sha256
}

// ReadManifest loads the manifest from a rules directory (zero value if absent).
func ReadManifest(dir string) Manifest {
	var m Manifest
	if raw, err := os.ReadFile(filepath.Join(dir, ManifestName)); err == nil {
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

// UpdateOpts configures an update. When Check is true nothing is written — only the diff is reported.
type UpdateOpts struct {
	Source   string // local directory or git URL
	Target   string // where to install (default: the source if local, else required)
	Now      string // caller-supplied timestamp
	Check    bool
	Subdir   string                 // subdir inside a cloned/checked-out source to install (e.g. "rules", "verifiers")
	Validate func(dir string) error // nil -> default rule-template validation
	// Ctx bounds and cancels a remote (git) fetch; nil means context.Background().
	Ctx context.Context
}

// UpdateResult summarizes an update for the CLI.
type UpdateResult struct {
	Manifest  Manifest
	Added     []string
	Changed   []string
	Removed   []string
	Errors    []Issue
	StagedDir string // populated on --check (a temp dir holding the fetched set)
	NoChange  bool
}

// Update fetches the rule set from Source, validates it (refusing a set with errors), diffs it
// against Target, and — unless Check — syncs Target and writes the manifest.
func Update(o UpdateOpts) (*UpdateResult, error) {
	ctx := o.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	staged, cleanup, version, err := fetch(ctx, o.Source, o.Subdir)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	if v := readVersionFile(staged); v != "" {
		version = v
	}

	validate := o.Validate
	if validate == nil {
		validate = ValidateForUpdate
	}
	if err := validate(staged); err != nil {
		return &UpdateResult{}, fmt.Errorf("refusing to update: %w", err)
	}

	newFiles, err := hashTree(staged)
	if err != nil {
		return nil, err
	}
	old := ReadManifest(o.Target).Files
	res := &UpdateResult{}
	for rel, sum := range newFiles {
		switch {
		case old[rel] == "":
			res.Added = append(res.Added, rel)
		case old[rel] != sum:
			res.Changed = append(res.Changed, rel)
		}
	}
	for rel := range old {
		if newFiles[rel] == "" {
			res.Removed = append(res.Removed, rel)
		}
	}
	sort.Strings(res.Added)
	sort.Strings(res.Changed)
	sort.Strings(res.Removed)
	res.NoChange = len(res.Added)+len(res.Changed)+len(res.Removed) == 0

	res.Manifest = Manifest{
		Source: o.Source, Version: version, UpdatedAt: o.Now,
		Count: len(newFiles), Files: newFiles,
	}
	if o.Check {
		res.StagedDir = staged
		return res, nil
	}
	if err := syncDir(staged, o.Target); err != nil {
		return nil, err
	}
	raw, _ := json.MarshalIndent(res.Manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(o.Target, ManifestName), raw, 0o644); err != nil {
		return nil, err
	}
	return res, nil
}

// fetch resolves src to a local directory of templates, returning a cleanup func and a version
// (git short-sha for repos, "local" for directories). A remote fetch is bounded by ctx, a clone
// timeout, and a size cap so a hung or disk-filling `--source` can't wedge the command.
func fetch(ctx context.Context, src, subdir string) (dir string, cleanup func(), version string, err error) {
	noop := func() {}
	if src == "" {
		return "", noop, "", fmt.Errorf("no --source given (local dir or git URL)")
	}
	if info, statErr := os.Stat(src); statErr == nil && info.IsDir() {
		if subdir != "" { // a templates checkout: install its rules/ or verifiers/ subdir
			if sub := filepath.Join(src, subdir); dirExists(sub) {
				return sub, noop, "local", nil
			}
		}
		return src, noop, "local", nil
	}
	if isGitURL(src) {
		tmp, err := os.MkdirTemp("", "prowl-rules-*")
		if err != nil {
			return "", noop, "", err
		}
		cleanup = func() { os.RemoveAll(tmp) }
		// CommandContext ties git's lifetime to ctx; the per-attempt timeout kills a hung connection
		// even when the parent ctx has no deadline.
		cctx, cancel := context.WithTimeout(ctx, cloneTimeout)
		defer cancel()
		// "--" stops src parsing as a flag; protocol.*.allow=never disables the ext/file transport
		// helpers that turn a clone URL into command execution; --filter=blob:limit caps blob size
		// server-side (the post-clone size check below backstops servers that ignore it).
		cmd := exec.CommandContext(cctx, "git",
			"-c", "protocol.ext.allow=never", "-c", "protocol.file.allow=user",
			"clone", "--depth", "1", "--filter=blob:limit=10m", "--", src, tmp)
		if out, err := cmd.CombinedOutput(); err != nil {
			cleanup()
			if ctx.Err() != nil { // parent cancelled (Ctrl-C / overall --timeout)
				return "", noop, "", fmt.Errorf("git clone cancelled: %w", ctx.Err())
			}
			if cctx.Err() == context.DeadlineExceeded {
				return "", noop, "", fmt.Errorf("git clone timed out after %s", cloneTimeout)
			}
			return "", noop, "", fmt.Errorf("git clone: %v: %s", err, out)
		}
		// Backstop the disk-fill guard: a server can ignore --filter and stream many small files.
		// Reject a checkout over the size cap before reading/syncing any of it.
		if n, serr := dirSize(tmp, maxCloneBytes); serr != nil {
			cleanup()
			return "", noop, "", serr
		} else if n > maxCloneBytes {
			cleanup()
			return "", noop, "", fmt.Errorf("refusing rule source: clone exceeds %d bytes (got >%d) — looks hostile/oversized", maxCloneBytes, n)
		}
		ver := "unknown"
		if b, err := exec.CommandContext(cctx, "git", "-C", tmp, "rev-parse", "--short", "HEAD").Output(); err == nil {
			ver = strings.TrimSpace(string(b))
		}
		if subdir == "" {
			subdir = "rules"
		}
		if sub := filepath.Join(tmp, subdir); dirExists(sub) { // install the requested subdir
			return sub, cleanup, ver, nil
		}
		return tmp, cleanup, ver, nil
	}
	return "", noop, "", fmt.Errorf("unsupported source %q (use a local directory or a git URL)", src)
}

// dirSize sums the size of every regular file under dir, stopping early once the total exceeds limit
// (so a huge tree is rejected without a full walk). Symlinks are not followed. The result is exact
// when <= limit and a lower bound (> limit) when the cap trips.
func dirSize(dir string, limit int64) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		total += info.Size()
		if total > limit {
			return filepath.SkipAll // over budget — stop walking, the caller will refuse the set
		}
		return nil
	})
	return total, err
}

func readVersionFile(dir string) string {
	if b, err := os.ReadFile(filepath.Join(dir, "VERSION")); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}

// isGitURL accepts only explicit, encrypted transports (https://, ssh://, scp-like git@host:path),
// rejecting cleartext (http://, git://) and the ext:: remote helper that would run arbitrary commands.
// For ssh forms the host must not begin with '-' (option-injection, CVE-2017-1000117 class).
func isGitURL(s string) bool {
	for _, p := range []string{"https://", "ssh://"} {
		if strings.HasPrefix(s, p) {
			if p == "ssh://" && sshHostLeadingDash(strings.TrimPrefix(s, p)) {
				return false
			}
			return true
		}
	}
	if strings.HasPrefix(s, "git@") && strings.Contains(s, ":") { // scp-like git@host:path
		// git@host:path -> host is between '@' and the first ':'. Reject a leading-dash host.
		hostPart := s[len("git@"):]
		host, _, _ := strings.Cut(hostPart, ":")
		return !strings.HasPrefix(host, "-")
	}
	return false
}

// sshHostLeadingDash reports whether the host of an ssh:// authority ("[user@]host[:port]/path")
// begins with '-', which older git could pass to ssh as an option. Userinfo, port, and path are
// stripped first.
func sshHostLeadingDash(authority string) bool {
	// Drop the path: host[:port] is everything before the first '/'.
	hostport, _, _ := strings.Cut(authority, "/")
	// Drop userinfo: host[:port] is everything after the last '@'.
	if at := strings.LastIndex(hostport, "@"); at >= 0 {
		hostport = hostport[at+1:]
	}
	// Drop an optional :port (host has no other ':'; IPv6 literals are bracketed).
	host := hostport
	if !strings.HasPrefix(host, "[") {
		host, _, _ = strings.Cut(host, ":")
	}
	host = strings.TrimPrefix(host, "[")
	return strings.HasPrefix(host, "-")
}

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

// hashTree returns relpath->sha256 for every .yaml/.yml under dir (excluding the manifest).
func hashTree(dir string) (map[string]string, error) {
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if ext := strings.ToLower(filepath.Ext(path)); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		sum := sha256.Sum256(raw)
		out[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	})
	return out, err
}

// managedFile reports whether path is a file syncDir may copy or delete: the rule templates
// (.yaml/.yml) plus SCHEMA.md. The manifest is never managed here — Update owns it separately.
func managedFile(path string) bool {
	if filepath.Base(path) == ManifestName {
		return false
	}
	if ext := strings.ToLower(filepath.Ext(path)); ext == ".yaml" || ext == ".yml" {
		return true
	}
	return filepath.Base(path) == "SCHEMA.md"
}

// syncDir mirrors src into dst: it copies every template from src and deletes every managed file
// under dst that src no longer contains, so the installed set exactly matches the staged set.
//
// Containment is enforced without trusting symlinks: dst is resolved with EvalSymlinks and every
// directory is created component-by-component, refusing any pre-existing symlinked component
// (mkdirAllNoSymlink), which closes the TOCTOU where a planted intermediate symlink would let a write
// escape the target. The delete pass keeps the same discipline: it never follows a symlink, only
// touches managed files, and stays within root.
func syncDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil { // ensure root exists so it can be resolved
		return err
	}
	root, err := filepath.EvalSymlinks(dst)
	if err != nil {
		return err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return err
	}
	// kept records every copied managed file (resolved-absolute) so the mirror pass tells an orphan
	// from a just-installed file.
	kept := map[string]bool{}
	err = filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		if rel == "." || rel == ".git" || strings.HasPrefix(rel, ".git"+string(os.PathSeparator)) {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 { // never copy a symlink from an untrusted source
			return fmt.Errorf("refusing symlink in source: %s", rel)
		}
		// Re-check containment against root (defense-in-depth vs a "../" sneaking through rel).
		target := filepath.Join(root, rel)
		if target != root && !strings.HasPrefix(target, root+string(os.PathSeparator)) {
			return fmt.Errorf("refusing path escaping target dir: %s", rel)
		}
		if d.IsDir() {
			return mkdirAllNoSymlink(root, target)
		}
		if !managedFile(path) {
			return nil
		}
		if err := mkdirAllNoSymlink(root, filepath.Dir(target)); err != nil {
			return err
		}
		if err := copyFile(path, target); err != nil {
			return err
		}
		kept[target] = true
		return nil
	})
	if err != nil {
		return err
	}
	return mirrorDelete(root, kept)
}

// mirrorDelete removes every managed file under root not in kept, then prunes emptied subdirs. It is
// syncDir's deletion half and runs only on a real install. Safety mirrors the copy path: it never
// descends into or follows a symlink, re-checks containment in root, and removes only managed files —
// never the manifest, never root itself.
func mirrorDelete(root string, kept map[string]bool) error {
	var emptyCandidates []string // subdirs to try pruning, recorded so we can delete deepest-first
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		// Stay within root (defense-in-depth; WalkDir already yields only paths under root).
		if !strings.HasPrefix(path, root+string(os.PathSeparator)) {
			return filepath.SkipDir
		}
		if d.IsDir() {
			if d.Type()&fs.ModeSymlink != 0 { // a symlinked dir: don't follow or delete it
				return filepath.SkipDir
			}
			emptyCandidates = append(emptyCandidates, path)
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 { // never unlink through/of a symlink we did not create
			return nil
		}
		if !managedFile(path) || kept[path] {
			return nil
		}
		// Lstat re-confirms this is a regular file (not a symlink raced into place) before unlinking.
		fi, lerr := os.Lstat(path)
		if lerr != nil {
			if os.IsNotExist(lerr) {
				return nil
			}
			return lerr
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		return os.Remove(path)
	})
	if err != nil {
		return err
	}
	// Prune now-empty managed subdirs, deepest-first so a parent emptied by its children also goes.
	sort.Sort(sort.Reverse(sort.StringSlice(emptyCandidates)))
	for _, dir := range emptyCandidates {
		entries, derr := os.ReadDir(dir)
		if derr != nil || len(entries) != 0 {
			continue // non-empty (e.g. still holds files) or unreadable — leave it
		}
		_ = os.Remove(dir) // best-effort: a failed prune is harmless (an empty dir loads nothing)
	}
	return nil
}

// mkdirAllNoSymlink creates dir and any missing parents below root (which must already exist as a
// real directory), refusing to traverse a pre-existing symlinked component. Unlike os.MkdirAll it
// Lstat()s each existing component and fails on a symlink, so a planted symlink can't redirect a
// later write outside root. dir must be lexically within root.
func mkdirAllNoSymlink(root, dir string) error {
	if dir == root {
		return nil
	}
	if dir != root && !strings.HasPrefix(dir, root+string(os.PathSeparator)) {
		return fmt.Errorf("refusing to create dir outside target: %s", dir)
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return err
	}
	cur := root
	for _, comp := range strings.Split(rel, string(os.PathSeparator)) {
		if comp == "" || comp == "." {
			continue
		}
		if comp == ".." { // should be impossible after the prefix check, but never walk upward
			return fmt.Errorf("refusing to create dir outside target: %s", dir)
		}
		cur = filepath.Join(cur, comp)
		fi, err := os.Lstat(cur)
		switch {
		case err == nil:
			if fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing symlinked path component in target: %s", cur)
			}
			if !fi.IsDir() {
				return fmt.Errorf("path component is not a directory: %s", cur)
			}
		case os.IsNotExist(err):
			// Mkdir fails if cur already exists, so a symlink raced into place is never followed.
			if err := os.Mkdir(cur, 0o755); err != nil {
				return err
			}
		default:
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	// O_NOFOLLOW: if a symlink was planted at dst by an earlier attack, fail rather than write through it.
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|oNoFollow, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// ValidateForUpdate is the default pre-install lint: it refuses a set with any error-level issue. It
// is what Update applies when no custom Validate hook is given.
func ValidateForUpdate(dir string) error {
	if errs := filterLevel(ValidateDir(dir), "error"); len(errs) > 0 {
		return fmt.Errorf("%d rule error(s)", len(errs))
	}
	return nil
}

func filterLevel(issues []Issue, level string) []Issue {
	var out []Issue
	for _, i := range issues {
		if i.Level == level {
			out = append(out, i)
		}
	}
	return out
}
