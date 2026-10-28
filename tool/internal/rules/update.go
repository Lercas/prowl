package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Lercas/prowl/tool/internal/localfile"
	"github.com/Lercas/prowl/tool/internal/ownedcmd"
)

// ManifestName is the version/provenance file written into a rules directory by `rules update`.
const ManifestName = ".prowl-rules.json"

// cloneTimeout bounds a single `rules update` git clone so a hung/hostile `--source` can't wedge it.
const cloneTimeout = 2 * time.Minute

// maxCloneBytes caps a fetched checkout's on-disk size, refusing a disk-filling source. Backstops the
// `--filter=blob:limit` git already applies.
const maxCloneBytes = 64 << 20 // 64 MiB

// ErrSourceUnavailable allows the CLI to use a bundled source after a failed remote acquisition.
// Validation, local I/O, installation and caller cancellation never carry this classification.
var ErrSourceUnavailable = errors.New("remote template source unavailable")

// Manifest records what rule set is installed and where it came from.
type Manifest struct {
	Source    string            `json:"source"`
	Version   string            `json:"version"`
	UpdatedAt string            `json:"updated_at"`
	Count     int               `json:"count"`
	Files     map[string]string `json:"files"` // relpath -> sha256
}

// UpdateOpts configures an update. Check reports the diff without writing to Target.
type UpdateOpts struct {
	Source   string // local directory or git URL
	Target   string // where to install (default: the source if local, else required)
	Now      string // caller-supplied timestamp
	Check    bool
	Subdir   string                 // subdir inside a cloned/checked-out source to install (e.g. "rules", "verifiers")
	Validate func(dir string) error // nil -> default rule-template validation
	// Ctx cancels acquisition, capture and installation; nil means context.Background().
	Ctx context.Context
}

// UpdateResult summarizes an update for the CLI.
type UpdateResult struct {
	Manifest        Manifest
	Added           []string
	Changed         []string
	Removed         []string
	Errors          []Issue
	StagedDir       string // owned validation copy on --check; the caller must Close the result
	NoChange        bool
	MetadataChanged bool // provenance or integrity differs, excluding the update timestamp
	cleanup         func() error
	closeOnce       sync.Once
	closeErr        error
}

// Close releases the owned --check validation copy. It never removes the public source or target.
func (result *UpdateResult) Close() error {
	if result == nil {
		return nil
	}
	result.closeOnce.Do(func() {
		if result.cleanup != nil {
			result.closeErr = result.cleanup()
		}
	})
	return result.closeErr
}

// Update fetches the rule set from Source, validates it (refusing a set with errors), diffs it
// against Target, and — unless Check — syncs Target and writes the manifest.
func Update(o UpdateOpts) (result *UpdateResult, err error) {
	selected, err := localfile.FirstDirectory(o.Target)
	if err != nil {
		return nil, err
	}
	var targetRoot *os.Root
	defer func() {
		if targetRoot != nil {
			err = errors.Join(err, targetRoot.Close())
		}
	}()
	oldManifest := Manifest{}
	if selected != "" {
		targetRoot, err = os.OpenRoot(selected)
		if err != nil {
			return nil, err
		}
		if err := localfile.CheckRootDestination(targetRoot, ManifestName); err != nil {
			return nil, fmt.Errorf("installed provenance: %w", err)
		}
		if err := localfile.CheckRootDestination(targetRoot, IntegrityManifestName); err != nil {
			return nil, fmt.Errorf("installed integrity destination: %w", err)
		}
		oldManifest, err = readManifestRoot(targetRoot, selected)
		if err != nil {
			return nil, fmt.Errorf("installed provenance: %w", err)
		}
	}
	ctx := o.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	staged, cleanup, version, err := fetch(ctx, o.Source, o.Subdir)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	snapshot, err := captureUpdate(ctx, staged)
	if err != nil {
		return nil, fmt.Errorf("capture update source: %w", err)
	}
	v, err := snapshot.version()
	if err != nil {
		return nil, fmt.Errorf("source VERSION: %w", err)
	}
	if v != "" {
		version = v
	}
	validationDir, err := snapshot.validationCopy()
	if err != nil {
		return nil, err
	}
	keepValidation := false
	defer func() {
		if !keepValidation {
			err = errors.Join(err, os.RemoveAll(validationDir))
		}
	}()
	validate := o.Validate
	if validate == nil {
		validate = ValidateForUpdate
	}
	if err := validate(validationDir); err != nil {
		return &UpdateResult{}, fmt.Errorf("refusing to update: %w", err)
	}
	validated, err := captureUpdate(ctx, validationDir)
	if err != nil {
		return nil, fmt.Errorf("validation snapshot: %w", err)
	}
	if !snapshot.unchanged(validated) {
		return nil, fmt.Errorf("refusing to update: validation snapshot changed")
	}
	if targetRoot != nil {
		if err := snapshot.preflight(targetRoot); err != nil {
			return nil, err
		}
	}
	newFiles := snapshot.hashes()
	managed := snapshot.managedHashes()
	old := map[string]string{}
	var oldIntegrity []byte
	oldIntegrityPresent := false
	if targetRoot != nil {
		old, err = inventoryTarget(ctx, targetRoot)
		if err != nil {
			return nil, fmt.Errorf("installed inventory: %w", err)
		}
		oldIntegrity, oldIntegrityPresent, err = localfile.ReadOptionalRoot(targetRoot, IntegrityManifestName, MaxIntegrityManifestSize)
		if err != nil {
			return nil, fmt.Errorf("installed integrity: %w", err)
		}
	}
	integrity, err := snapshot.integrityBytes()
	if err != nil {
		return nil, err
	}
	res := &UpdateResult{}
	for rel, sum := range managed {
		switch {
		case old[rel] == "":
			res.Added = append(res.Added, rel)
		case old[rel] != sum:
			res.Changed = append(res.Changed, rel)
		}
	}
	for rel := range old {
		if managed[rel] == "" {
			res.Removed = append(res.Removed, rel)
		}
	}
	sort.Strings(res.Added)
	sort.Strings(res.Changed)
	sort.Strings(res.Removed)
	res.MetadataChanged = oldManifest.Source != o.Source || oldManifest.Version != version ||
		!maps.Equal(oldManifest.Files, newFiles) || !oldIntegrityPresent || !bytes.Equal(oldIntegrity, integrity)
	res.NoChange = len(res.Added)+len(res.Changed)+len(res.Removed) == 0 && !res.MetadataChanged

	res.Manifest = Manifest{
		Source: o.Source, Version: version, UpdatedAt: o.Now,
		Count: len(newFiles), Files: newFiles,
	}
	raw, err := json.MarshalIndent(res.Manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxProvenanceSize {
		return nil, fmt.Errorf("generated provenance exceeds %d bytes", MaxProvenanceSize)
	}
	if o.Check {
		res.StagedDir = validationDir
		res.cleanup = func() error { return os.RemoveAll(validationDir) }
		keepValidation = true
		return res, nil
	}
	if targetRoot == nil {
		if err := os.MkdirAll(o.Target, 0o755); err != nil {
			return nil, err
		}
		targetRoot, err = os.OpenRoot(o.Target)
		if err != nil {
			return nil, err
		}
	}
	if err := localfile.CheckRootDestination(targetRoot, ManifestName); err != nil {
		return nil, err
	}
	if err := localfile.CheckRootDestination(targetRoot, IntegrityManifestName); err != nil {
		return nil, err
	}
	if err := snapshot.install(ctx, targetRoot); err != nil {
		return nil, err
	}
	// Seal the validated bytes directly; never bless a later reread of the installed directory.
	if err := localfile.WriteRootAtomic(targetRoot, IntegrityManifestName, integrity, 0o644); err != nil {
		return nil, err
	}
	// Replace the inode within the selected root; hardlink aliases retain the old public metadata.
	if err := localfile.WriteRootAtomic(targetRoot, ManifestName, raw, 0o644); err != nil {
		return nil, err
	}
	return res, nil
}

// fetch resolves src to a local directory of templates, returning a cleanup func and a version
// (git short-sha for repos, "local" for directories). A remote fetch is bounded by ctx, a clone
// timeout, and a size cap so a hung or disk-filling `--source` can't wedge the command.
func fetch(ctx context.Context, src, subdir string) (dir string, cleanup func(), version string, err error) {
	noop := func() {}
	if err := ctx.Err(); err != nil {
		return "", noop, "", err
	}
	if subdir != "" && (!fs.ValidPath(filepath.ToSlash(subdir)) || !filepath.IsLocal(subdir)) {
		return "", noop, "", fmt.Errorf("source subdir must be a relative path inside the source")
	}
	if src == "" {
		return "", noop, "", fmt.Errorf("no --source given (local dir or git URL)")
	}
	selected, err := localfile.FirstDirectory(src)
	if err != nil {
		return "", noop, "", fmt.Errorf("source directory: %w", err)
	}
	if selected != "" {
		dir, err := selectSourceDirectory(selected, subdir)
		return dir, noop, "local", err
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
		if out, err := ownedcmd.Run(cmd); err != nil {
			cleanup()
			if ctx.Err() != nil { // parent cancelled (Ctrl-C / overall --timeout)
				return "", noop, "", fmt.Errorf("git clone cancelled: %w", ctx.Err())
			}
			if cctx.Err() == context.DeadlineExceeded {
				return "", noop, "", fmt.Errorf("%w: git clone timed out after %s", ErrSourceUnavailable, cloneTimeout)
			}
			return "", noop, "", fmt.Errorf("%w: git clone: %w: %s", ErrSourceUnavailable, err, out)
		}
		// Backstop the disk-fill guard: a server can ignore --filter and stream many small files.
		// Reject a checkout over the size cap before reading/syncing any of it.
		if n, serr := dirSizeContext(cctx, tmp, maxCloneBytes); serr != nil {
			cleanup()
			return "", noop, "", serr
		} else if n > maxCloneBytes {
			cleanup()
			return "", noop, "", fmt.Errorf("refusing rule source: clone exceeds %d bytes (got >%d) — looks hostile/oversized", maxCloneBytes, n)
		}
		out, err := ownedcmd.Run(exec.CommandContext(cctx, "git", "-C", tmp, "rev-parse", "--short", "HEAD"))
		if err != nil {
			cleanup()
			return "", noop, "", fmt.Errorf("read source revision: %w: %s", err, out)
		}
		ver := strings.TrimSpace(out)
		if !validGitRevision(ver) {
			cleanup()
			return "", noop, "", fmt.Errorf("invalid source git revision")
		}
		if subdir == "" {
			subdir = "rules"
		}
		selected, err := selectSourceDirectory(tmp, subdir)
		if err != nil {
			cleanup()
			return "", noop, "", err
		}
		return selected, cleanup, ver, nil
	}
	return "", noop, "", fmt.Errorf("unsupported source %q (use a local directory or a git URL)", src)
}

// A missing optional subdir supports standalone libraries. A present wrong type, broken link,
// access error or link escaping the source cannot silently choose the parent library instead.
func selectSourceDirectory(dir, subdir string) (string, error) {
	if subdir == "" {
		return dir, nil
	}
	selected, err := localfile.FirstDirectory(filepath.Join(dir, subdir))
	if err != nil {
		return "", fmt.Errorf("source subdir: %w", err)
	}
	if selected == "" {
		return dir, nil
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	child, openErr := root.OpenRoot(subdir)
	closeErr := root.Close()
	if openErr != nil {
		return "", errors.Join(openErr, closeErr)
	}
	if err := errors.Join(closeErr, child.Close()); err != nil {
		return "", err
	}
	return selected, nil
}

func validGitRevision(value string) bool {
	if len(value) < 4 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

// dirSize sums the size of every regular file under dir, stopping early once the total exceeds limit
// (so a huge tree is rejected without a full walk). Symlinks are not followed. The result is exact
// when <= limit and a lower bound (> limit) when the cap trips.
func dirSize(dir string, limit int64) (int64, error) {
	return dirSizeContext(context.Background(), dir, limit)
}

func dirSizeContext(ctx context.Context, dir string, limit int64) (total int64, err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	entries := 0
	err = fs.WalkDir(root.FS(), ".", func(_ string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}
		entries++
		if entries > MaxUpdateEntries {
			return fmt.Errorf("clone exceeds %d entries", MaxUpdateEntries)
		}
		if d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() > limit-total {
			total = limit + 1
			return filepath.SkipAll // over budget — stop walking, the caller will refuse the set
		}
		total += info.Size()
		return nil
	})
	return total, err
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

// managedFile reports whether path is a file an update may copy or delete: the rule templates
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
