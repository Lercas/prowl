package source

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/ownedcmd"
)

type repositoryOriginKey struct{}
type repositoryOrigin struct {
	roots         []string
	url           string
	revision      string
	pinned, empty bool
}

// RepositoryLocator strips transport credentials without changing the resource's path identity.
func RepositoryLocator(raw string) string {
	if strings.HasPrefix(raw, "git@") {
		rest := strings.TrimPrefix(raw, "git@")
		host, path, ok := strings.Cut(rest, ":")
		if strings.HasPrefix(rest, "[") {
			end := strings.Index(rest, "]:")
			if end >= 0 {
				host, path, ok = rest[:end+1], rest[end+2:], true
			}
		}
		if !ok || host == "" || path == "" {
			return "<invalid repository URL>"
		}
		// SCP home-relative paths must not collapse into absolute ssh:// paths.
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "ssh" && u.Scheme != "git") {
		return "<invalid repository URL>"
	}
	u.User, u.RawQuery, u.Fragment, u.ForceQuery = nil, "", "", false
	return u.String()
}

func (o repositoryOrigin) relative(path string) (string, bool) {
	for _, root := range o.roots {
		if path == root {
			return "", true
		}
		if strings.HasPrefix(path, root+string(filepath.Separator)) {
			return filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator))), true
		}
	}
	return "", false
}
func (o repositoryOrigin) locator(path string) string {
	if relative, ok := o.relative(path); ok {
		if relative == "" {
			return o.url
		}
		return o.url + "!/" + relative
	}
	return path
}
func (o repositoryOrigin) artifact(path string) string {
	relative, ok := o.relative(path)
	if !ok {
		relative = path
	}
	if relative == "" {
		return o.url
	}
	return o.url + "!/" + url.PathEscape(filepath.ToSlash(relative))
}

type repositoryDataWriter struct {
	writer    io.Writer
	remaining int64
	cancel    context.CancelFunc
}

func (w *repositoryDataWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		w.cancel()
		return 0, errors.New("repository metadata limit reached")
	}
	n, err := w.writer.Write(p)
	w.remaining -= int64(n)
	return n, err
}
func repositoryData(ctx context.Context, dir string, opts CloneOpts, writer io.Writer, limit int64, args ...string) error {
	actx, cancel := context.WithTimeout(ctx, contextFetchTimeout(ctx, opts.Timeout))
	defer cancel()
	cmd := gitCmd(actx, dir, args...)
	_, err := ownedcmd.RunWithStdout(cmd, &repositoryDataWriter{writer, limit, cancel})
	if err != nil {
		return errors.New("repository revision metadata could not be read completely")
	}
	return nil
}

// RepositoryContext binds a temporary checkout to stable acquisition locators. History blobs retain
// their own blob IDs; the collection's HEAD is never asserted as each historical blob's commit.
// The returned context remains usable on metadata failure so readable files can still be scanned.
func RepositoryContext(ctx context.Context, dir string, opts CloneOpts) (context.Context, error) {
	ctx = snapshotFetchTimeout(ctx)
	origin := repositoryOrigin{roots: []string{filepath.Clean(dir)}, url: RepositoryLocator(opts.URL)}
	if physical, err := filepath.EvalSymlinks(dir); err == nil && physical != origin.roots[0] {
		origin.roots = append(origin.roots, physical)
	}
	ctx = context.WithValue(ctx, bucketOriginKey{}, struct{}{})
	ctx = context.WithValue(ctx, repositoryOriginKey{}, origin)
	ctx = model.WithSourceLocator(ctx, origin.locator)
	var head bytes.Buffer
	headErr := repositoryData(ctx, dir, opts, &head, 128, "rev-parse", "--verify", "HEAD^{commit}")
	revision := strings.TrimSpace(head.String())
	var refsDigest string
	empty := false
	var snapshotErr error
	if headErr != nil || !model.ValidImmutableMetadata("commit", revision) {
		snapshotErr = errors.New("repository HEAD could not be pinned")
		if headErr != nil {
			var refs, symbolic bytes.Buffer
			refsErr := repositoryData(ctx, dir, opts, &refs, 1, "for-each-ref", "--format=%(objectname)")
			symErr := repositoryData(ctx, dir, opts, &symbolic, 4096, "symbolic-ref", "--quiet", "HEAD")
			entries, readErr := os.ReadDir(dir)
			empty = refsErr == nil && refs.Len() == 0 && symErr == nil && strings.HasPrefix(strings.TrimSpace(symbolic.String()), "refs/heads/") && readErr == nil && len(entries) == 1 && entries[0].Name() == ".git"
			if empty {
				snapshotErr = nil
				revision = ""
			}
		}
	}
	if opts.Full && snapshotErr == nil {
		hash := sha256.New()
		if err := repositoryData(ctx, dir, opts, hash, 64<<20, "for-each-ref", "--format=%(refname)%00%(objectname)"); err != nil {
			snapshotErr = err
		} else {
			refsDigest = hex.EncodeToString(hash.Sum(nil))
		}
	}
	depth := opts.Depth
	if depth <= 0 && !opts.Full {
		depth = 1
	}
	model.CoverageFrom(ctx).RegisterScope("repository", origin.url, struct {
		Revision, Head, Refs, Branch string
		History, Empty               bool
		Depth                        int
	}{"1.5.0-repository-v1", revision, refsDigest, opts.Branch, opts.Full, empty, depth})
	commit := revision
	if opts.Full || snapshotErr != nil {
		commit = ""
	}
	ctx = model.WithProvenance(model.WithoutProvenance(ctx), map[string]any{"source_url": origin.url, "url": "", "commit": commit})
	if snapshotErr != nil {
		model.Note(ctx, "repository_revision_unavailable", origin.url, true)
	}
	origin.revision, origin.empty, origin.pinned = commit, empty, snapshotErr == nil && !opts.Full
	ctx = context.WithValue(ctx, repositoryOriginKey{}, origin)
	return ctx, snapshotErr
}
