package source

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/Lercas/prowl/tool/internal/credentialset"
	"github.com/Lercas/prowl/tool/internal/model"
)

// readCredentialWorktree binds only the selected working files, never unchanged
// HEAD/index companions. This is an observed intake, not an atomic Git snapshot.
func readCredentialWorktree(ctx context.Context, ch chan<- model.Item, root string, paths, exclude []string, maxBytes int64) error {
	rootFS, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer rootFS.Close()
	ctx = credentialRootContext(ctx)
	model.CoverageFrom(ctx).RegisterScope("components-worktree", root, struct {
		Revision string
		MaxItems int
		MaxBytes int
	}{"selected-working-files-v1", maxComponentRepositoryItems, maxComponentRepositoryBytes})
	scopes := map[string]*credentialset.Scope{root: ctx.Value(credentialScopeKey{}).(*credentialset.Scope)}
	selected := make([]string, 0, len(paths))
	seen := make(map[string]bool)
	for _, path := range paths {
		if path == "." || !filepath.IsLocal(filepath.FromSlash(path)) || filepath.ToSlash(filepath.Clean(path)) != path || seen[path] {
			return errors.New("invalid or duplicate working-tree selection")
		}
		seen[path] = true
		if excludedGitPath(ctx, path, exclude) || stateDirectoryExcluded(ctx, filepath.Join(root, path)) {
			continue
		}
		selected = append(selected, path)
		if len(selected) > maxComponentRepositoryItems {
			return errors.New("working-tree component item limit reached")
		}
	}
	var total int64
	for _, path := range selected {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Check every traversed directory, including parents absent from the diff.
		// Symlink aliases can be scanned within os.Root, but cannot lend roles.
		linked := false
		parts := strings.Split(path, "/")
		for i := 1; i <= len(parts); i++ {
			prefix := filepath.Join(parts[:i]...)
			info, err := rootFS.Lstat(prefix)
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				linked = true
				break
			}
			if i < len(parts) {
				full := filepath.Join(root, prefix)
				if _, exists := scopes[full]; exists {
					continue
				}
				if err := nestedCredentialRoot(ctx, rootFS, root, full, scopes); err != nil {
					return err
				}
			}
		}
		before, err := rootFS.Stat(filepath.FromSlash(path))
		if err != nil || !before.Mode().IsRegular() {
			return errors.New("working-tree component is not a readable regular file")
		}
		if before.Size() > maxBytes {
			model.Note(ctx, "max_size", path, true)
			return errSourceTooLarge
		}
		if before.Size() > maxComponentRepositoryBytes-total {
			return errors.New("working-tree component byte limit reached")
		}
		data, err := readSourceFile(func() (*os.File, error) {
			file, err := rootFS.OpenFile(filepath.FromSlash(path), os.O_RDONLY|sourceOpenFlags, 0)
			if err != nil {
				return nil, err
			}
			after, err := file.Stat()
			if err != nil || !os.SameFile(before, after) {
				_ = file.Close()
				return nil, errors.New("working-tree component changed during open")
			}
			return file, nil
		}, min(maxBytes, maxComponentRepositoryBytes-total))
		if err != nil {
			return err
		}
		total += int64(len(data))
		emitCtx := credentialFileContext(ctx, filepath.Join(root, path), scopes)
		if linked {
			emitCtx = withoutCredentialScope(ctx)
		}
		if !emitPayload(emitCtx, ch, path, data, maxBytes, exclude, map[string]any{"git_worktree": true}) {
			return ctx.Err()
		}
	}
	return nil
}
