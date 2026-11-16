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
		Revision             string
		MaxItems             int
		MaxBytes             int
		MaxBoundaries        int
		MaxBoundaryPathBytes int
	}{"selected-working-files-v2-stable-boundaries", maxComponentRepositoryItems, maxComponentRepositoryBytes, maxComponentWorktreeObservations, maxComponentRepositoryBytes})
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
	observations := &worktreeObservations{}
	var total int64
	for _, path := range selected {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Check every traversed directory, including parents absent from the diff.
		// Symlink aliases can be scanned within os.Root, but cannot lend roles.
		linked := false
		var before os.FileInfo
		var boundaries []string
		parts := strings.Split(path, "/")
		for i := 1; i <= len(parts); i++ {
			prefix := filepath.Join(parts[:i]...)
			info, err := observations.observe(rootFS, prefix)
			if err != nil || info == nil {
				return errors.New("working-tree path boundary unavailable")
			}
			boundaries = append(boundaries, prefix)
			before = info
			if info.Mode()&os.ModeSymlink != 0 {
				linked = true
				break
			}
			if i < len(parts) {
				marker := filepath.Join(prefix, ".git")
				gitInfo, err := observations.observe(rootFS, marker)
				if err != nil {
					return err
				}
				boundaries = append(boundaries, marker)
				full := filepath.Join(root, prefix)
				if gitInfo != nil && scopes[full] == nil {
					if len(scopes) >= maxComponentRepositoryItems {
						return errors.New("working-tree repository scope limit reached")
					}
					scopes[full] = credentialset.NewScope()
				}
			}
		}
		if linked {
			before, err = rootFS.Stat(filepath.FromSlash(path))
		}
		if err != nil || before == nil || !before.Mode().IsRegular() {
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
			return observations.open(rootFS, filepath.FromSlash(path), before, boundaries)
		}, min(maxBytes, maxComponentRepositoryBytes-total))
		if err != nil {
			return err
		}
		if err := observations.validate(rootFS, boundaries); err != nil {
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
