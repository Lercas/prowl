package source

import (
	"context"
	"path/filepath"

	"github.com/Lercas/prowl/tool/internal/model"
)

// Local scopes describe selection, not an immutable snapshot of mutable files.
func registerLocalScope(ctx context.Context, kind, target string, policy any) {
	if target == "" {
		target = "."
	}
	if absolute, err := filepath.Abs(target); err == nil {
		target = absolute
	}
	if origin, ok := ctx.Value(repositoryOriginKey{}).(repositoryOrigin); ok {
		model.CoverageFrom(ctx).RegisterScope("repository-selection", origin.locator(target), struct {
			Kind      string
			Selection any
		}{kind, policy})
		return
	}
	model.CoverageFrom(ctx).RegisterScope(kind, target, policy)
}

func registerGitScope(ctx context.Context, kind, dir string, paths, exclude []string, maxBytes int64) {
	registerLocalScope(ctx, kind, dir, struct {
		Paths, Exclude []string
		MaxBytes       int64
	}{paths, exclude, maxBytes})
}
