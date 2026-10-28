package source

import (
	"context"
	"github.com/Lercas/prowl/tool/internal/model"
)

// GitIndexFiles reads immutable index objects rather than their working-tree counterparts.
func GitIndexFiles(ctx context.Context, paths, exclude []string, maxBytes int64) <-chan model.Item {
	return GitIndexFilesIn(ctx, "", paths, exclude, maxBytes)
}
