package source

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Lercas/prowl/tool/internal/model"
)

type filesystemOriginKey struct{}

// The origin belongs only to one filesystem root; other sources and subsequent roots do not inherit it.
type filesystemOrigin struct{ display, physical string }

func hasParentSegment(path string) bool {
	for _, segment := range strings.Split(filepath.ToSlash(path), "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

// Joining a display identity must not clean '..' across a symbolic link.
func displaySourcePath(root, relative string) string {
	if relative == "." {
		return root
	}
	if strings.HasSuffix(root, string(os.PathSeparator)) {
		return root + relative
	}
	return root + string(os.PathSeparator) + relative
}

func (o filesystemOrigin) uri(path string) string {
	physical := o.physical
	if path != o.display {
		dirPrefix := displaySourcePath(o.display, "")
		switch {
		case strings.HasPrefix(path, dirPrefix):
			physical = displaySourcePath(physical, strings.TrimPrefix(path, dirPrefix))
		case strings.HasPrefix(path, o.display+"!/"):
			physical += strings.TrimPrefix(path, o.display)
		default:
			return ""
		}
	}
	return model.PathURI(physical, runtime.GOOS)
}

func withFilesystemOrigin(ctx context.Context, display, physical string) (context.Context, error) {
	abs, err := filepath.Abs(physical)
	if err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, filesystemOriginKey{}, filesystemOrigin{display, abs}), nil
}
