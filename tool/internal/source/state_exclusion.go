package source

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

type stateDirectoryKey struct{}

// WithStateDirectory keeps local scanner state out of physical filesystem
// acquisition, including explicitly selected aliases. It does not suppress
// similarly named paths from remote sources or historical Git objects.
func WithStateDirectory(ctx context.Context, directory string) context.Context {
	if directory == "" {
		return ctx
	}
	path, err := filepath.Abs(directory)
	if err != nil {
		return ctx
	}
	return context.WithValue(ctx, stateDirectoryKey{}, path)
}

func stateDirectoryExcluded(ctx context.Context, path string) bool {
	directory, ok := ctx.Value(stateDirectoryKey{}).(string)
	if !ok {
		return false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	if resolved, err := filepath.EvalSymlinks(directory); err == nil {
		directory = resolved
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	rel, err := filepath.Rel(directory, abs)
	if err == nil && (rel == "." || filepath.IsLocal(rel)) {
		return true
	}
	// macOS and Windows may preserve caller casing while resolving symlinks.
	// Case-folding alone would wrongly hide distinct files on a case-sensitive
	// volume, so verify the actual directory identity before excluding an alias.
	folded, err := filepath.Rel(strings.ToLower(directory), strings.ToLower(abs))
	if err != nil || (folded != "." && !filepath.IsLocal(folded)) {
		return false
	}
	state, err := os.Stat(directory)
	if err != nil {
		return false
	}
	for candidate := abs; ; candidate = filepath.Dir(candidate) {
		if info, err := os.Stat(candidate); err == nil && os.SameFile(state, info) {
			return true
		}
		if filepath.Dir(candidate) == candidate {
			return false
		}
	}
}
