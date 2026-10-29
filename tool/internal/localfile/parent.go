package localfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// OpenParent opens a file's parent under root, pinning each directory before proceeding. Existing
// symlink components are refused; rooted opens also prevent a raced link from escaping the root.
// The caller owns the returned root. Without create, an absent parent returns os.ErrNotExist.
func OpenParent(root *os.Root, rel string, create bool) (parent *os.Root, name string, err error) {
	if !fs.ValidPath(rel) || rel == "." || !filepath.IsLocal(filepath.FromSlash(rel)) {
		return nil, "", fmt.Errorf("invalid relative file path")
	}
	parts := strings.Split(rel, "/")
	name = parts[len(parts)-1]
	current, err := root.OpenRoot(".")
	if err != nil {
		return nil, "", err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, current.Close())
		}
	}()
	for _, part := range parts[:len(parts)-1] {
		info, statErr := current.Lstat(part)
		if errors.Is(statErr, os.ErrNotExist) && create {
			if mkdirErr := current.Mkdir(part, 0o755); mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
				return nil, "", mkdirErr
			}
			info, statErr = current.Lstat(part)
		}
		if statErr != nil {
			return nil, "", statErr
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, "", fmt.Errorf("parent component %q must be a directory, not a link", part)
		}
		next, openErr := current.OpenRoot(part)
		if openErr != nil {
			return nil, "", openErr
		}
		closeErr := current.Close()
		current = next
		if closeErr != nil {
			return nil, "", closeErr
		}
	}
	return current, name, nil
}
