package source

import (
	"errors"
	"os"
)

const maxComponentWorktreeObservations = 100000

// Keep path identity and repository markers stable across this observed intake.
// File contents remain mutable: this is not an atomic filesystem snapshot.
type worktreeObservations struct {
	seen  map[string]os.FileInfo
	bytes int
}

func (o *worktreeObservations) observe(root *os.Root, path string) (os.FileInfo, error) {
	info, err := root.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		info, err = nil, nil
	}
	if err != nil {
		return nil, err
	}
	if previous, exists := o.seen[path]; exists {
		if !sameWorktreeObservation(previous, info) {
			return nil, errors.New("working-tree acquisition boundary changed")
		}
		return info, nil
	}
	if len(o.seen) >= maxComponentWorktreeObservations || len(path) > maxComponentRepositoryBytes-o.bytes {
		return nil, errors.New("working-tree boundary observation limit reached")
	}
	if o.seen == nil {
		o.seen = make(map[string]os.FileInfo)
	}
	o.seen[path] = info
	o.bytes += len(path)
	return info, nil
}

func sameWorktreeObservation(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Mode().Type() == b.Mode().Type() && os.SameFile(a, b)
}

func (o *worktreeObservations) validate(root *os.Root, paths []string) error {
	for _, path := range paths {
		if _, err := o.observe(root, path); err != nil {
			return err
		}
	}
	return nil
}

func (o *worktreeObservations) open(root *os.Root, path string, before os.FileInfo, boundaries []string) (*os.File, error) {
	file, err := root.OpenFile(path, os.O_RDONLY|sourceOpenFlags, 0)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, errors.New("working-tree component changed during open")
	}
	if err := o.validate(root, boundaries); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
