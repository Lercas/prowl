// Package localfile provides bounded reads and honest discovery for local policy files.
package localfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// FirstExisting selects the first existing name without treating broken links or access errors
// as absence. The selected path still has to be opened and validated by its loader.
func FirstExisting(names ...string) (string, error) {
	for _, name := range names {
		if _, err := os.Lstat(name); err == nil {
			return name, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect %s: %w", name, err)
		}
		if err := checkMissingParents(name); err != nil {
			return "", err
		}
	}
	return "", nil
}

// checkMissingParents distinguishes a missing leaf from a dangling ancestor symlink. Lstat on
// home/rules reports ENOENT for both; only an actually absent directory may trigger fallback.
func checkMissingParents(name string) error {
	for dir := filepath.Dir(name); ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(dir); err == nil {
			info, err := os.Stat(dir)
			if err != nil {
				return fmt.Errorf("inspect parent %s: %w", dir, err)
			}
			if !info.IsDir() {
				return fmt.Errorf("parent %s must be a directory", dir)
			}
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect parent %s: %w", dir, err)
		}
		if filepath.Dir(dir) == dir {
			return nil
		}
	}
}

// FirstDirectory chooses the first existing directory, preserving candidate precedence. An
// existing wrong type, broken link or access failure is an error rather than permission to try
// another library. A valid symlink to a directory is supported.
func FirstDirectory(names ...string) (string, error) {
	name, err := FirstExisting(names...)
	if err != nil || name == "" {
		return name, err
	}
	info, err := os.Stat(name)
	if err != nil {
		return "", fmt.Errorf("inspect directory %s: %w", name, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s must be a directory", name)
	}
	return name, nil
}

// ReadRegular reads at most limit bytes and refuses special files before reading. Opening with
// O_NONBLOCK on Unix prevents a FIFO from blocking before its type can be checked. Explicitly
// selected symlinks may resolve to a regular file. Read, stat and close failures are all returned.
func ReadRegular(path string, limit int64) (raw []byte, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|oNonBlock, 0)
	if err != nil {
		return nil, err
	}
	return readOpenedRegular(f, path, limit)
}

// ReadRootRegular applies the same bounded regular-file contract inside an opened directory root.
// os.Root refuses symlinks escaping that root, including an attacker-swapped manifest/file.
func ReadRootRegular(root *os.Root, name string, limit int64) ([]byte, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|oNonBlock, 0)
	if err != nil {
		return nil, err
	}
	return readOpenedRegular(f, name, limit)
}

func readOpenedRegular(f *os.File, path string, limit int64) (raw []byte, err error) {
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("file %s too large (%d bytes > %d limit)", path, info.Size(), limit)
	}
	raw, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("file %s too large (> %d limit)", path, limit)
	}
	return raw, nil
}
