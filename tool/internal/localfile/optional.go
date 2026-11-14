package localfile

import (
	"errors"
	"os"
)

// ReadOptionalRoot reads an optional regular file within root. Only actual absence is optional:
// broken links, unreadable entries, wrong types and escaped symlinks remain errors.
func ReadOptionalRoot(root *os.Root, name string, limit int64) ([]byte, bool, error) {
	if _, err := root.Lstat(name); errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	raw, err := ReadRootRegular(root, name, limit)
	return raw, true, err
}

// ReadOptionalDirectoryFile allows a truly absent library directory, preserving all errors in an
// existing selection. The read remains pinned to one opened root, including directory aliases.
func ReadOptionalDirectoryFile(dir, name string, limit int64) (raw []byte, present bool, err error) {
	selected, err := FirstDirectory(dir)
	if err != nil || selected == "" {
		return nil, false, err
	}
	root, err := os.OpenRoot(selected)
	if err != nil {
		return nil, false, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	return ReadOptionalRoot(root, name, limit)
}
