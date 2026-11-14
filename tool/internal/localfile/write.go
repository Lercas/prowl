package localfile

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// CheckRootDestination permits an absent or regular filename within root, refusing all links and
// special files before a caller fetches or installs anything.
func CheckRootDestination(root *os.Root, name string) error {
	if !filepath.IsLocal(name) || filepath.Base(name) != name || name == "." {
		return fmt.Errorf("atomic destination must be a filename: %q", name)
	}
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s: atomic destination must be a regular file, not a link or special file", name)
	}
	return nil
}

// WriteRootAtomic replaces a regular file without modifying its previous inode or hardlink aliases.
// The temporary file stays inside root and is removed on failure; readers never see a partial write.
func WriteRootAtomic(root *os.Root, name string, raw []byte, mode fs.FileMode) (err error) {
	return WriteRootAtomicWith(root, name, mode, func(w io.Writer) error {
		_, err := w.Write(raw)
		return err
	})
}

// WriteRootAtomicWith streams into an owned temporary file and commits only a successful write.
// The destination and its previous hardlinks remain intact on rendering, write or close failure.
func WriteRootAtomicWith(root *os.Root, name string, mode fs.FileMode, write func(io.Writer) error) (err error) {
	return writeRootAtomicWithContext(context.Background(), root, name, mode, write)
}

func writeRootAtomicWithContext(ctx context.Context, root *os.Root, name string, mode fs.FileMode, write func(io.Writer) error) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := CheckRootDestination(root, name); err != nil {
		return err
	}
	tmp := ".prowl-atomic-" + rand.Text() + ".tmp"
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if f != nil {
			err = errors.Join(err, f.Close())
		}
		if !committed {
			if cleanupErr := root.Remove(tmp); !errors.Is(cleanupErr, os.ErrNotExist) {
				err = errors.Join(err, cleanupErr)
			}
		}
	}()
	w := &checkedWriter{w: f}
	if err := write(w); err != nil {
		return err
	}
	if w.err != nil {
		return w.err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	closeErr := f.Close()
	f = nil
	if closeErr != nil {
		return closeErr
	}
	if err := CheckRootDestination(root, name); err != nil {
		return err
	}
	// Cancellation observed before commit must leave the previous artifact intact.
	if err := ctx.Err(); err != nil {
		return err
	}
	// A link raced into the destination after Lstat is replaced by Rename, never followed.
	if err := root.Rename(tmp, name); err != nil {
		return err
	}
	committed = true // the temporary name is no longer ours; never clean a later replacement
	return nil
}

type checkedWriter struct {
	w   io.Writer
	err error
}

func (w *checkedWriter) Write(raw []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	n, err := w.w.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	w.err = err
	return n, err
}

// WriteAtomic pins the explicitly selected parent directory, including a valid directory alias.
// It never creates missing parents or follows a destination link.
func WriteAtomic(path string, mode fs.FileMode, write func(io.Writer) error) (err error) {
	return WriteAtomicContext(context.Background(), path, mode, write)
}

// WriteAtomicContext checks cancellation before rendering and immediately before Rename.
// A completed commit is not rolled back if the context is cancelled afterward.
func WriteAtomicContext(ctx context.Context, path string, mode fs.FileMode, write func(io.Writer) error) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Split preserves OS path resolution through a directory alias followed by "..". Dir would
	// clean that spelling lexically and silently select a different parent.
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	return writeRootAtomicWithContext(ctx, root, name, mode, write)
}

func WriteAtomicBytes(path string, raw []byte, mode fs.FileMode) error {
	return WriteAtomic(path, mode, func(w io.Writer) error {
		_, err := w.Write(raw)
		return err
	})
}
