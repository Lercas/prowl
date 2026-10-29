package verify

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Lercas/prowl/tool/internal/localfile"
)

const (
	MaxVerifierSize = 512 * 1024
	MaxManifestSize = 8 << 20
	MaxSetBytes     = 64 << 20
	MaxSetFiles     = 10000
)

type verifierFile struct {
	path, rel string
	raw       []byte
}

type directorySnapshot struct {
	files    []verifierFile
	manifest map[string]string // nil means absent; an empty map is a present empty manifest
}

// readDirectorySnapshot bounds all reads and keeps one copy of each file for both its integrity
// check and compilation. Root-scoped reads never follow a selected entry outside the library.
func readDirectorySnapshot(dir string, withManifest bool) (snapshot *directorySnapshot, err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	return readDirectorySnapshotRoot(root, dir, withManifest)
}

// readDirectorySnapshotRoot leaves root open for a generator to keep reads and writes in the same
// selected directory even if its pathname or alias changes meanwhile.
func readDirectorySnapshotRoot(root *os.Root, dir string, withManifest bool) (snapshot *directorySnapshot, err error) {
	snapshot = &directorySnapshot{}
	if withManifest {
		if _, err := root.Lstat(ManifestName); err == nil {
			raw, err := localfile.ReadRootRegular(root, ManifestName, MaxManifestSize)
			if err != nil {
				return nil, err
			}
			snapshot.manifest, err = parseManifest(raw)
			if err != nil {
				return nil, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	total := 0
	err = fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Base(rel) == ManifestName {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(rel))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		if len(snapshot.files) >= MaxSetFiles {
			return fmt.Errorf("verifier set exceeds %d files", MaxSetFiles)
		}
		raw, err := localfile.ReadRootRegular(root, filepath.FromSlash(rel), MaxVerifierSize)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		if len(raw) > MaxSetBytes-total {
			return fmt.Errorf("verifier set exceeds %d bytes", MaxSetBytes)
		}
		total += len(raw)
		snapshot.files = append(snapshot.files, verifierFile{filepath.Join(dir, filepath.FromSlash(rel)), rel, raw})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return snapshot, nil
}
