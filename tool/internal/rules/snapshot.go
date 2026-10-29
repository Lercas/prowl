package rules

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
	MaxIntegrityManifestSize = 8 << 20
	MaxLibraryBytes          = 64 << 20
	MaxLibraryFiles          = 10000
)

type templateFile struct {
	path, rel string
	raw       []byte
}

type librarySnapshot struct {
	files    []templateFile
	manifest map[string]string // nil means absent; empty means a present empty manifest
}

// readLibrarySnapshot captures bounded regular-file bytes for both integrity and compilation.
// Root-scoped opens reject escaping links, including an attacker-swapped manifest or template.
func readLibrarySnapshot(dir string, withManifest bool) (snapshot *librarySnapshot, err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	return readLibrarySnapshotRoot(root, dir, withManifest)
}

// readLibrarySnapshotRoot leaves root open so manifest generation can write into the same directory
// even if its pathname is renamed or its alias changes after the snapshot is captured.
func readLibrarySnapshotRoot(root *os.Root, dir string, withManifest bool) (snapshot *librarySnapshot, err error) {
	snapshot = &librarySnapshot{}
	if withManifest {
		if _, err := root.Lstat(IntegrityManifestName); err == nil {
			raw, err := localfile.ReadRootRegular(root, IntegrityManifestName, MaxIntegrityManifestSize)
			if err != nil {
				return nil, err
			}
			snapshot.manifest, err = localfile.ParseSHA256Manifest(raw, IntegrityManifestName)
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
		if d.IsDir() || filepath.Base(rel) == IntegrityManifestName {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(rel))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		if len(snapshot.files) >= MaxLibraryFiles {
			return fmt.Errorf("rule library exceeds %d files", MaxLibraryFiles)
		}
		raw, err := localfile.ReadRootRegular(root, filepath.FromSlash(rel), MaxTemplateSize)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		if len(raw) > MaxLibraryBytes-total {
			return fmt.Errorf("rule library exceeds %d bytes", MaxLibraryBytes)
		}
		total += len(raw)
		snapshot.files = append(snapshot.files, templateFile{filepath.Join(dir, filepath.FromSlash(rel)), rel, raw})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return snapshot, nil
}
