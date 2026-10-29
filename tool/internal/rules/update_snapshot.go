package rules

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Lercas/prowl/tool/internal/localfile"
)

const (
	MaxUpdateSchemaSize = 8 << 20
	MaxUpdateEntries    = 200000
	MaxUpdateInputs     = 2*MaxLibraryFiles + 2
)

type updateFile struct {
	rel string
	raw []byte
}

type updateSnapshot struct {
	files []updateFile
}

// captureUpdate freezes managed files and validation metadata before a validator can see them.
// Every later hash and install uses these bytes, never a second read of the public source.
func captureUpdate(ctx context.Context, dir string) (snapshot *updateSnapshot, err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	snapshot = &updateSnapshot{}
	total, entries, yamlFiles := 0, 0, 0
	err = fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		if rel == ".git" {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		entries++
		if entries > MaxUpdateEntries {
			return fmt.Errorf("update source exceeds %d entries", MaxUpdateEntries)
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink in update source: %s", rel)
		}
		if d.IsDir() {
			if rel == "VERSION" || rel == IntegrityManifestName || filepath.Base(rel) == "SCHEMA.md" {
				return fmt.Errorf("%s must be a regular file", rel)
			}
			return nil
		}
		limit := int64(MaxTemplateSize)
		switch {
		case rel == IntegrityManifestName:
			limit = MaxIntegrityManifestSize
		case rel == "VERSION":
			limit = MaxVersionSize
		case filepath.Base(rel) == "SCHEMA.md":
			limit = MaxUpdateSchemaSize
		case managedFile(rel):
			yamlFiles++
			if yamlFiles > MaxLibraryFiles {
				return fmt.Errorf("update source exceeds %d YAML files", MaxLibraryFiles)
			}
		default:
			return nil
		}
		if len(snapshot.files) >= MaxUpdateInputs {
			return fmt.Errorf("update source exceeds %d selected files", MaxUpdateInputs)
		}
		raw, err := localfile.ReadRootRegular(root, filepath.FromSlash(rel), limit)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		if len(raw) > MaxLibraryBytes-total {
			return fmt.Errorf("update source exceeds %d selected bytes", MaxLibraryBytes)
		}
		total += len(raw)
		snapshot.files = append(snapshot.files, updateFile{rel, raw})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return snapshot, nil
}

func (snapshot *updateSnapshot) hashes() map[string]string {
	out := map[string]string{}
	for _, file := range snapshot.files {
		if !managedFile(file.rel) || filepath.Base(file.rel) == "SCHEMA.md" {
			continue
		}
		sum := sha256.Sum256(file.raw)
		out[file.rel] = hex.EncodeToString(sum[:])
	}
	return out
}

func (snapshot *updateSnapshot) managedHashes() map[string]string {
	out := map[string]string{}
	for _, file := range snapshot.files {
		if managedFile(file.rel) {
			sum := sha256.Sum256(file.raw)
			out[file.rel] = hex.EncodeToString(sum[:])
		}
	}
	return out
}

func (snapshot *updateSnapshot) integrityBytes() ([]byte, error) {
	var b strings.Builder
	for _, file := range snapshot.files {
		if !managedFile(file.rel) || filepath.Base(file.rel) == "SCHEMA.md" {
			continue
		}
		b.WriteString(localfile.SHA256ManifestLine(sha256.Sum256(file.raw), file.rel))
		if b.Len() > MaxIntegrityManifestSize {
			return nil, fmt.Errorf("generated integrity manifest exceeds %d bytes", MaxIntegrityManifestSize)
		}
	}
	return []byte(b.String()), nil
}

// inventoryTarget hashes the actual bounded managed regular files without requiring valid YAML.
// This permits repair of malformed templates while refusing an unmeasurable target before writes.
func inventoryTarget(ctx context.Context, root *os.Root) (map[string]string, error) {
	out := map[string]string{}
	entries, total, yamlFiles := 0, 0, 0
	err := fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}
		entries++
		if entries > MaxUpdateEntries {
			return fmt.Errorf("installed tree exceeds %d entries", MaxUpdateEntries)
		}
		if d.IsDir() || !managedFile(rel) {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("installed managed file %s must be regular, not a link or special file", rel)
		}
		limit := int64(MaxTemplateSize)
		if filepath.Base(rel) == "SCHEMA.md" {
			limit = MaxUpdateSchemaSize
		} else {
			yamlFiles++
			if yamlFiles > MaxLibraryFiles {
				return fmt.Errorf("installed library exceeds %d YAML files", MaxLibraryFiles)
			}
		}
		if len(out) >= MaxUpdateInputs {
			return fmt.Errorf("installed library exceeds %d managed files", MaxUpdateInputs)
		}
		raw, err := localfile.ReadRootRegular(root, filepath.FromSlash(rel), limit)
		if err != nil {
			return err
		}
		if len(raw) > MaxLibraryBytes-total {
			return fmt.Errorf("installed library exceeds %d managed bytes", MaxLibraryBytes)
		}
		total += len(raw)
		sum := sha256.Sum256(raw)
		out[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	return out, err
}

func (snapshot *updateSnapshot) unchanged(other *updateSnapshot) bool {
	if len(snapshot.files) != len(other.files) {
		return false
	}
	for i, file := range snapshot.files {
		if file.rel != other.files[i].rel || !bytes.Equal(file.raw, other.files[i].raw) {
			return false
		}
	}
	return true
}

func writeCaptured(root *os.Root, file updateFile) error {
	parent, name, err := localfile.OpenParent(root, file.rel, true)
	if err != nil {
		return err
	}
	return errors.Join(localfile.WriteRootAtomic(parent, name, file.raw, 0o644), parent.Close())
}

func (snapshot *updateSnapshot) materialize(dir string) (err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	for _, file := range snapshot.files {
		if err := writeCaptured(root, file); err != nil {
			return err
		}
	}
	return nil
}

func (snapshot *updateSnapshot) preflight(root *os.Root) error {
	for _, file := range snapshot.files {
		if !managedFile(file.rel) {
			continue
		}
		parent, name, err := localfile.OpenParent(root, file.rel, false)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if err := errors.Join(localfile.CheckRootDestination(parent, name), parent.Close()); err != nil {
			return err
		}
	}
	return nil
}

func (snapshot *updateSnapshot) install(ctx context.Context, root *os.Root) error {
	if err := snapshot.preflight(root); err != nil {
		return err
	}
	kept := map[string]bool{}
	for _, file := range snapshot.files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !managedFile(file.rel) {
			continue
		}
		if err := writeCaptured(root, file); err != nil {
			return err
		}
		kept[file.rel] = true
	}
	return mirrorDeleteRoot(root, kept)
}

// mirrorDeleteRoot removes only orphaned managed regular files. Enumeration and deletion share
// the same opened root; directory aliases and unmanaged files remain untouched.
func mirrorDeleteRoot(root *os.Root, kept map[string]bool) error {
	var dirs []string
	err := fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			dirs = append(dirs, rel)
			return nil
		}
		if !managedFile(rel) || kept[rel] || !d.Type().IsRegular() {
			return nil
		}
		info, err := root.Lstat(filepath.FromSlash(rel))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		return root.Remove(filepath.FromSlash(rel))
	})
	if err != nil {
		return err
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dirs)))
	for _, rel := range dirs {
		info, err := root.Lstat(filepath.FromSlash(rel))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		entries, err := fs.ReadDir(root.FS(), rel)
		if err == nil && len(entries) == 0 {
			_ = root.Remove(filepath.FromSlash(rel)) // best-effort empty-directory pruning
		}
	}
	return nil
}

func (snapshot *updateSnapshot) version() (string, error) {
	for _, file := range snapshot.files {
		if file.rel == "VERSION" {
			return parseVersion(file.raw)
		}
	}
	return "", nil
}

// validationCopy supplies path-based validators with an owned copy of exactly the captured bytes.
func (snapshot *updateSnapshot) validationCopy() (dir string, err error) {
	dir, err = os.MkdirTemp("", "prowl-update-validation-*")
	if err != nil {
		return "", err
	}
	if err := snapshot.materialize(dir); err != nil {
		return "", errors.Join(err, os.RemoveAll(dir))
	}
	return dir, nil
}
