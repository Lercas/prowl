// Package bundle checks immutable embedded YAML snapshots against their manifest.
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"path"
	"strings"
)

func Verify(files fs.FS) error {
	manifest, err := fs.ReadFile(files, "MANIFEST.sha256")
	if err != nil {
		return err
	}
	listed := map[string]string{}
	for _, line := range strings.Split(string(manifest), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 64 {
			return errors.New("invalid embedded manifest")
		}
		name := strings.TrimPrefix(fields[1], "*")
		if !fs.ValidPath(name) || listed[name] != "" {
			return errors.New("invalid embedded manifest path")
		}
		listed[name] = fields[0]
	}
	if len(listed) == 0 {
		return errors.New("empty embedded manifest")
	}
	for name, want := range listed {
		raw, err := fs.ReadFile(files, name)
		if err != nil {
			return err
		}
		h := sha256.Sum256(raw)
		if hex.EncodeToString(h[:]) != want {
			return errors.New("embedded snapshot hash mismatch")
		}
	}
	return fs.WalkDir(files, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (path.Ext(name) == ".yaml" || path.Ext(name) == ".yml") && listed[name] == "" {
			return errors.New("unlisted embedded template")
		}
		return nil
	})
}
