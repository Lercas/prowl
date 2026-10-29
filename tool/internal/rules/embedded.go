package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"

	"github.com/Lercas/prowl/tool/internal/bundle"
	"gopkg.in/yaml.v3"
)

// LoadEmbedded requires the binary-anchored manifest and rejects duplicate IDs.
func LoadEmbedded(files fs.FS) (*Engine, error) {
	if err := bundle.Verify(files); err != nil {
		return nil, err
	}
	e := &Engine{bundled: true}
	seen := map[string]bool{}
	err := fs.WalkDir(files, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || path.Ext(name) != ".yaml" {
			return nil
		}
		raw, err := fs.ReadFile(files, name)
		if err != nil {
			return err
		}
		if len(raw) > MaxTemplateSize {
			return fmt.Errorf("embedded rule template too large")
		}
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		for {
			var t Template
			if err := dec.Decode(&t); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return fmt.Errorf("embedded/%s: %w", name, err)
			}
			if t.isZero() {
				continue
			}
			t.path = "embedded/" + name
			if err := t.compile(); err != nil {
				return err
			}
			if seen[t.ID] {
				return fmt.Errorf("duplicate embedded rule ID")
			}
			seen[t.ID] = true
			e.templates = append(e.templates, &t)
		}
		return nil
	})
	return e, err
}
