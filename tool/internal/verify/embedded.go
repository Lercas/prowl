package verify

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"time"

	"github.com/Lercas/prowl/tool/internal/bundle"
	"gopkg.in/yaml.v3"
)

// LoadEmbedded trusts only the immutable snapshot anchored in the binary's manifest.
// Loading compiles policy without contacting any provider.
func LoadEmbedded(timeout time.Duration, files fs.FS) (*Set, error) {
	return LoadEmbeddedWithOptions(timeout, files, Options{Concurrency: currentConcurrency()})
}

func LoadEmbeddedWithOptions(timeout time.Duration, files fs.FS, options Options) (*Set, error) {
	if err := bundle.Verify(files); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	s := NewWithOptions(timeout, options)
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
		if len(raw) > MaxVerifierSize {
			return fmt.Errorf("embedded verifier too large")
		}
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		for {
			var doc yaml.Node
			if err := dec.Decode(&doc); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return fmt.Errorf("embedded/%s: %w", name, err)
			}
			if len(doc.Content) == 0 || doc.Content[0].Tag == "!!null" {
				continue
			}
			data, err := yaml.Marshal(&doc)
			if err != nil {
				return err
			}
			strict := yaml.NewDecoder(bytes.NewReader(data))
			strict.KnownFields(true)
			var v Verifier
			if err := strict.Decode(&v); err != nil {
				return fmt.Errorf("embedded/%s: %w", name, err)
			}
			if seen[v.ID] {
				return fmt.Errorf("duplicate embedded verifier")
			}
			seen[v.ID] = true
			v.path = "embedded/" + name
			if err := compileVerifier(&v); err != nil {
				return err
			}
			s.verifiers = append(s.verifiers, &v)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}
