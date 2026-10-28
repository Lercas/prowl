package verify

import (
	"fmt"
	"io/fs"
	"path"
	"time"

	"github.com/Lercas/prowl/tool/internal/bundle"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"gopkg.in/yaml.v3"
)

// LoadEmbedded trusts only the bytes anchored in the binary's embedded manifest.
func LoadEmbedded(timeout time.Duration, files fs.FS) (*Set, error) {
	if err := bundle.Verify(files); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	s := &Set{client: safehttp.Client(timeout), sem: make(chan struct{}, concurrency)}
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
		var v Verifier
		if err := yaml.Unmarshal(raw, &v); err != nil {
			return err
		}
		if v.ID == "" || len(v.Match) == 0 || len(v.Requests) == 0 {
			return fmt.Errorf("invalid embedded verifier")
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
		return nil
	})
	return s, err
}
