package taxonomy

import (
	_ "embed"
	"fmt"

	"github.com/Lercas/prowl/tool/internal/saferegex"
	"gopkg.in/yaml.v3"
)

//go:embed secret_taxonomy.yaml
var embedded []byte

// DefaultYAML returns the built-in taxonomy source.
func DefaultYAML() []byte { return embedded }

// LoadDefault parses the taxonomy embedded in the binary.
func LoadDefault() (*Taxonomy, error) {
	var t Taxonomy
	if err := yaml.Unmarshal(embedded, &t); err != nil {
		return nil, fmt.Errorf("parse embedded taxonomy: %w", err)
	}
	compiled := t.Types[:0]
	for _, st := range t.Types {
		// saferegex keeps compilation consistent with the on-disk loaders; the bundled patterns are
		// all well under the limits, so this never skips a built-in type.
		re, err := saferegex.Compile(st.Detection.Regex)
		if err != nil {
			t.Skipped = append(t.Skipped, st.ID)
			continue
		}
		st.RE = re
		compiled = append(compiled, st)
	}
	t.Types = compiled
	return &t, nil
}
