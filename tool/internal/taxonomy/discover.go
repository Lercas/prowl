package taxonomy

import (
	"fmt"
	"strings"

	"github.com/Lercas/prowl/tool/internal/localfile"
)

// DiscoverGitleaks selects the workspace's first gitleaks policy, preserving precedence even when
// that file is broken. CLI and LSP use the same selection and loader.
func DiscoverGitleaks() (string, error) {
	return localfile.FirstExisting(".gitleaks.toml", "gitleaks.toml")
}

// RequireComplete rejects a partially compiled taxonomy on executing paths. Low-level loaders
// retain Skipped for validators and migration diagnostics.
func RequireComplete(t *Taxonomy) error {
	if len(t.Skipped) > 0 {
		return fmt.Errorf("unsupported or invalid regex in %s", strings.Join(t.Skipped, ", "))
	}
	return nil
}
