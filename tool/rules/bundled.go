// Package bundledrules holds the offline rule snapshot carried by release binaries.
package bundledrules

import "embed"

//go:embed */*.yaml MANIFEST.sha256
var Files embed.FS
