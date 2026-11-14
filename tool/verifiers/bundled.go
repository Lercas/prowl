// Package bundledverifiers holds the binary-anchored offline verifier snapshot.
package bundledverifiers

import "embed"

//go:embed *.yaml MANIFEST.sha256
var Files embed.FS
