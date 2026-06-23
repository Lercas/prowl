//go:build !noml_embed

package mlmodel

import _ "embed"

// The default build bakes the model into the binary so --ml works with zero
// setup. Use -tags noml_embed for a lean binary without it.
//
//go:embed model_binary.json
var embedded []byte
