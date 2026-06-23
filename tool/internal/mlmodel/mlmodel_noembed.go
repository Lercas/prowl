//go:build noml_embed

package mlmodel

// Lean build (-tags noml_embed): no model baked in, so Load() returns
// ErrNoEmbedded and the ML stage needs an external model via --ml-model PATH or
// ~/.prowl/model_binary.json.
var embedded []byte
