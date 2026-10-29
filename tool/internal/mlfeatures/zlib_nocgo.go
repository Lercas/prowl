//go:build !cgo

package mlfeatures

// zlibCompressedLen uses the same zlib level-6 compressor as the training
// reference inside a memory-bounded, embedded WebAssembly module.
func zlibCompressedLen(raw []byte) int {
	return wasmCompressedLen(raw)
}
