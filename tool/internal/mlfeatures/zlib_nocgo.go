//go:build !cgo

package mlfeatures

import (
	"bytes"
	"compress/zlib"
)

// zlibCompressedLen returns the byte length of Go's compress/zlib output at
// level 6. Go's pure-Go DEFLATE is NOT byte-compatible with CPython's C zlib
// (typically 4-6 bytes larger), so compression_ratio only approximates Python;
// build with cgo for exact parity. This fallback exists only so the package
// still builds where cgo is unavailable.
func zlibCompressedLen(raw []byte) int {
	if len(raw) == 0 {
		return 0
	}
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, 6)
	if err != nil {
		panic(err)
	}
	if _, err := w.Write(raw); err != nil {
		panic(err)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return buf.Len()
}
