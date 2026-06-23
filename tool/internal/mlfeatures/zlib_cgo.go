//go:build cgo

package mlfeatures

/*
#cgo LDFLAGS: -lz
#include <zlib.h>
#include <stdlib.h>

// zcomp_len returns the length of zlib.compress(src, level), discarding the
// bytes. Same C library and stream framing as Python, so the length is identical.
static unsigned long zcomp_len(const unsigned char* src, unsigned long srclen, int level) {
    unsigned long bound = compressBound(srclen);
    unsigned char* dst = (unsigned char*)malloc(bound);
    if (dst == NULL) {
        return 0;
    }
    unsigned long dstlen = bound;
    int rc = compress2(dst, &dstlen, src, srclen, level);
    free(dst);
    if (rc != Z_OK) {
        return 0;
    }
    return dstlen;
}
*/
import "C"

import "unsafe"

// zlibCompressedLen returns the byte length of zlib.compress(raw, level=6) via
// the system zlib, matching CPython's output exactly.
func zlibCompressedLen(raw []byte) int {
	if len(raw) == 0 {
		return 0
	}
	p := (*C.uchar)(unsafe.Pointer(&raw[0]))
	// level 6 == Python zlib.compress default.
	n := C.zcomp_len(p, C.ulong(len(raw)), C.int(6))
	return int(n)
}
