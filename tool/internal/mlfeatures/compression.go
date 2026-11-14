package mlfeatures

import (
	"sync"

	"github.com/klauspost/compress/flate"
)

// The versioned feature name prevents old zlib-trained external models from
// silently scoring a different feature distribution.
const CompressionFeature = "compression_ratio_go_flate_v1"

type compressionCounter struct{ n int }

func (c *compressionCounter) Write(p []byte) (int, error) {
	c.n += len(p)
	return len(p), nil
}

type compressor struct {
	count  compressionCounter
	writer *flate.Writer
}

var compressorPool = sync.Pool{New: func() any {
	c := new(compressor)
	w, err := flate.NewWriter(&c.count, 6)
	if err != nil {
		panic(err) // constant compression level; unreachable
	}
	c.writer = w
	return c
}}

// flateCompressedLen is the canonical training and inference implementation.
// Each stream is raw DEFLATE, level 6, fully closed before measuring its size.
func flateCompressedLen(raw []byte) int {
	c := compressorPool.Get().(*compressor)
	defer compressorPool.Put(c)
	c.count.n = 0
	c.writer.Reset(&c.count)
	if _, err := c.writer.Write(raw); err != nil {
		panic(err) // the counting writer cannot fail
	}
	if err := c.writer.Close(); err != nil {
		panic(err)
	}
	return c.count.n
}
