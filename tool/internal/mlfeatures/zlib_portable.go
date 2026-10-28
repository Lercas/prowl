//go:build !cgo

package mlfeatures

import (
	"context"
	_ "embed"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// Only our immutable compressor bytecode executes here, never scanner input.
//
//go:embed zlib_length.wasm
var zlibModule []byte

var compressionOnce sync.Once
var compressionSlots chan *compressor
var compressionError error

type compressor struct {
	module  api.Module
	fn      api.Function
	pointer uint32
}

func initCompression() {
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithMemoryLimitPages(256))
	compiled, err := r.CompileModule(ctx, zlibModule)
	if err != nil {
		compressionError = err
		return
	}
	// WASI is instantiated without env, filesystem, network or process arguments.
	if _, err = wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		compressionError = err
		return
	}
	compressionSlots = make(chan *compressor, 4)
	for range 4 {
		m, err := r.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName(""))
		if err != nil {
			compressionError = err
			return
		}
		ptr, err := m.ExportedFunction("input_ptr").Call(ctx)
		if err != nil {
			compressionError = err
			return
		}
		compressionSlots <- &compressor{m, m.ExportedFunction("compressed_len"), uint32(ptr[0])}
	}
}
func wasmCompressedLen(raw []byte) int {
	if len(raw) == 0 {
		return 0
	}
	if len(raw) > 1<<20 {
		panic("ML compression input exceeds budget")
	}
	compressionOnce.Do(initCompression)
	if compressionError != nil {
		panic("ML compression runtime unavailable")
	}
	c := <-compressionSlots
	defer func() { compressionSlots <- c }()
	if !c.module.Memory().Write(c.pointer, raw) {
		panic("ML compression memory budget exceeded")
	}
	result, err := c.fn.Call(context.Background(), uint64(len(raw)))
	if err != nil || len(result) != 1 || result[0] == 0 {
		panic("ML compression failed")
	}
	return int(result[0])
}
