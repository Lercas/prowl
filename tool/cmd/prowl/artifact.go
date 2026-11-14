package main

import (
	"io"
	"io/fs"
	"os"

	"github.com/Lercas/prowl/tool/internal/localfile"
)

func writeArtifactBytes(path string, raw []byte, mode fs.FileMode) error {
	if path != "" {
		return localfile.WriteAtomicBytes(path, raw, mode)
	}
	n, err := os.Stdout.Write(raw)
	if err == nil && n != len(raw) {
		return io.ErrShortWrite
	}
	return err
}
