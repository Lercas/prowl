// Package checkedio enforces the io.Writer count contract before buffered protocol output.
package checkedio

import (
	"errors"
	"io"
)

var errInvalidCount = errors.New("invalid writer byte count")

type writer struct{ output io.Writer }

// NewWriter turns a nil-error short write into io.ErrShortWrite and rejects impossible counts.
// This prevents bufio from retrying an ambiguous partial frame or looping on a zero-byte write.
func NewWriter(output io.Writer) io.Writer { return writer{output: output} }

func (w writer) Write(p []byte) (int, error) {
	n, err := w.output.Write(p)
	if n < 0 || n > len(p) {
		return 0, errInvalidCount
	}
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}
