package localfile

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicCancellationPreservesArtifactAndCleansTemporaryFile(t *testing.T) {
	for _, before := range []bool{true, false} {
		dir := t.TempDir()
		path := filepath.Join(dir, "artifact")
		if err := os.WriteFile(path, []byte("previous owned artifact"), 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		if before {
			cancel()
		}
		called := false
		err := WriteAtomicContext(ctx, path, 0o600, func(w io.Writer) error {
			called = true
			if _, err := io.WriteString(w, "rendered replacement"); err != nil {
				return err
			}
			cancel() // A successful renderer does not authorize commit after cancellation.
			return nil
		})
		cancel()
		if !errors.Is(err, context.Canceled) || called == before {
			t.Fatalf("before=%v called=%v error=%v", before, called, err)
		}
		raw, err := os.ReadFile(path)
		if err != nil || string(raw) != "previous owned artifact" {
			t.Fatal("cancelled replacement changed previous artifact")
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 1 {
			t.Fatal("cancelled replacement leaked an owned temporary file")
		}
	}
}
