package post

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestCancelledBaselinePreservesPreviousList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(path, []byte(`["previous"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WriteBaselineContext(ctx, path, []model.Finding{{Fingerprint: "novel"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled baseline returned %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != `["previous"]` {
		t.Fatal("cancelled baseline changed accepted list")
	}
}
