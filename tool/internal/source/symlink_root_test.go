package source

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestExplicitSymlinkDirectoryRootIsScanned(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires an optional Windows privilege")
	}
	dir := t.TempDir()
	actual := filepath.Join(dir, "actual")
	link := filepath.Join(dir, "chosen")
	if err := os.Mkdir(actual, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(actual, "config.env"), []byte("KEY=\x41KIANAFGYOEYPXU1DSYP"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(actual, link); err != nil {
		t.Fatal(err)
	}
	cov := model.NewCoverage()
	var items []model.Item
	for item := range Filesystem(model.WithCoverage(context.Background(), cov), []string{link}, nil, 4096) {
		items = append(items, item)
	}
	if len(items) != 1 || items[0].Path != filepath.Join(link, "config.env") {
		t.Fatal("explicit directory symlink yielded a false clean scan")
	}
	if complete, _, _ := cov.Snapshot(); !complete {
		t.Fatal("valid symlink root considered incomplete")
	}
}
