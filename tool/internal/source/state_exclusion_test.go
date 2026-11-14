package source

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateStateIsExcludedBeforePhysicalAcquisition(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "private-state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(state, "key.txt")
	write(t, secret, "private key material")
	ordinary := filepath.Join(dir, "app.env")
	write(t, ordinary, "API_KEY=ordinary")
	ctx := WithStateDirectory(t.Context(), state)
	var paths []string
	for item := range Filesystem(ctx, []string{dir}, nil, 1024) {
		if item.Error != nil {
			t.Fatal(item.Error)
		}
		paths = append(paths, item.Path)
	}
	if len(paths) != 1 || !strings.HasSuffix(paths[0], "app.env") {
		t.Fatalf("private state entered scan: %v", paths)
	}
	for item := range FilesFromList(ctx, []string{secret}, 1024) {
		t.Fatalf("explicit state path entered scan: %s", item.Path)
	}
	alias := filepath.Join(dir, "alias.txt")
	if err := os.Symlink(secret, alias); err != nil {
		t.Skip("symlink unavailable")
	}
	for item := range Filesystem(ctx, []string{alias}, nil, 1024) {
		t.Fatalf("state alias entered scan: %s", item.Path)
	}
	if stateDirectoryExcluded(ctx, ordinary) {
		t.Fatal("ordinary file excluded")
	}
}

func TestPrivateStateCaseAliasOnCaseInsensitiveFilesystems(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "private-state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "PRIVATE-STATE")
	a, err := os.Stat(alias)
	if err != nil {
		t.Skip("case-sensitive filesystem")
	}
	b, err := os.Stat(state)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(a, b) {
		t.Skip("distinct case-sensitive directories")
	}
	file := filepath.Join(alias, "key.txt")
	write(t, filepath.Join(state, "key.txt"), "private state contents")
	for item := range Filesystem(WithStateDirectory(t.Context(), state), []string{file}, nil, 1024) {
		t.Fatalf("case alias entered physical scan: %s", item.Path)
	}
}

func TestPrivateStateDoesNotHideDistinctCaseSensitiveSibling(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "private-state")
	other := filepath.Join(root, "PRIVATE-STATE")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(other, 0o700); os.IsExist(err) {
		t.Skip("case-insensitive filesystem")
	} else if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(other, "app.env")
	write(t, path, "legitimate code source")
	if stateDirectoryExcluded(WithStateDirectory(t.Context(), state), path) {
		t.Fatal("distinct case-sensitive source was excluded")
	}
}
