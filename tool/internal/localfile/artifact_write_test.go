package localfile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestStreamingAtomicFailurePreservesPreviousFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report")
	if err := os.WriteFile(path, []byte("previous artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := errors.New("owned renderer failure")
	err := WriteAtomic(path, 0o600, func(w io.Writer) error {
		if _, err := io.WriteString(w, "incomplete replacement"); err != nil {
			return err
		}
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("lost renderer failure: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "previous artifact" {
		t.Fatal("failed streaming write changed the old artifact")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("failed streaming write leaked an owned temporary file")
	}
}

func TestArtifactWriterKeepsItsSelectedParentDuringRendering(t *testing.T) {
	parent := t.TempDir()
	dir, moved := filepath.Join(parent, "selected"), filepath.Join(parent, "moved")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	err := WriteAtomic(filepath.Join(dir, "report"), 0o600, func(w io.Writer) error {
		if err := os.Rename(dir, moved); err != nil {
			return err
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "report"), []byte("replacement pathname sentinel"), 0o600); err != nil {
			return err
		}
		_, err := io.WriteString(w, "captured parent artifact")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		filepath.Join(moved, "report"): "captured parent artifact",
		filepath.Join(dir, "report"):   "replacement pathname sentinel",
	} {
		raw, err := os.ReadFile(path)
		if err != nil || string(raw) != want {
			t.Fatalf("artifact followed a replaced parent pathname: %s", path)
		}
	}
}

func TestArtifactPathPreservesAliasThenParentResolution(t *testing.T) {
	parent := t.TempDir()
	work, external := filepath.Join(parent, "work"), filepath.Join(parent, "external")
	for _, dir := range []string{work, filepath.Join(external, "nested")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(work, "alias")
	if err := os.Symlink(filepath.Join(external, "nested"), alias); err != nil {
		t.Skipf("directory aliases unavailable: %v", err)
	}
	rawPath := alias + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "report"
	if err := WriteAtomicBytes(rawPath, []byte("expected parent"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(external, "report"))
	if err != nil || string(raw) != "expected parent" {
		t.Fatal("artifact path was cleaned into a different parent")
	}
	if _, err := os.Stat(filepath.Join(work, "report")); !os.IsNotExist(err) {
		t.Fatal("artifact was written to the lexical parent of the alias")
	}
}
