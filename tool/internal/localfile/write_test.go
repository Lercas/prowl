package localfile

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicWriterKeepsTheOpenedDirectory(t *testing.T) {
	parent := t.TempDir()
	dir, moved := filepath.Join(parent, "selected"), filepath.Join(parent, "moved")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Rename(dir, moved); err != nil {
		t.Skipf("opened directory rename unavailable: %v", err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteRootAtomic(root, "manifest", []byte("captured root"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(moved, "manifest"))
	if err != nil || string(raw) != "captured root" {
		t.Fatalf("write left the captured directory: err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "manifest")); !os.IsNotExist(err) {
		t.Fatal("write followed a replacement of the selected pathname")
	}
	entries, err := os.ReadDir(moved)
	if err != nil || len(entries) != 1 {
		t.Fatalf("atomic write left temporary files: entries=%v err=%v", entries, err)
	}
	info, err := os.Stat(filepath.Join(moved, "manifest"))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("public manifest permissions lost: info=%v err=%v", info, err)
	}
}

func TestAtomicWriterRefusesUnsafeDestinationsWithoutChangingThem(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Mkdir(filepath.Join(dir, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"directory", ".", "../outside", filepath.Join("nested", "manifest"), filepath.Join(dir, "absolute")} {
		if err := WriteRootAtomic(root, name, []byte("owned"), 0o644); err == nil {
			t.Errorf("unsafe destination %q accepted", name)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "directory" {
		t.Fatalf("rejected writes changed the directory: entries=%v err=%v", entries, err)
	}
}

func TestSHA256FilenameEscapesAndDuplicateNormalization(t *testing.T) {
	sum := sha256.Sum256([]byte("owned"))
	for _, name := range []string{" leading  spaces.yaml", "*literal.yaml", "line\nbreak.yaml", "carriage\rreturn.yaml", `back\slash.yaml`} {
		line := SHA256ManifestLine(sum, name)
		parsed, err := ParseSHA256Manifest([]byte(line), "owned-manifest")
		if err != nil || len(parsed) != 1 || parsed[filepath.ToSlash(name)] == "" {
			t.Fatalf("filename changed during round trip: name=%q parsed=%v err=%v", name, parsed, err)
		}
	}
	checksum := strings.Repeat("0", 64)
	for _, line := range []string{`\` + checksum + `  trailing\`, `\` + checksum + `  unknown\t.yaml`, `\` + checksum + `  ../outside\n.yaml`} {
		if _, err := ParseSHA256Manifest([]byte(line+"\n"), "owned-manifest"); err == nil {
			t.Errorf("unsafe or invalid escape accepted: %q", line)
		}
	}
	// An escaped line and an ordinary line naming the same file cannot override each other.
	if _, err := ParseSHA256Manifest([]byte(checksum+"  owned.yaml\n\\"+checksum+"  owned.yaml\n"), "owned-manifest"); err == nil {
		t.Fatal("duplicate entry bypassed detection using the escaped line prefix")
	}
}
