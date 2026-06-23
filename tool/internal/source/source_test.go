package source

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/Lercas/prowl/tool/internal/model"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func drain(ch <-chan model.Item) map[string]model.Item {
	out := map[string]model.Item{}
	for it := range ch {
		out[filepath.Base(it.Path)] = it
	}
	return out
}

func TestFilesystemWalkFiltering(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.py"), `AWS = "x"`)
	write(t, filepath.Join(dir, "README.md"), "docs")
	write(t, filepath.Join(dir, "node_modules", "lib.js"), "skipdir")
	write(t, filepath.Join(dir, "logo.png"), "skipext")
	write(t, filepath.Join(dir, "bin.dat"), "abc\x00\x00def") // binary (null bytes)
	write(t, filepath.Join(dir, "big.go"), strings.Repeat("x", 5000))
	write(t, filepath.Join(dir, "skipme.txt"), "excluded by substr")

	got := drain(Filesystem(context.Background(), []string{dir}, []string{"skipme"}, 1000)) // maxSize 1000 -> big.go skipped

	if _, ok := got["a.py"]; !ok {
		t.Error("a.py should be scanned")
	}
	if got["README.md"].Source != "file" {
		t.Errorf("README.md source = %q, want file", got["README.md"].Source)
	}
	if got["a.py"].Source != "code" {
		t.Error("a.py source should be code")
	}
	for _, skip := range []string{"lib.js", "logo.png", "bin.dat", "big.go", "skipme.txt"} {
		if _, ok := got[skip]; ok {
			t.Errorf("%s should have been skipped (dir/ext/binary/size/exclude)", skip)
		}
	}
}

// TestFilesystemEmitsLockFiles: dependency-lock manifests (go.sum, *.lock, …) must be emitted for
// scanning, not blind-skipped (the scan layer drops only their generic hash noise).
func TestFilesystemEmitsLockFiles(t *testing.T) {
	dir := t.TempDir()
	// Lockfiles are emitted (not skipped) so a real credential in one — a private-registry URL in
	// package-lock.json — is still caught; the scan layer suppresses only the hash noise.
	write(t, filepath.Join(dir, "go.sum"), "github.com/x/y v1.2.3 h1:vj9j2Cgf8Vt3vZh7M3DM6vL7c8jc7E0YQ8Ksa8yLU=\n")
	write(t, filepath.Join(dir, "package-lock.json"), `{"lockfileVersion":3}`)
	write(t, filepath.Join(dir, "composer.lock"), `{"content-hash":"deadbeef"}`)
	write(t, filepath.Join(dir, "go.mod"), "module example.com/x\n")
	write(t, filepath.Join(dir, "main.go"), `key = "AKIANAFGYOEYPXU1DSYP"`)

	got := drain(Filesystem(context.Background(), []string{dir}, nil, 1<<20))

	for _, f := range []string{"go.sum", "package-lock.json", "composer.lock", "go.mod", "main.go"} {
		if _, ok := got[f]; !ok {
			t.Errorf("%s must be emitted for scanning (lockfiles are no longer blind-skipped)", f)
		}
	}
}

func TestLooksBinaryAndSourceType(t *testing.T) {
	if !looksBinary([]byte("text\x00more")) {
		t.Error("null byte should mark binary")
	}
	if looksBinary([]byte("plain text only")) {
		t.Error("plain text wrongly marked binary")
	}
	if sourceForPath("a/b/c.md") != "file" || sourceForPath("a/b/c.go") != "code" {
		t.Error("sourceForPath mapping wrong")
	}
}

// utf16BOM encodes s as UTF-16 with a leading byte-order mark (le=true -> FF FE little-endian).
func utf16BOM(s string, le bool) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, 2+len(units)*2)
	if le {
		out = append(out, 0xFF, 0xFE)
	} else {
		out = append(out, 0xFE, 0xFF)
	}
	buf := make([]byte, 2)
	for _, u := range units {
		if le {
			binary.LittleEndian.PutUint16(buf, u)
		} else {
			binary.BigEndian.PutUint16(buf, u)
		}
		out = append(out, buf...)
	}
	return out
}

// TestScannableTextUTF16: a BOM-marked UTF-16 file (NUL every other byte) must be transcoded to UTF-8
// and reported scannable, not misclassified as binary.
func TestScannableTextUTF16(t *testing.T) {
	const secret = `aws_access_key_id = "AKIA4MNQ2RST7UVWX9YZ"`
	// Sanity: the raw UTF-16 bytes would trip the old binary check.
	leBytes := utf16BOM(secret, true)
	if !looksBinary(leBytes) {
		t.Fatal("precondition: raw UTF-16-LE bytes should look binary (NUL every other byte)")
	}
	for _, tc := range []struct {
		name string
		le   bool
	}{{"LE", true}, {"BE", false}} {
		t.Run(tc.name, func(t *testing.T) {
			text, ok := scannableText(utf16BOM(secret, tc.le))
			if !ok {
				t.Fatal("UTF-16 file should be scannable after transcoding, not skipped as binary")
			}
			if string(text) != secret {
				t.Fatalf("transcoded text = %q, want %q", text, secret)
			}
		})
	}

	// A plain UTF-8/ASCII file is returned unchanged.
	if text, ok := scannableText([]byte(secret)); !ok || string(text) != secret {
		t.Fatalf("plain ASCII: got (%q,%v), want (%q,true)", text, ok, secret)
	}
	// Genuinely binary content (embedded NUL, no UTF-16 BOM) is still skipped.
	if _, ok := scannableText([]byte("text\x00more")); ok {
		t.Error("binary content without a BOM should still be skipped")
	}
}

// TestFilesystemScansUTF16File: end-to-end, a secret in a UTF-16-LE-with-BOM file on disk must be
// emitted by the filesystem walk.
func TestFilesystemScansUTF16File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.cs")
	if err := os.WriteFile(path, utf16BOM(`key = "AKIA4MNQ2RST7UVWX9YZ"`, true), 0o644); err != nil {
		t.Fatal(err)
	}
	got := drain(Filesystem(context.Background(), []string{dir}, nil, 1<<20))
	it, ok := got["secret.cs"]
	if !ok {
		t.Fatal("UTF-16 file should be scanned, not silently skipped as binary")
	}
	if !strings.Contains(it.Text, "AKIA4MNQ2RST7UVWX9YZ") {
		t.Errorf("emitted text missing the secret; got %q", it.Text)
	}
}

func TestFilesFromList(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.py")
	write(t, p, `K = "secret"`)
	got := drain(FilesFromList(context.Background(), []string{p, filepath.Join(dir, "missing.py")}, 1<<20))
	if _, ok := got["x.py"]; !ok || len(got) != 1 {
		t.Errorf("FilesFromList should yield exactly the existing file, got %d", len(got))
	}
}

const encSecret = `aws_access_key_id = "AKIA4MNQ2RST7UVWX9YZ"`

// utf16NoBOM encodes s as UTF-16 with NO byte-order mark (le=true -> little-endian).
func utf16NoBOM(s string, le bool) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2)
	buf := make([]byte, 2)
	for _, u := range units {
		if le {
			binary.LittleEndian.PutUint16(buf, u)
		} else {
			binary.BigEndian.PutUint16(buf, u)
		}
		out = append(out, buf...)
	}
	return out
}

// utf32BOM encodes s as UTF-32 with a leading byte-order mark (le=true -> FF FE 00 00 little-endian).
func utf32BOM(s string, le bool) []byte {
	out := make([]byte, 0, 4+len([]rune(s))*4)
	if le {
		out = append(out, 0xFF, 0xFE, 0x00, 0x00)
	} else {
		out = append(out, 0x00, 0x00, 0xFE, 0xFF)
	}
	buf := make([]byte, 4)
	for _, r := range []rune(s) {
		if le {
			binary.LittleEndian.PutUint32(buf, uint32(r))
		} else {
			binary.BigEndian.PutUint32(buf, uint32(r))
		}
		out = append(out, buf...)
	}
	return out
}

// TestScannableTextBOMlessUTF16: a BOM-less UTF-16 source (common from Windows tooling) must be
// heuristically detected, transcoded to UTF-8, and reported scannable in both endiannesses.
func TestScannableTextBOMlessUTF16(t *testing.T) {
	for _, tc := range []struct {
		name string
		le   bool
	}{{"LE", true}, {"BE", false}} {
		t.Run(tc.name, func(t *testing.T) {
			raw := utf16NoBOM(encSecret, tc.le)
			if !looksBinary(raw) {
				t.Fatal("precondition: raw BOM-less UTF-16 bytes should look binary (NUL every other byte)")
			}
			text, ok := scannableText(raw)
			if !ok {
				t.Fatal("BOM-less UTF-16 must be scannable after heuristic transcoding, not skipped as binary")
			}
			if string(text) != encSecret {
				t.Fatalf("transcoded text = %q, want %q", text, encSecret)
			}
		})
	}
}

// TestScannableTextUTF32: UTF-32 BOM files must transcode correctly in both endiannesses. UTF-32-LE
// starts with the UTF-16-LE BOM bytes (FF FE), so the UTF-32 check must run first.
func TestScannableTextUTF32(t *testing.T) {
	for _, tc := range []struct {
		name string
		le   bool
	}{{"LE", true}, {"BE", false}} {
		t.Run(tc.name, func(t *testing.T) {
			text, ok := scannableText(utf32BOM(encSecret, tc.le))
			if !ok {
				t.Fatal("UTF-32 file should be scannable after transcoding, not skipped/garbled")
			}
			if string(text) != encSecret {
				t.Fatalf("UTF-32 transcoded text = %q, want %q", text, encSecret)
			}
		})
	}
}

// TestScannableTextNoOverCorrection: a genuinely binary blob (NULs across both parities, as in a real
// PNG/ELF) must not be mistaken for BOM-less UTF-16 and transcoded to garbage; it must still be skipped.
func TestScannableTextNoOverCorrection(t *testing.T) {
	// PNG signature followed by NULs on both even and odd positions (real binary shape).
	binBlob := append([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, make([]byte, 256)...)
	binBlob = append(binBlob, []byte{0x01, 0x00, 0x02, 0x00, 0xFF, 0xFE, 0x03}...)
	if _, ok := scannableText(binBlob); ok {
		t.Error("a real binary (NULs on both parities) must still be skipped, not transcoded to garbage")
	}
	// Plain ASCII unchanged.
	if text, ok := scannableText([]byte(encSecret)); !ok || string(text) != encSecret {
		t.Fatalf("plain ASCII: got (%q,%v), want (%q,true)", text, ok, encSecret)
	}
	// A short file with a single stray NUL (not the every-other-byte UTF-16 pattern) is still binary.
	if _, ok := scannableText([]byte("hello\x00world here is text")); ok {
		t.Error("stray-NUL content (not UTF-16 pattern) must still be skipped as binary")
	}
}

// TestFilesystemScansBOMlessUTF16File: end-to-end, a secret in a BOM-less UTF-16-LE file on disk must
// be emitted by the filesystem walk.
func TestFilesystemScansBOMlessUTF16File(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret.cs"), utf16NoBOM(encSecret, true), 0o644); err != nil {
		t.Fatal(err)
	}
	got := drain(Filesystem(context.Background(), []string{dir}, nil, 1<<20))
	it, ok := got["secret.cs"]
	if !ok {
		t.Fatal("BOM-less UTF-16 file should be scanned, not silently skipped as binary")
	}
	if !strings.Contains(it.Text, "AKIA4MNQ2RST7UVWX9YZ") {
		t.Errorf("emitted text missing the secret; got %q", it.Text)
	}
}

// TestFilesystemFollowsExplicitSymlinkRoot: an explicitly-named symlink root is followed, while a
// symlink discovered inside a walked tree stays refused (scope-escape guard).
func TestFilesystemFollowsExplicitSymlinkRoot(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.py")
	write(t, real, encSecret)
	link := filepath.Join(dir, "link.py")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	// Explicit symlink root -> followed, secret emitted under the link's path.
	got := drain(Filesystem(context.Background(), []string{link}, nil, 1<<20))
	it, ok := got["link.py"]
	if !ok {
		t.Fatal("an explicitly-named symlink root must be followed, not silently dropped")
	}
	if !strings.Contains(it.Text, "AKIA4MNQ2RST7UVWX9YZ") {
		t.Errorf("followed symlink text missing the secret; got %q", it.Text)
	}

	// In-tree symlink discovered by the walk -> still refused (scope-escape guard kept).
	tree := filepath.Join(dir, "tree")
	write(t, filepath.Join(tree, "normal.py"), "x = 1")
	if err := os.Symlink(real, filepath.Join(tree, "intree.py")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	got2 := drain(Filesystem(context.Background(), []string{tree}, nil, 1<<20))
	if _, leaked := got2["intree.py"]; leaked {
		t.Error("an in-tree symlink must stay refused (scope-escape protection)")
	}
}

// TestFilesFromListFollowsSymlink: an explicitly-listed symlink (a FilesFromList entry) is followed,
// not silently dropped.
func TestFilesFromListFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.py")
	write(t, real, encSecret)
	link := filepath.Join(dir, "link.py")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	got := drain(FilesFromList(context.Background(), []string{link}, 1<<20))
	it, ok := got["link.py"]
	if !ok {
		t.Fatal("FilesFromList must follow an explicitly-listed symlink, not drop it silently")
	}
	if !strings.Contains(it.Text, "AKIA4MNQ2RST7UVWX9YZ") {
		t.Errorf("followed symlink text missing the secret; got %q", it.Text)
	}
}

// TestFilesystemDefaultSkipDirOverride: a default-skip dir (build/) is pruned during a normal walk but
// scanned when named explicitly as the root.
func TestFilesystemDefaultSkipDirOverride(t *testing.T) {
	dir := t.TempDir()
	build := filepath.Join(dir, "build")
	write(t, filepath.Join(build, "leaked.py"), encSecret)
	write(t, filepath.Join(dir, "main.py"), "x = 1")

	// Normal walk: build/ is pruned (leaked.py not emitted).
	got := drain(Filesystem(context.Background(), []string{dir}, nil, 1<<20))
	if _, ok := got["leaked.py"]; ok {
		t.Error("build/ should be pruned during a normal walk")
	}
	// Explicit build/ root: override, leaked.py IS scanned.
	got2 := drain(Filesystem(context.Background(), []string{build}, nil, 1<<20))
	it, ok := got2["leaked.py"]
	if !ok {
		t.Fatal("naming build/ explicitly as a root must scan it (override the default skip)")
	}
	if !strings.Contains(it.Text, "AKIA4MNQ2RST7UVWX9YZ") {
		t.Errorf("explicit build/ scan missing the secret; got %q", it.Text)
	}
}

// TestDecodeUTF32BOM unit-checks the ordered detection: UTF-32-LE (FF FE 00 00) must be decoded as
// UTF-32, not mistaken for UTF-16-LE (FF FE …).
func TestDecodeUTF32BOM(t *testing.T) {
	le := utf32BOM("AB", true)
	dec, ok := decodeUTF32BOM(le)
	if !ok || string(dec) != "AB" {
		t.Fatalf("UTF-32-LE decode = (%q,%v), want (\"AB\",true)", dec, ok)
	}
	// A UTF-16-LE BOM (FF FE) without the trailing 00 00 must NOT be taken as UTF-32.
	if _, ok := decodeUTF32BOM([]byte{0xFF, 0xFE, 'A', 0x00}); ok {
		t.Error("a UTF-16-LE BOM must not be misdetected as UTF-32")
	}
}
