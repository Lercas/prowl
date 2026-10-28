// Package source provides pluggable content sources that yield model.Item streams.
package source

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/resilience"
)

// Stdin scans bounded standard input, optionally using the requested per-file limit.
func Stdin(ctx context.Context, limits ...int64) <-chan model.Item {
	return StdinNamed(ctx, "<stdin>", limits...)
}
func StdinNamed(ctx context.Context, name string, limits ...int64) <-chan model.Item {
	maxBytes := int64(4 << 20)
	if len(limits) > 0 && limits[0] > 0 {
		maxBytes = limits[0]
	}
	model.CoverageFrom(ctx).RegisterScope("stdin", name, struct{ MaxSize int64 }{maxBytes})
	return stdinNamedFrom(ctx, os.Stdin, maxBytes, name)
}
func StdinLimited(ctx context.Context, maxBytes int64) <-chan model.Item {
	return StdinNamed(ctx, "<stdin>", maxBytes)
}
func stdinFrom(ctx context.Context, input io.ReadCloser, maxBytes int64) <-chan model.Item {
	return stdinNamedFrom(ctx, input, maxBytes, "<stdin>")
}
func stdinNamedFrom(ctx context.Context, input io.ReadCloser, maxBytes int64, name string) <-chan model.Item {
	ch := make(chan model.Item, 1)
	go func() {
		defer close(ch)
		stopClose := closeInputOnCancel(ctx, input)
		defer stopClose()
		data, err := readSourceBytes(input, maxBytes)
		if err != nil {
			model.Note(ctx, "stdin_read_failed", name, true)
			emitSourceError(ctx, ch, name, err)
			return
		}
		if len(data) > 0 {
			emitPayload(ctx, ch, name, data, maxBytes, nil, nil)
		}
	}()
	return ch
}

// send delivers an item unless ctx is cancelled; returns false when the consumer should stop.
func send(ctx context.Context, ch chan<- model.Item, it model.Item) bool {
	model.AttachProvenance(ctx, &it)
	if origin, ok := ctx.Value(filesystemOriginKey{}).(filesystemOrigin); ok && it.ArtifactURI == "" {
		it.ArtifactURI = origin.uri(it.Path)
	}
	select {
	case ch <- it:
		return true
	case <-ctx.Done():
		return false
	}
}

var defaultSkipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true,
	".venv": true, "__pycache__": true, "target": true, ".idea": true, ".terraform": true,
}

// NOTE: dependency-lock manifests (go.sum, *.lock, …) are deliberately NOT skipped here — people leak
// real credentials in them (a private-registry URL in package-lock.json). The scan layer instead drops
// only the generic_high_entropy noise on their package hashes (see scan.isLockfile).

var skipExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true, ".webp": true,
	".pdf": true, ".zip": true, ".gz": true, ".tar": true, ".bz2": true, ".7z": true,
	".mp4": true, ".mp3": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".so": true, ".dll": true, ".dylib": true, ".class": true, ".o": true, ".a": true,
	".wasm": true, ".bin": true, ".exe": true, ".jar": true,
	".ai": true, ".eps": true, ".ps": true, // design/PostScript assets: base64-heavy, not source code
}

// Filesystem walks roots and yields text Items, skipping binaries/large files/excluded paths.
func Filesystem(ctx context.Context, roots, exclude []string, maxBytes int64) <-chan model.Item {
	for _, root := range roots {
		target, _ := filepath.Abs(root)
		model.CoverageFrom(ctx).RegisterScope("filesystem", target, struct {
			Exclude  []string
			MaxBytes int64
		}{exclude, maxBytes})
	}
	ch := make(chan model.Item, 128)
	go func() {
		defer close(ch)
		// Guard the whole walk: a panic in the callback must not crash the process or skip close(ch).
		resilience.Guard(
			func() { walkRoots(ctx, ch, roots, exclude, maxBytes) },
			func(r any) {
				model.Note(ctx, "walk_failed", "", true)
				logx.Warn("recovered filesystem-walk panic")
				emitSourceError(ctx, ch, "", errors.New("filesystem reader failed"))
			},
		)
	}()
	return ch
}

func walkRoots(ctx context.Context, ch chan<- model.Item, roots, exclude []string, maxBytes int64) {
	for _, root := range roots {
		rootCtx := ctx
		if excludedSourcePath(root, exclude) {
			continue
		}
		info, statErr := os.Stat(root)
		if statErr != nil {
			if !emitSourceError(ctx, ch, root, statErr) {
				return
			}
			continue
		}
		walkRoot := root
		if info.IsDir() && hasParentSegment(root) {
			// OS traversal resolves symlinks before '..'; filepath.Join/WalkDir clean lexically.
			resolved, err := filepath.EvalSymlinks(root)
			if err != nil {
				if !emitSourceError(ctx, ch, root, err) {
					return
				}
				continue
			}
			rootCtx, err = withFilesystemOrigin(ctx, root, resolved)
			if err != nil {
				if !emitSourceError(ctx, ch, root, err) {
					return
				}
				continue
			}
			walkRoot = resolved
		}
		// An explicitly-named symlink ROOT was chosen by the user, so follow it (the in-tree guard below
		// only refuses links discovered inside a tree, not a target the user listed).
		if fi, lerr := os.Lstat(root); lerr == nil && fi.Mode()&fs.ModeSymlink != 0 {
			if !info.IsDir() {
				if !emitSymlinkRoot(rootCtx, ch, root, exclude, maxBytes) {
					return
				}
				continue
			}
			// WalkDir does not descend into a symlink, even when it is the explicitly chosen root.
			resolved, err := filepath.EvalSymlinks(root)
			if err != nil {
				if !emitSourceError(ctx, ch, root, err) {
					return
				}
				continue
			}
			walkRoot = resolved
		}
		if !info.IsDir() {
			if !emitFile(rootCtx, ch, root, maxBytes, exclude) {
				return
			}
			continue
		}
		rootFS, openErr := os.OpenRoot(walkRoot)
		if openErr != nil {
			if !emitSourceError(rootCtx, ch, root, openErr) {
				return
			}
			continue
		}
		walkErr := filepath.WalkDir(walkRoot, func(diskPath string, d fs.DirEntry, err error) error {
			path := diskPath
			if ctx.Err() != nil {
				return filepath.SkipAll
			}
			if walkRoot != root {
				rel, err := filepath.Rel(walkRoot, path)
				if err != nil {
					return err
				}
				// Keep report paths and exclusions relative to the root the user chose.
				path = displaySourcePath(root, rel)
			}
			if excludedSourcePath(path, exclude) {
				if err == nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if err != nil {
				if !emitSourceError(rootCtx, ch, path, err) {
					return filepath.SkipAll
				}
				return nil
			}
			if d.IsDir() {
				// Prune default-skip dirs (generated/vendored noise), unless one is named explicitly as
				// the scan root (the override). Log the prune at Debug so the dropped subtree isn't silent.
				if defaultSkipDirs[d.Name()] && path != root {
					model.Note(ctx, "excluded_directory", path, false)
					logx.Debug("skipped: default-skip dir (name it explicitly as a root to scan it)", "path", path)
					return filepath.SkipDir
				}
				return nil
			}
			// Never follow an in-tree symlink: one discovered during the walk can point outside the
			// scanned root (-> /etc/shadow) and escape scope. A named symlink root is handled above.
			if d.Type()&fs.ModeSymlink != 0 {
				model.Note(ctx, "symlink", path, false)
				return nil
			}
			if skipByExtension(ctx, path) {
				model.Note(ctx, "unsupported_extension", path, false)
				return nil
			}
			info, err := d.Info()
			if err != nil {
				if !emitSourceError(rootCtx, ch, path, err) {
					return filepath.SkipAll
				}
				return nil
			}
			if !info.Mode().IsRegular() {
				return nil // special files discovered in a tree are outside the regular-file scan policy
			}
			if info.Size() > maxBytes {
				if !emitSourceError(rootCtx, ch, path, errSourceTooLarge) {
					return filepath.SkipAll
				}
				return nil
			}
			rel, err := filepath.Rel(walkRoot, diskPath)
			if err != nil {
				if !emitSourceError(rootCtx, ch, path, err) {
					return filepath.SkipAll
				}
				return nil
			}
			data, err := readSourceFile(func() (*os.File, error) {
				return rootFS.OpenFile(rel, os.O_RDONLY|sourceOpenFlags, 0)
			}, maxBytes)
			if err != nil {
				if !emitSourceError(rootCtx, ch, path, err) {
					return filepath.SkipAll
				}
				return nil
			}
			if !emitPayload(rootCtx, ch, path, data, maxBytes, exclude, nil) {
				return filepath.SkipAll
			}
			return nil
		})
		_ = rootFS.Close()
		if walkErr != nil && !emitSourceError(rootCtx, ch, root, walkErr) {
			return
		}
	}
}

// emitFile reads one explicitly-listed file (a FilesFromList entry) and emits it as an Item. A symlink
// among them is followed (Stat, not Lstat) since the user chose the path; this differs from the fs walk,
// which refuses links discovered by descent. Unreadable targets produce an incomplete-source item.
func emitFile(ctx context.Context, ch chan<- model.Item, path string, maxBytes int64, exclude []string) bool {
	return emitListedTarget(ctx, ch, path, path, maxBytes, exclude)
}

// emitSymlinkRoot follows an explicitly-named symlink ROOT and emits its target, honouring the same
// --exclude patterns (matched against the link path) before deferring to the shared emit path.
func emitSymlinkRoot(ctx context.Context, ch chan<- model.Item, path string, exclude []string, maxBytes int64) bool {
	for _, ex := range exclude {
		if config.PathMatch(ex, path) {
			return true
		}
	}
	return emitListedTarget(ctx, ch, path, path, maxBytes, exclude)
}

// emitListedTarget is the shared read/scan/emit path for an explicitly-chosen target. It follows
// symlinks (Stat), applies the binary-extension / size / encoding filters, and emits under reportPath.
// Returns false only when the consumer stopped.
func emitListedTarget(ctx context.Context, ch chan<- model.Item, path, reportPath string, maxBytes int64, exclude []string) bool {
	for _, pattern := range exclude {
		if config.PathMatch(pattern, reportPath) {
			return true
		}
	}
	if skipByExtension(ctx, path) {
		model.Note(ctx, "unsupported_extension", path, false)
		return true
	}
	if hasParentSegment(path) {
		physical, err := filepath.EvalSymlinks(path)
		if err != nil {
			return emitSourceError(ctx, ch, reportPath, err)
		}
		ctx, err = withFilesystemOrigin(ctx, reportPath, physical)
		if err != nil {
			return emitSourceError(ctx, ch, reportPath, err)
		}
		path = physical
	}
	// Stat (follows symlinks) so an explicitly-listed link is resolved to its target's regular file.
	info, err := os.Stat(path)
	if err != nil {
		return emitSourceError(ctx, ch, reportPath, err)
	}
	if !info.Mode().IsRegular() {
		return emitSourceError(ctx, ch, reportPath, errors.New("source is not a regular file"))
	}
	if info.Size() > maxBytes {
		return emitSourceError(ctx, ch, reportPath, errSourceTooLarge)
	}
	data, err := readSourceFile(func() (*os.File, error) {
		return os.OpenFile(path, os.O_RDONLY|sourceOpenFlags, 0)
	}, maxBytes)
	if err != nil {
		return emitSourceError(ctx, ch, reportPath, err)
	}
	return emitPayload(ctx, ch, reportPath, data, maxBytes, exclude, nil)
}

func excludedSourcePath(path string, exclude []string) bool {
	for _, pattern := range exclude {
		if config.PathMatch(pattern, path) {
			return true
		}
	}
	return false
}

// docMagic are leading magic bytes of document/asset formats that slip the NUL check but embed base64
// streams that flood generic_high_entropy (PDF, PostScript, JPEG). Catches a mis-extensioned one too.
var docMagic = [][]byte{[]byte("%PDF-"), []byte("%!PS"), []byte("\xFF\xD8\xFF" /* JPEG */)}

func looksBinary(b []byte) bool {
	for _, m := range docMagic {
		if len(b) >= len(m) && string(b[:len(m)]) == string(m) {
			return true
		}
	}
	n := len(b)
	if n > 8000 {
		n = 8000
	}
	for i := 0; i < n; i++ {
		if b[i] == 0 {
			return true
		}
	}
	return false
}

// scannableText prepares raw file bytes for scanning. UTF-16 / UTF-32 sources carry interior NULs that
// would trip looksBinary and skip the file (and its secrets), so it transcodes them to UTF-8 first, then
// applies the binary check. Detection order matters: a UTF-32-LE BOM (FF FE 00 00) starts with the
// UTF-16-LE BOM (FF FE), so UTF-32 must be checked first. Order: UTF-32-BOM, UTF-16-BOM, BOM-less UTF-16
// (heuristic), then the plain binary check. Returns the bytes to scan (original or transcoded) and ok.
func scannableText(b []byte) (text []byte, ok bool) {
	if dec, isUTF32 := decodeUTF32BOM(b); isUTF32 {
		return finalizeDecoded(dec)
	}
	if dec, isUTF16 := decodeUTF16BOM(b); isUTF16 {
		return finalizeDecoded(dec)
	}
	// BOM-less UTF-16 (common from Windows tooling): detect the NUL-every-other-byte pattern and
	// transcode, but only when the result is clean text (see decodeUTF16NoBOM's guards).
	if dec, isUTF16 := decodeUTF16NoBOM(b); isUTF16 {
		return finalizeDecoded(dec)
	}
	if looksBinary(b) {
		return nil, false
	}
	return b, true
}

// ScannableText normalizes a source payload into UTF-8 text and rejects binary data. Source
// adapters that already hold content in memory (CI artifacts, SaaS APIs) use the same decision as
// the filesystem walker instead of maintaining subtly different binary/encoding heuristics.
func ScannableText(b []byte) ([]byte, bool) {
	return scannableText(b)
}

// finalizeDecoded applies the binary check to already-transcoded UTF-8 text, so a file that decoded to
// genuinely binary content is still skipped.
func finalizeDecoded(dec []byte) (text []byte, ok bool) {
	if looksBinary(dec) {
		return nil, false
	}
	return dec, true
}

// decodeUTF16BOM transcodes b to UTF-8 when it begins with a UTF-16 byte-order mark (FF FE little- or
// FE FF big-endian); otherwise it returns (nil, false) and the caller scans the bytes as-is. An odd
// trailing byte (a truncated final code unit) is dropped. The BOM itself is not emitted.
func decodeUTF16BOM(b []byte) ([]byte, bool) {
	if len(b) < 2 {
		return nil, false
	}
	var order binary.ByteOrder
	switch {
	case b[0] == 0xFF && b[1] == 0xFE:
		order = binary.LittleEndian
	case b[0] == 0xFE && b[1] == 0xFF:
		order = binary.BigEndian
	default:
		return nil, false
	}
	return transcodeUTF16(b[2:], order), true
}

// transcodeUTF16 decodes the UTF-16 code units in body (no BOM, given byte order) to UTF-8. An odd
// trailing byte (a truncated final code unit) is dropped.
func transcodeUTF16(body []byte, order binary.ByteOrder) []byte {
	units := make([]uint16, 0, len(body)/2)
	for i := 0; i+1 < len(body); i += 2 {
		units = append(units, order.Uint16(body[i:i+2]))
	}
	runes := utf16.Decode(units)
	out := make([]byte, 0, len(runes)*utf8.UTFMax)
	for _, r := range runes {
		out = utf8.AppendRune(out, r)
	}
	return out
}

// decodeUTF32BOM transcodes b to UTF-8 when it begins with a UTF-32 BOM (00 00 FE FF / FF FE 00 00).
// Must run before decodeUTF16BOM (a UTF-32-LE BOM starts with the UTF-16-LE BOM bytes). An out-of-range
// or surrogate code point becomes U+FFFD; a trailing partial (< 4 byte) code unit is dropped.
func decodeUTF32BOM(b []byte) ([]byte, bool) {
	if len(b) < 4 {
		return nil, false
	}
	var order binary.ByteOrder
	switch {
	case b[0] == 0x00 && b[1] == 0x00 && b[2] == 0xFE && b[3] == 0xFF:
		order = binary.BigEndian
	case b[0] == 0xFF && b[1] == 0xFE && b[2] == 0x00 && b[3] == 0x00:
		order = binary.LittleEndian
	default:
		return nil, false
	}
	body := b[4:]
	out := make([]byte, 0, (len(body)/4)*utf8.UTFMax)
	for i := 0; i+3 < len(body); i += 4 {
		cp := order.Uint32(body[i : i+4])
		r := rune(utf8.RuneError)
		if cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF) {
			// Keep the replacement rune initialized above.
		} else {
			r = rune(cp)
		}
		out = utf8.AppendRune(out, r)
	}
	return out, true
}

// decodeUTF16NoBOM heuristically detects a BOM-less UTF-16 file and transcodes it. ASCII-as-UTF-16 puts
// a NUL in every other byte (odd positions for LE, even for BE); we sample the head and accept it only
// when enough NULs are confined to one parity AND the other parity is entirely NUL-free. The strict
// guards keep a genuine binary (NULs across both parities) from being transcoded into finding-flooding garbage.
func decodeUTF16NoBOM(b []byte) ([]byte, bool) {
	// Need a few code units to judge the parity pattern; a 2-byte file is ambiguous.
	if len(b) < 8 || len(b)%2 != 0 {
		return nil, false
	}
	n := len(b)
	if n > 8000 {
		n = 8000 &^ 1 // keep the sample even so parity indexing is meaningful
	}
	var nulEven, nulOdd int
	for i := 0; i < n; i++ {
		if b[i] == 0 {
			if i%2 == 0 {
				nulEven++
			} else {
				nulOdd++
			}
		}
	}
	// Require a substantial fraction of code units to carry a high-byte NUL, so a file with a few stray
	// NULs isn't transcoded. The /4 threshold tolerates runs of non-ASCII code units.
	units := n / 2
	threshold := units / 4
	switch {
	case nulOdd >= threshold && nulEven == 0:
		// NULs confined to odd positions, none on even -> UTF-16-LE.
		return transcodeUTF16(b, binary.LittleEndian), true
	case nulEven >= threshold && nulOdd == 0:
		// NULs confined to even positions, none on odd -> UTF-16-BE.
		return transcodeUTF16(b, binary.BigEndian), true
	default:
		return nil, false
	}
}

func sourceForPath(path string) string {
	lower := strings.ToLower(path)
	if strings.Contains(lower, ".docx!/") || strings.Contains(lower, ".xlsx!/") ||
		strings.Contains(lower, ".pptx!/") {
		return "file"
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".md", ".rst", ".txt", ".adoc":
		// A filesystem doc is just a "file" in the user-facing Finding.Source; no detection logic
		// branches on this. Code files keep "code", the label shared with the other sources.
		return "file"
	default:
		return "code"
	}
}
