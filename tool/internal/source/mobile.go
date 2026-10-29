package source

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"path/filepath"
	"strings"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/resilience"
)

// An APK/IPA is a ZIP; we walk every entry, scan text/JSON/plist/xml raw, and run a printable-strings
// pass over binary entries (.dex/.arsc/.so/Mach-O) so embedded keys in resources and string tables —
// where most hardcoded secrets sit (arXiv 2510.18601) — surface to the existing scan cascade.

// Mobile extraction budgets bound a scan against a zip bomb; --max-size caps a single entry, these cap
// the cumulative cost many under-cap entries could still rack up. Vars (not consts) so tests can shrink them.
var (
	// maxMobileTotalBytes caps the sum of all extracted entry bodies.
	maxMobileTotalBytes int64 = 1 << 30 // 1 GiB
	// maxMobileEntries caps how many zip entries are inspected (a zip can declare an absurd count).
	maxMobileEntries = 200_000
	// maxMobileEntryBytes bounds actual bytes read from a single entry, including forged headers.
	maxMobileEntryBytes int64 = 64 << 20 // 64 MiB
)

const (
	// mobileSource labels mobile findings "code" so the existing example/test-path demotion and lockfile
	// noise drop (scan.pathIsFilesystem allow-lists code|file|"") apply uniformly; the archive provenance
	// is still visible in Path (<app>.apk!/<internal/path>).
	mobileSource  = "code"
	minRunDefault = 5 // min printable-run length; short runs on obfuscated binaries are entropy noise.
)

// MobileOptions configures a mobile-app scan.
type MobileOptions struct {
	MaxBytes int64
	Exclude  []string
	Strings  bool // run the binary printable-strings pass (default true)
	MinRun   int  // min printable-run length (default minRunDefault)
}

// mobileBudget tracks cumulative extraction cost; once any cap is crossed it records an error so the
// walk aborts (mirrors imageBudget).
type mobileBudget struct {
	totalBytes int64
	entries    int64
	err        error
}

// addEntry charges one entry of bodyBytes against the budget, returning false (and setting b.err once)
// when a cap is crossed.
func (b *mobileBudget) addEntry(bodyBytes int64) bool {
	if b.err != nil {
		return false
	}
	b.entries++
	if b.entries > int64(maxMobileEntries) {
		b.err = fmt.Errorf("mobile extraction aborted: exceeded the %d-entry cap (possible zip bomb)", maxMobileEntries)
		return false
	}
	return b.addBytes(bodyBytes)
}

func (b *mobileBudget) addBytes(bodyBytes int64) bool {
	if b.err != nil {
		return false
	}
	if bodyBytes < 0 || bodyBytes > maxMobileTotalBytes-b.totalBytes {
		b.err = fmt.Errorf("mobile extraction aborted: extracted bytes exceeded the %d-byte cap (possible zip bomb)", maxMobileTotalBytes)
		return false
	}
	b.totalBytes += bodyBytes
	return true
}

// MobileItems is the public entry the cmd calls; it forwards to Extract.
func MobileItems(ctx context.Context, p string, opts MobileOptions) (<-chan model.Item, error) {
	return Extract(ctx, p, opts)
}

// Extract opens a local APK/IPA (or any ZIP — both formats are ZIPs) and yields each entry's scannable
// content as a model.Item. A non-zip / truncated file returns an error so the caller exits non-zero.
// On success the walk runs in a guarded background goroutine so a malformed entry never crashes the
// process or skips close(ch).
func Extract(ctx context.Context, p string, opts MobileOptions) (<-chan model.Item, error) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = maxMobileEntryBytes
	}
	zr, err := zip.OpenReader(p)
	if err != nil {
		return nil, fmt.Errorf("open mobile archive %q: %w", p, err)
	}
	archiveBase := filepath.Base(p)
	ch := make(chan model.Item, 128)
	go func() {
		defer close(ch)
		defer zr.Close()
		resilience.Guard(
			func() { emitMobile(ctx, ch, &zr.Reader, archiveBase, opts) },
			func(r any) {
				model.Note(ctx, "mobile_processing_failed", p, true)
				logx.Warn("recovered mobile-scan panic")
				emitSourceError(ctx, ch, archiveBase, errors.New("mobile reader failed"))
			},
		)
	}()
	return ch, nil
}

// emitMobile walks every zip entry, classifies it, and sends its scannable text (or its extracted
// printable strings for binaries) as an Item. It stops early on ctx cancel or a blown budget.
func emitMobile(ctx context.Context, ch chan<- model.Item, zr *zip.Reader, archiveBase string, opts MobileOptions) {
	if len(zr.File) > maxMobileEntries {
		model.Note(ctx, "mobile_entry_limit", archiveBase, true)
		logx.Error("mobile extraction aborted: too many entries (possible zip bomb)",
			"entries", len(zr.File), "limit", maxMobileEntries)
		emitSourceError(ctx, ch, archiveBase, fmt.Errorf("mobile archive exceeds the %d-entry cap", maxMobileEntries))
		return
	}
	b := &mobileBudget{}
	for _, f := range zr.File {
		if ctx.Err() != nil {
			return
		}
		name := f.Name // forward-slash internal path, e.g. "res/raw/cfg.json"
		if f.FileInfo().IsDir() {
			continue
		}
		reportPath := archiveBase + "!/" + name
		// Inspected headers remain bounded even when bodies are deliberately excluded.
		if !b.addEntry(0) {
			model.Note(ctx, "mobile_budget_limit", archiveBase, true)
			emitSourceError(ctx, ch, archiveBase, b.err)
			return
		}
		if excludedMobile(name, opts.Exclude) || excludedMobile(reportPath, opts.Exclude) {
			continue
		}
		cls := classifyEntry(name)
		if cls == clsSkip || (cls == clsBinStrings && !opts.Strings) {
			continue
		}
		usize := int64(math.MaxInt64)
		if f.UncompressedSize64 <= math.MaxInt64 {
			usize = int64(f.UncompressedSize64)
		}
		limit := min(opts.MaxBytes, maxMobileEntryBytes)
		if f.UncompressedSize64 > math.MaxInt64 || usize > limit {
			model.Note(ctx, "max_size", reportPath, true)
			if !emitSourceError(ctx, ch, reportPath, fmt.Errorf("mobile entry exceeds the %d-byte size limit", limit)) {
				return
			}
			continue
		}
		if !b.addBytes(usize) {
			model.Note(ctx, "mobile_budget_limit", archiveBase, true)
			emitSourceError(ctx, ch, archiveBase, b.err)
			return
		}
		rc, err := f.Open()
		if err != nil {
			model.Note(ctx, "mobile_entry_failed", archiveBase, true)
			if !emitSourceError(ctx, ch, reportPath, err) {
				return
			}
			continue
		}
		body, rerr := readCapped(rc, usize, limit)
		closeErr := rc.Close()
		if rerr != nil || closeErr != nil {
			model.Note(ctx, "mobile_entry_failed", archiveBase, true)
			if !emitSourceError(ctx, ch, reportPath, cmp(rerr, closeErr)) {
				return
			}
			continue
		}
		switch cls {
		case clsTextRaw:
			text, ok := scannableText(body)
			if !ok {
				// A text-classified entry that is actually binary (mis-extensioned, or binary AXML /
				// bplist): fall through to the strings pass so nothing is silently dropped.
				if opts.Strings {
					emitStrings(ctx, ch, body, reportPath, opts)
				}
				continue
			}
			if !send(ctx, ch, model.Item{Text: string(text), Source: mobileSource, Path: reportPath}) {
				return
			}
		case clsBinStrings:
			if opts.Strings {
				emitStrings(ctx, ch, body, reportPath, opts)
			}
		}
	}
}

// readCapped validates actual size and reads through EOF so ZIP CRC failures cannot be missed.
func readCapped(rc io.Reader, usize, max int64) ([]byte, error) {
	data, err := readSourceBytes(rc, max)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != usize {
		return nil, errors.New("mobile entry size does not match its header")
	}
	return data, nil
}

// excludedMobile reports whether name matches any exclude pattern (glob OR substring, same matcher as
// the filesystem/image sources).
func excludedMobile(name string, exclude []string) bool {
	for _, ex := range exclude {
		if config.PathMatch(ex, name) {
			return true
		}
	}
	return false
}

type entryClass int

const (
	clsTextRaw entryClass = iota
	clsBinStrings
	clsSkip
)

// classifyEntry decides how a zip entry is scanned by its name: high-value config files and known text
// extensions are scanned raw; known binaries get the strings pass; pure assets (images/fonts/media) are
// skipped; an unknown extension defaults to the strings pass (cheap, high recall).
func classifyEntry(name string) entryClass {
	ext := strings.ToLower(filepath.Ext(name))
	base := path.Base(name)
	// High-value plain config files — always raw, even if huge or oddly named (the SecretLoc high-hit
	// class: google-services.json carries api_key / current_key / mobilesdk_app_id). A binary AXML
	// AndroidManifest or bplist Info.plist fails scannableText and falls through to strings in emitMobile.
	switch base {
	case "google-services.json", "GoogleService-Info.plist", "Info.plist", "AndroidManifest.xml":
		return clsTextRaw
	}
	switch ext {
	case ".json", ".xml", ".plist", ".txt", ".properties", ".yml", ".yaml", ".js", ".ts",
		".html", ".css", ".smali", ".kt", ".java", ".pem", ".cer", ".crt", ".cfg", ".conf",
		".ini", ".env", ".gradle", ".pro":
		return clsTextRaw
	case ".dex", ".so", ".arsc", ".nib", ".bin", ".dylib", ".a", ".o":
		return clsBinStrings
	}
	if skipExt[ext] {
		return clsSkip
	}
	// Unknown/extensionless (a bare classes.dex variant, a Mach-O with no ext): strings pass.
	return clsBinStrings
}

// emitStrings runs the two printable-strings passes (8-bit ASCII, then UTF-16LE) over a binary blob and
// sends the newline-joined runs as one Item, so scan.Run's lineIndex gives each run its own line/col and
// capGenericPerFile bounds the per-path noise.
func emitStrings(ctx context.Context, ch chan<- model.Item, body []byte, reportPath string, opts MobileOptions) {
	min := opts.MinRun
	if min <= 0 {
		min = minRunDefault
	}
	var b strings.Builder
	ascii8(body, min, &b)  // .so/Mach-O C-strings
	utf16le(body, min, &b) // .dex/.arsc UTF-16 string pool
	if b.Len() == 0 {
		return
	}
	send(ctx, ch, model.Item{Text: b.String(), Source: mobileSource, Path: reportPath})
}

// isPrint reports whether c is tab or a printable ASCII byte (other control bytes terminate a run).
func isPrint(c byte) bool { return c == 0x09 || (c >= 0x20 && c <= 0x7e) }

// ascii8 is the classic GNU-strings scan: contiguous printable bytes of length >= min become one line.
func ascii8(body []byte, min int, b *strings.Builder) {
	start := 0
	for i := 0; i < len(body); i++ {
		if !isPrint(body[i]) {
			if i-start >= min {
				b.Write(body[start:i])
				b.WriteByte('\n')
			}
			start = i + 1
		}
	}
	if len(body)-start >= min {
		b.Write(body[start:])
		b.WriteByte('\n')
	}
}

// utf16le recovers printable ASCII stored as little-endian UTF-16 (low byte printable, high byte 0x00) —
// the form of dex/arsc string-pool entries. Both byte alignments are scanned so an odd-shifted pool is
// not missed; the two phases read disjoint index sets so they can't duplicate a run. A non-zero high
// byte ends the run; surrogate decoding is unnecessary (secrets are ASCII-range tokens).
func utf16le(body []byte, min int, b *strings.Builder) {
	utf16lePhase(body, 0, min, b)
	utf16lePhase(body, 1, min, b)
}

func utf16lePhase(body []byte, start, min int, b *strings.Builder) {
	run := make([]byte, 0, 64)
	flush := func() {
		if len(run) >= min {
			b.Write(run)
			b.WriteByte('\n')
		}
		run = run[:0]
	}
	for i := start; i+1 < len(body); i += 2 {
		lo, hi := body[i], body[i+1]
		if hi == 0x00 && isPrint(lo) {
			run = append(run, lo)
		} else {
			flush()
		}
	}
	flush()
}

// MobileBytes exercises the same intake without touching the filesystem.
func MobileBytes(ctx context.Context, name string, data []byte, opts MobileOptions) (<-chan model.Item, error) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = maxMobileEntryBytes
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	ch := make(chan model.Item, 128)
	go func() {
		defer close(ch)
		resilience.Guard(func() { emitMobile(ctx, ch, zr, name, opts) }, func(any) { model.Note(ctx, "mobile_processing_failed", name, true) })
	}()
	return ch, nil
}
