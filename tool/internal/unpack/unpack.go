// Package unpack walks bounded, in-memory archive payloads without writing extracted files to disk.
package unpack

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"path"
	"strings"
)

const (
	defaultMaxEntries = 10_000
	defaultMaxDepth   = 3
)

// Limits bounds one root archive and all recursively nested archives.
type Limits struct {
	MaxEntry   int64 // largest ordinary emitted file
	MaxArchive int64 // largest compressed root/nested archive held in memory
	MaxTotal   int64 // cumulative declared/uncompressed bytes across the recursive walk
	MaxEntries int   // cumulative archive headers inspected
	MaxDepth   int   // archive layers, including the root
}

// Entry is one regular, non-symlink archive member.
type Entry struct {
	Path string
	Data []byte
}

// Stats summarizes an expansion. Skipped covers unsafe names, directories, links, and oversized
// ordinary entries; a blown global budget is returned as an error.
type Stats struct {
	Archives int
	Entries  int
	Emitted  int
	Skipped  int
}

// BoundedLimits builds practical recursive limits from the caller's per-entry and compressed-input
// caps. Expanded content is capped at 4x compressed input, never below the compressed cap and never
// above 512 MiB unless the caller explicitly allows a larger compressed input.
func BoundedLimits(maxEntry, maxArchive int64) Limits {
	if maxEntry <= 0 {
		maxEntry = 10 << 20
	}
	if maxArchive <= 0 {
		maxArchive = 100 << 20
	}
	maxTotal := int64(512 << 20)
	if maxArchive <= maxTotal/4 {
		maxTotal = maxArchive * 4
	} else if maxArchive > maxTotal {
		maxTotal = maxArchive
	}
	return Limits{
		MaxEntry: maxEntry, MaxArchive: maxArchive, MaxTotal: maxTotal,
		MaxEntries: defaultMaxEntries, MaxDepth: defaultMaxDepth,
	}
}

type format uint8

const (
	formatNone format = iota
	formatZIP
	formatTAR
	formatGZIP
)

type walker struct {
	limits    Limits
	remaining uint64
	stats     Stats
	emit      func(Entry) error
}

// Walk recursively expands root and calls emit for each ordinary member. recognized=false means the
// payload is not a supported ZIP/TAR/GZIP archive and emit was not called.
func Walk(root string, raw []byte, limits Limits, emit func(Entry) error) (stats Stats, recognized bool, err error) {
	limits = normalizeLimits(limits)
	if limits.MaxEntry == math.MaxInt64 || limits.MaxArchive == math.MaxInt64 {
		return stats, true, errors.New("archive size limit is too large")
	}
	if int64(len(raw)) > limits.MaxArchive {
		return stats, true, fmt.Errorf("archive exceeds compressed-size limit (%d > %d)", len(raw), limits.MaxArchive)
	}
	f := detectFormat(root, raw)
	if f == formatNone {
		return stats, false, nil
	}
	w := &walker{
		limits:    limits,
		remaining: uint64(limits.MaxTotal), //nolint:gosec // normalizeLimits guarantees a positive int64.
		emit:      emit,
	}
	err = w.walk(root, raw, f, 0)
	return w.stats, true, err
}

func normalizeLimits(l Limits) Limits {
	if l.MaxEntry <= 0 {
		l.MaxEntry = 10 << 20
	}
	if l.MaxArchive <= 0 {
		l.MaxArchive = 100 << 20
	}
	if l.MaxTotal <= 0 {
		if l.MaxArchive > math.MaxInt64/4 {
			l.MaxTotal = math.MaxInt64
		} else {
			l.MaxTotal = l.MaxArchive * 4
		}
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = defaultMaxEntries
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = defaultMaxDepth
	}
	return l
}

// MaybeArchive reports whether name has a supported archive/document extension. It is used only to
// avoid an early extension skip; Walk still verifies the actual magic/structure before expanding.
func MaybeArchive(name string) bool {
	lower := strings.ToLower(name)
	for _, suffix := range []string{
		".zip", ".jar", ".docx", ".xlsx", ".pptx", ".apk", ".ipa",
		".tar", ".tar.gz", ".tgz", ".gz",
	} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func detectFormat(name string, raw []byte) format {
	switch {
	case len(raw) >= 4 && bytes.Equal(raw[:4], []byte{'P', 'K', 3, 4}):
		return formatZIP
	case len(raw) >= 4 && bytes.Equal(raw[:4], []byte{'P', 'K', 5, 6}):
		return formatZIP // empty ZIP
	case len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b:
		return formatGZIP
	case len(raw) >= 262 && bytes.Equal(raw[257:262], []byte("ustar")):
		return formatTAR
	case strings.HasSuffix(strings.ToLower(name), ".tar"):
		return formatTAR
	default:
		return formatNone
	}
}

func (w *walker) walk(name string, raw []byte, f format, depth int) error {
	if depth >= w.limits.MaxDepth {
		w.stats.Skipped++
		return nil
	}
	w.stats.Archives++
	switch f {
	case formatZIP:
		return w.walkZIP(name, raw, depth)
	case formatTAR:
		return w.walkTAR(name, raw, depth)
	case formatGZIP:
		return w.walkGZIP(name, raw, depth)
	default:
		return errors.New("unsupported archive format")
	}
}

func (w *walker) charge(n uint64) error {
	if n > w.remaining {
		return fmt.Errorf("archive content expands beyond the %d-byte cumulative limit", w.limits.MaxTotal)
	}
	w.remaining -= n
	return nil
}

func (w *walker) addHeader() error {
	w.stats.Entries++
	if w.stats.Entries > w.limits.MaxEntries {
		return fmt.Errorf("archive exceeds the %d-entry cumulative limit", w.limits.MaxEntries)
	}
	return nil
}

func (w *walker) walkZIP(root string, raw []byte, depth int) error {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return fmt.Errorf("open ZIP: %w", err)
	}
	for _, f := range zr.File {
		if err := w.addHeader(); err != nil {
			return err
		}
		if f.FileInfo().IsDir() || f.Mode()&fs.ModeSymlink != 0 {
			w.stats.Skipped++
			continue
		}
		if err := w.charge(f.UncompressedSize64); err != nil {
			return err
		}
		name, ok := safeName(f.Name)
		if !ok {
			w.stats.Skipped++
			continue
		}
		limit := w.entryReadLimit(name)
		if f.UncompressedSize64 > math.MaxInt64 {
			w.stats.Skipped++
			continue
		}
		if int64(f.UncompressedSize64) > limit { //nolint:gosec // MaxInt64 guard proves representability.
			w.stats.Skipped++
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		data, err := readBounded(rc, limit)
		closeErr := rc.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if err := w.handle(root+"!/"+name, data, depth); err != nil {
			return err
		}
	}
	return nil
}

func (w *walker) walkTAR(root string, raw []byte, depth int) error {
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read TAR: %w", err)
		}
		if err := w.addHeader(); err != nil {
			return err
		}
		// A zero typeflag is the legacy regular-file encoding (the deprecated tar.TypeRegA value).
		if h.Typeflag != tar.TypeReg && h.Typeflag != 0 {
			w.stats.Skipped++
			continue
		}
		if h.Size < 0 {
			return errors.New("TAR entry has a negative size")
		}
		if err := w.charge(uint64(h.Size)); err != nil { //nolint:gosec // h.Size is checked non-negative.
			return err
		}
		name, ok := safeName(h.Name)
		if !ok {
			w.stats.Skipped++
			continue
		}
		limit := w.entryReadLimit(name)
		if h.Size > limit {
			w.stats.Skipped++
			continue
		}
		data, err := readBounded(tr, limit)
		if err != nil {
			return err
		}
		if err := w.handle(root+"!/"+name, data, depth); err != nil {
			return err
		}
	}
}

func (w *walker) walkGZIP(root string, raw []byte, depth int) error {
	gr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("open GZIP: %w", err)
	}
	name := gzipMemberName(root, gr.Name)
	data, readErr := readBounded(gr, w.limits.MaxArchive)
	closeErr := gr.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := w.addHeader(); err != nil {
		return err
	}
	if err := w.charge(uint64(len(data))); err != nil {
		return err
	}
	return w.handle(root+"!/"+name, data, depth)
}

func (w *walker) entryReadLimit(name string) int64 {
	if MaybeArchive(name) {
		return w.limits.MaxArchive
	}
	return w.limits.MaxEntry
}

func (w *walker) handle(name string, data []byte, depth int) error {
	if f := detectFormat(name, data); f != formatNone {
		return w.walk(name, data, f, depth+1)
	}
	if int64(len(data)) > w.limits.MaxEntry {
		w.stats.Skipped++
		return nil
	}
	if err := w.emit(Entry{Path: name, Data: data}); err != nil {
		return err
	}
	w.stats.Emitted++
	return nil
}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 || limit == math.MaxInt64 {
		return nil, errors.New("invalid archive read limit")
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("archive member exceeds the %d-byte read limit", limit)
	}
	return data, nil
}

func safeName(name string) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	clean := path.Clean(name)
	if clean == "" || clean == "." || clean == ".." || path.IsAbs(clean) || strings.HasPrefix(clean, "../") {
		return "", false
	}
	return clean, true
}

func gzipMemberName(root, headerName string) string {
	if clean, ok := safeName(headerName); ok {
		return clean
	}
	base := path.Base(root)
	lower := strings.ToLower(base)
	switch {
	case strings.HasSuffix(lower, ".tar.gz"):
		return base[:len(base)-3]
	case strings.HasSuffix(lower, ".tgz"):
		return base[:len(base)-4] + ".tar"
	case strings.HasSuffix(lower, ".gz"):
		return base[:len(base)-3]
	default:
		return "payload"
	}
}
