package source

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func TestMobileIncompleteExtractionIsReported(t *testing.T) {
	for _, capKind := range []string{"size", "total", "count"} {
		t.Run(capKind, func(t *testing.T) {
			t.Cleanup(restoreMobileCaps(maxMobileTotalBytes, maxMobileEntries, maxMobileEntryBytes))
			opts := defaultOpts()
			switch capKind {
			case "size":
				opts.MaxBytes = 4
			case "total":
				maxMobileTotalBytes = 4
			case "count":
				maxMobileEntries = 1
			}
			apk := makeAPK(t, map[string][]byte{"a.txt": []byte("large content"), "b.txt": []byte("large content")})
			ch, err := Extract(context.Background(), apk, opts)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, it := range drainTexts(ch) {
				found = found || it.Error != nil
			}
			if !found {
				t.Fatal("limited extraction was certified clean")
			}
		})
	}
}

func TestMobileCRCFailureIsReported(t *testing.T) {
	var raw bytes.Buffer
	zw := zip.NewWriter(&raw)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "config.txt", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	const original = "original content"
	if _, err := io.WriteString(w, original); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	data := raw.Bytes()
	data[bytes.Index(data, []byte(original))] = 'X'
	p := filepath.Join(t.TempDir(), "corrupt.apk")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	ch, err := Extract(context.Background(), p, defaultOpts())
	if err != nil {
		t.Fatal(err)
	}
	items := drainTexts(ch)
	if len(items) != 1 || items[0].Error == nil {
		t.Fatalf("CRC failure was hidden: %+v", items)
	}
}

func TestMobileStringsKeepLongRuns(t *testing.T) {
	text := strings.Repeat(" ", 4200) + "AWS = \"" + awsKey + "\""
	for _, utf16 := range []bool{false, true} {
		body := []byte(text)
		if utf16 {
			body = nil
			for _, c := range []byte(text) {
				body = append(body, c, 0)
			}
		}
		apk := makeAPK(t, map[string][]byte{"classes.dex": body})
		ch, err := Extract(context.Background(), apk, defaultOpts())
		if err != nil {
			t.Fatal(err)
		}
		items := drainTexts(ch)
		if len(items) != 1 || !strings.Contains(items[0].Text, awsKey) {
			t.Fatalf("utf16=%v: long string silently clipped: paths=%v", utf16, paths(items))
		}
	}
}

func TestMobileBudgetCannotOverflow(t *testing.T) {
	b := mobileBudget{totalBytes: 1}
	if b.addEntry(math.MaxInt64) || b.err == nil {
		t.Fatal("budget overflow bypassed the extraction cap")
	}
}

func TestMobileExclusionsDoNotSpendBodyBudget(t *testing.T) {
	t.Cleanup(restoreMobileCaps(maxMobileTotalBytes, maxMobileEntries, maxMobileEntryBytes))
	maxMobileTotalBytes = 100
	maxMobileEntryBytes = 64
	opts := defaultOpts()
	opts.Exclude = []string{"large.txt"}
	apk := makeAPK(t, map[string][]byte{
		"large.txt": bytes.Repeat([]byte("x"), 1000),
		"icon.png":  bytes.Repeat([]byte("x"), 1000),
		"prod.env":  []byte("AWS = \"" + awsKey + "\""),
	})
	ch, err := Extract(context.Background(), apk, opts)
	if err != nil {
		t.Fatal(err)
	}
	items := drainTexts(ch)
	if len(items) != 1 || items[0].Error != nil || !strings.Contains(items[0].Text, awsKey) {
		t.Fatalf("excluded or asset body spent scan budget: %+v", items)
	}
}

func TestNoStringsAlsoSkipsMisExtensionedBinary(t *testing.T) {
	apk := makeAPK(t, map[string][]byte{"config.json": append([]byte{0}, []byte(awsKey)...)})
	opts := defaultOpts()
	opts.Strings = false
	ch, err := Extract(context.Background(), apk, opts)
	if err != nil {
		t.Fatal(err)
	}
	if items := drainTexts(ch); len(items) != 0 {
		t.Fatalf("strings pass ran despite --no-strings: %+v", items)
	}
}

const (
	awsKey = "\x41KIA4MNQ2RST7UVWX9YZ" // AWS access-key-id shape (image_test uses the same)
)

// makeAPK builds an in-memory ZIP (== APK/IPA) from name->body, writes it to a temp .apk, and returns
// its path. Entries are Deflate-compressed so UncompressedSize64 is exercised.
func makeAPK(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "app.apk")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func drainTexts(ch <-chan model.Item) []model.Item {
	var out []model.Item
	for it := range ch {
		out = append(out, it)
	}
	return out
}

func mobileDetector(t *testing.T) *detect.Detector {
	t.Helper()
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	return detect.New(tax)
}

func defaultOpts() MobileOptions {
	return MobileOptions{MaxBytes: 10 << 20, Strings: true, MinRun: minRunDefault}
}

// TestExtractPlantedKeyInJSON: a planted AWS key in res/raw/config.json is emitted raw AND produces a
// real detector finding through scannableText + the scan cascade.
func TestExtractPlantedKeyInJSON(t *testing.T) {
	body := []byte(fmt.Sprintf(`{"api_key":"%s"}`, awsKey))
	apk := makeAPK(t, map[string][]byte{"res/raw/config.json": body})

	ch, err := Extract(context.Background(), apk, defaultOpts())
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	items := drainTexts(ch)
	var found *model.Item
	for i := range items {
		if strings.HasSuffix(items[i].Path, "config.json") {
			found = &items[i]
		}
	}
	if found == nil {
		t.Fatalf("config.json not emitted; got paths %v", paths(items))
	}
	if !strings.Contains(found.Text, awsKey) {
		t.Errorf("emitted item missing the planted key: %q", found.Text)
	}
	if !strings.HasPrefix(found.Path, "app.apk!/") {
		t.Errorf("path %q lacks the <archive>!/ prefix", found.Path)
	}

	fs := scan.Run(context.Background(), feedItems(items...), mobileDetector(t), nil, nil, 2, nil, nil)
	if !hasType(fs, "aws") {
		t.Fatalf("no aws finding produced from the planted key; findings: %v", findingTypes(fs))
	}
}

// TestGoogleServicesHighValue: a hardcoded key in google-services.json (a high-value file) is scanned
// raw and surfaces as a finding.
func TestGoogleServicesHighValue(t *testing.T) {
	body := []byte(fmt.Sprintf(`{"client":[{"api_key":[{"current_key":"%s"}]}]}`, awsKey))
	apk := makeAPK(t, map[string][]byte{"google-services.json": body})

	ch, err := Extract(context.Background(), apk, defaultOpts())
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	items := drainTexts(ch)
	if len(items) == 0 || !strings.Contains(items[0].Text, awsKey) {
		t.Fatalf("google-services.json not scanned raw; items: %v", paths(items))
	}
	fs := scan.Run(context.Background(), feedItems(items...), mobileDetector(t), nil, nil, 2, nil, nil)
	if !hasType(fs, "aws") {
		t.Fatalf("no finding from the google-services.json key; findings: %v", findingTypes(fs))
	}
}

// TestStringsExtractDex: the ascii8 pass recovers a key wrapped in NUL bytes inside a .dex, and a
// sub-min run is excluded.
func TestStringsExtractDex(t *testing.T) {
	blob := bytes.Join([][]byte{{0, 0, 0}, []byte(awsKey), {0, 0}, []byte("abc")}, nil)
	apk := makeAPK(t, map[string][]byte{"classes.dex": blob})

	ch, err := Extract(context.Background(), apk, defaultOpts())
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	items := drainTexts(ch)
	if len(items) != 1 {
		t.Fatalf("want 1 strings item, got %d (%v)", len(items), paths(items))
	}
	text := items[0].Text
	if !strings.Contains(text, awsKey) {
		t.Errorf("ascii8 did not recover the key: %q", text)
	}
	for _, line := range strings.Split(text, "\n") {
		if line == "abc" {
			t.Errorf("sub-min run 'abc' (len 3 < %d) should have been excluded", minRunDefault)
		}
	}
}

// TestStringsUTF16LE: the utf16le pass recovers a key stored as little-endian UTF-16 in a resources.arsc
// string pool; a high-byte!=0 (non-ASCII BMP) sequence is dropped.
func TestStringsUTF16LE(t *testing.T) {
	var blob []byte
	for _, c := range []byte(awsKey) {
		blob = append(blob, c, 0x00) // LE UTF-16: low byte then NUL high byte
	}
	blob = append(blob, 0x41, 0x30, 0x42, 0x30) // 'A','B' with high byte 0x30 != 0 -> not ASCII-LE, dropped
	apk := makeAPK(t, map[string][]byte{"resources.arsc": blob})

	ch, err := Extract(context.Background(), apk, defaultOpts())
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	items := drainTexts(ch)
	if len(items) != 1 {
		t.Fatalf("want 1 strings item, got %d", len(items))
	}
	if !strings.Contains(items[0].Text, awsKey) {
		t.Errorf("utf16le did not recover the key: %q", items[0].Text)
	}
}

// TestMisExtensionedBinary: a .json entry that is actually binary (interior NULs) is rejected by
// scannableText and falls through to the strings pass, so the planted key is still recovered.
func TestMisExtensionedBinary(t *testing.T) {
	blob := bytes.Join([][]byte{{0x00, 0x01, 0x02, 0x00}, []byte(awsKey), {0x00, 0xff}}, nil)
	apk := makeAPK(t, map[string][]byte{"res/raw/blob.json": blob})

	ch, err := Extract(context.Background(), apk, defaultOpts())
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	items := drainTexts(ch)
	if len(items) != 1 || !strings.Contains(items[0].Text, awsKey) {
		t.Fatalf("mis-extensioned binary key not recovered via strings fallback; items=%v", paths(items))
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		want entryClass
	}{
		{"google-services.json", clsTextRaw},
		{"Payload/App.app/GoogleService-Info.plist", clsTextRaw},
		{"Payload/App.app/Info.plist", clsTextRaw},
		{"AndroidManifest.xml", clsTextRaw},
		{"res/raw/x.json", clsTextRaw},
		{"assets/config.properties", clsTextRaw},
		{"res/drawable/icon.png", clsSkip},
		{"res/font/x.ttf", clsSkip},
		{"classes.dex", clsBinStrings},
		{"lib/arm64-v8a/libapp.so", clsBinStrings},
		{"resources.arsc", clsBinStrings},
		{"unknown.weirdext", clsBinStrings},
		{"noextfile", clsBinStrings},
	}
	for _, c := range cases {
		if got := classifyEntry(c.name); got != c.want {
			t.Errorf("classifyEntry(%q) = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestNoStrings: with Strings=false a binary entry yields no item.
func TestNoStrings(t *testing.T) {
	blob := bytes.Join([][]byte{{0, 0}, []byte(awsKey), {0}}, nil)
	apk := makeAPK(t, map[string][]byte{"classes.dex": blob})
	opts := defaultOpts()
	opts.Strings = false
	ch, err := Extract(context.Background(), apk, opts)
	if err != nil {
		t.Fatal(err)
	}
	if items := drainTexts(ch); len(items) != 0 {
		t.Errorf("Strings=false should emit no binary-strings item, got %d", len(items))
	}
}

// TestEntryCapAbort: a zip with more entries than the shrunk entry cap aborts and records b.err.
func TestEntryCapAbort(t *testing.T) {
	t.Cleanup(restoreMobileCaps(maxMobileTotalBytes, maxMobileEntries, maxMobileEntryBytes))
	maxMobileEntries = 5
	maxMobileTotalBytes = 1 << 30

	entries := map[string][]byte{}
	for i := 0; i < 50; i++ {
		entries[fmt.Sprintf("res/raw/f%d.json", i)] = []byte(`{"k":"v"}`)
	}
	apk := makeAPK(t, entries)
	zr, err := zip.OpenReader(apk)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()

	ch := make(chan model.Item, 256)
	go func() {
		defer close(ch)
		emitMobile(context.Background(), ch, &zr.Reader, "app.apk", defaultOpts())
	}()
	got := len(drainTexts(ch))
	if got > maxMobileEntries {
		t.Errorf("emitted %d items past the %d-entry cap", got, maxMobileEntries)
	}
}

// TestTotalBytesCapAbort: ten 1 KiB entries blow a 2 KiB total-bytes cap; the walk stops early.
func TestTotalBytesCapAbort(t *testing.T) {
	t.Cleanup(restoreMobileCaps(maxMobileTotalBytes, maxMobileEntries, maxMobileEntryBytes))
	maxMobileTotalBytes = 2048
	maxMobileEntries = 1_000_000

	entries := map[string][]byte{}
	for i := 0; i < 10; i++ {
		entries[fmt.Sprintf("res/raw/f%d.txt", i)] = bytes.Repeat([]byte("A"), 1024)
	}
	apk := makeAPK(t, entries)
	zr, err := zip.OpenReader(apk)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()

	ch := make(chan model.Item, 64)
	go func() {
		defer close(ch)
		emitMobile(context.Background(), ch, &zr.Reader, "app.apk", defaultOpts())
	}()
	got := int64(len(drainTexts(ch)))
	if got*1024 > maxMobileTotalBytes+1024 {
		t.Errorf("emitted %d items (~%d bytes); extraction did not stop near the %d-byte cap", got, got*1024, maxMobileTotalBytes)
	}
}

// TestBudgetAddEntry checks the cap arithmetic directly.
func TestBudgetAddEntry(t *testing.T) {
	t.Cleanup(restoreMobileCaps(maxMobileTotalBytes, maxMobileEntries, maxMobileEntryBytes))
	maxMobileEntries = 3
	maxMobileTotalBytes = 1 << 30
	b := &mobileBudget{}
	for i := 0; i < 3; i++ {
		if !b.addEntry(1) {
			t.Fatalf("entry %d wrongly rejected", i)
		}
	}
	if b.addEntry(1) || b.err == nil {
		t.Fatal("4th entry should trip the entry cap and set err")
	}
}

// TestContextCancel: a pre-cancelled ctx drains zero items and closes the channel (no hang).
func TestContextCancel(t *testing.T) {
	apk := makeAPK(t, map[string][]byte{"res/raw/x.json": []byte(`{"api_key":"` + awsKey + `"}`)})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch, err := Extract(ctx, apk, defaultOpts())
	if err != nil {
		t.Fatal(err)
	}
	if items := drainTexts(ch); len(items) != 0 {
		t.Errorf("cancelled ctx should emit 0 items, got %d", len(items))
	}
}

// TestExtractNonZip: a non-zip file returns an error (so cmdMobile can exit non-zero).
func TestExtractNonZip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "not.apk")
	if err := os.WriteFile(p, []byte("this is not a zip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Extract(context.Background(), p, defaultOpts()); err == nil {
		t.Fatal("Extract of a non-zip should error")
	}
}

func restoreMobileCaps(tb int64, en int, eb int64) func() {
	return func() { maxMobileTotalBytes, maxMobileEntries, maxMobileEntryBytes = tb, en, eb }
}

// --- test helpers ---

func feedItems(items ...model.Item) <-chan model.Item {
	ch := make(chan model.Item, len(items))
	for _, it := range items {
		ch <- it
	}
	close(ch)
	return ch
}

func paths(items []model.Item) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.Path
	}
	return out
}

func findingTypes(fs []model.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Type
	}
	return out
}

func hasType(fs []model.Finding, sub string) bool {
	for _, f := range fs {
		if strings.Contains(f.Type, sub) {
			return true
		}
	}
	return false
}
