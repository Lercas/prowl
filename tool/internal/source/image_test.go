package source

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/safehttp"
)

// fakeLayer is a minimal v1.Layer whose Uncompressed() returns a fixed in-memory tar. Only
// Uncompressed() is exercised by emitLayer; the rest satisfy the interface.
type fakeLayer struct{ tarBytes []byte }

func (f fakeLayer) Uncompressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(f.tarBytes)), nil
}
func (f fakeLayer) Compressed() (io.ReadCloser, error)  { return f.Uncompressed() }
func (f fakeLayer) Digest() (v1.Hash, error)            { return v1.Hash{}, nil }
func (f fakeLayer) DiffID() (v1.Hash, error)            { return v1.Hash{}, nil }
func (f fakeLayer) Size() (int64, error)                { return int64(len(f.tarBytes)), nil }
func (f fakeLayer) MediaType() (types.MediaType, error) { return types.OCILayer, nil }

// makeTar builds a tar whose entries each carry `body` under names file0..fileN-1.
func makeTar(t *testing.T, n int, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := 0; i < n; i++ {
		hdr := &tar.Header{Name: fmt.Sprintf("file%d.txt", i), Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func drainItems(ch <-chan model.Item) int {
	n := 0
	for range ch {
		n++
	}
	return n
}

// TestEmitLayerTotalBytesCap: the cumulative-bytes budget must abort a layer whose entries sum past the
// cap, even though each individual file is under the per-file --max-size.
func TestEmitLayerTotalBytesCap(t *testing.T) {
	defer restoreImageCaps(maxImageTotalBytes, maxImageEntries, maxImageLayers)
	maxImageTotalBytes = 2048 // tiny cap so a few 1 KiB files trip it
	maxImageEntries = 1_000_000
	maxImageLayers = 1000

	body := bytes.Repeat([]byte("A"), 1024) // 1 KiB per file, well under maxBytes below
	tarBytes := makeTar(t, 10, body)        // 10 KiB total >> 2 KiB cap

	ch := make(chan model.Item, 64)
	b := &imageBudget{}
	var ok bool
	go func() {
		defer close(ch)
		ok = emitLayer(context.Background(), ch, 0, fakeLayer{tarBytes}, 1<<20, nil, b)
	}()
	got := drainItems(ch)

	if ok {
		t.Error("emitLayer should return false (abort) once the total-bytes cap is blown")
	}
	if b.err == nil || !strings.Contains(b.err.Error(), "byte cap") {
		t.Errorf("budget error = %v, want a total-bytes cap abort", b.err)
	}
	if int64(got)*1024 > maxImageTotalBytes+1024 {
		t.Errorf("emitted %d files (~%d bytes) — extraction did not stop near the %d-byte cap", got, got*1024, maxImageTotalBytes)
	}
}

// TestEmitLayerEntryCap: the entry-count budget must abort a tar with too many entries (a bomb of empty
// entries exhausts CPU even with zero body bytes).
func TestEmitLayerEntryCap(t *testing.T) {
	defer restoreImageCaps(maxImageTotalBytes, maxImageEntries, maxImageLayers)
	maxImageTotalBytes = 1 << 30
	maxImageEntries = 5
	maxImageLayers = 1000

	tarBytes := makeTar(t, 50, []byte("x")) // 50 entries, cap is 5

	ch := make(chan model.Item, 128)
	b := &imageBudget{}
	var ok bool
	go func() {
		defer close(ch)
		ok = emitLayer(context.Background(), ch, 0, fakeLayer{tarBytes}, 1<<20, nil, b)
	}()
	drainItems(ch)

	if ok {
		t.Error("emitLayer should return false (abort) once the entry cap is blown")
	}
	if b.err == nil || !strings.Contains(b.err.Error(), "entry cap") {
		t.Errorf("budget error = %v, want an entry-count cap abort", b.err)
	}
	if b.entries > maxImageEntries+1 {
		t.Errorf("processed %d entries, should have stopped at the %d cap", b.entries, maxImageEntries)
	}
}

// TestEmitLayerUnderBudgetScans confirms a legitimate under-budget layer is fully scanned.
func TestEmitLayerUnderBudgetScans(t *testing.T) {
	defer restoreImageCaps(maxImageTotalBytes, maxImageEntries, maxImageLayers)
	maxImageTotalBytes = 1 << 30
	maxImageEntries = 1000
	maxImageLayers = 1000

	tarBytes := makeTar(t, 1, []byte(`aws = "AKIA4MNQ2RST7UVWX9YZ"`))

	ch := make(chan model.Item, 8)
	b := &imageBudget{}
	var ok bool
	go func() {
		defer close(ch)
		ok = emitLayer(context.Background(), ch, 0, fakeLayer{tarBytes}, 1<<20, nil, b)
	}()
	got := drainItems(ch)

	if !ok {
		t.Errorf("under-budget layer wrongly aborted: %v", b.err)
	}
	if got != 1 {
		t.Errorf("emitted %d items, want 1 (legitimate layer must still be scanned)", got)
	}
}

func restoreImageCaps(tb int64, en, ly int) func() {
	return func() { maxImageTotalBytes, maxImageEntries, maxImageLayers = tb, en, ly }
}

// TestImageSSRFGuard: a ref whose registry host is an internal address (loopback, standing in for cloud
// metadata) must be refused at dial time by safehttp's guarded transport, surfacing ErrBlockedAddress.
func TestImageSSRFGuard(t *testing.T) {
	defer func() { safehttp.AllowPrivate.Store(false) }()
	safehttp.AllowPrivate.Store(false)

	_, err := Image(context.Background(), "127.0.0.1:9/foo/bar:latest", 1<<20, 2*time.Second, nil)
	if err == nil {
		t.Fatal("pull of an internal-address registry ref should fail (SSRF guard)")
	}
	if !strings.Contains(err.Error(), "refusing to connect to internal address") {
		t.Fatalf("error %q does not show the SSRF dial guard fired; crane may be using an unguarded transport", err)
	}
}
