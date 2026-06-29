package source

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"path/filepath"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/safehttp"
)

// writeImageTarball builds a 1-layer docker/OCI tarball from name->body files and returns its path.
func writeImageTarball(t *testing.T, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	layer, err := tarball.LayerFromReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "img.tar")
	ref, _ := name.NewTag("prowl-test:latest")
	if err := tarball.WriteToFile(path, ref, img); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestImageTarballLocalNoNetwork proves a local tarball scans end-to-end with the SSRF guard armed
// (AllowPrivate=false) — a local load must consult no transport, so no dial occurs.
func TestImageTarballLocalNoNetwork(t *testing.T) {
	safehttp.AllowPrivate.Store(false)
	path := writeImageTarball(t, map[string]string{"app/config.env": "AWS_SECRET=AKIA4MNQ2RST7UVWX9YZ\n"})
	ch, _, err := Image(context.Background(), path, ImageAuto, 1<<20, 5*time.Second, nil)
	if err != nil {
		t.Fatalf("Image(tarball): %v", err)
	}
	var found bool
	for it := range ch {
		if strings.Contains(it.Text, "AKIA4MNQ2RST7UVWX9YZ") {
			found = true
		}
	}
	if !found {
		t.Fatal("planted secret not found scanning a local tarball")
	}
}

// TestImageTarballMultiImage: a multi-image docker-save tar must scan EVERY image, not be rejected.
func TestImageTarballMultiImage(t *testing.T) {
	mk := func(secret string) v1.Image {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		body := "key=" + secret
		if err := tw.WriteHeader(&tar.Header{Name: "app/x.env", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
		tw.Close()
		layer, err := tarball.LayerFromReader(&buf)
		if err != nil {
			t.Fatal(err)
		}
		img, err := mutate.AppendLayers(empty.Image, layer)
		if err != nil {
			t.Fatal(err)
		}
		return img
	}
	ta, _ := name.NewTag("prowl-test/a:latest")
	tb, _ := name.NewTag("prowl-test/b:latest")
	path := filepath.Join(t.TempDir(), "multi.tar")
	if err := tarball.MultiRefWriteToFile(path, map[name.Reference]v1.Image{
		ta: mk("AKIA4MNQ2RST7UVWX9YZ"), tb: mk("AKIA4ZX9QJ7K2MNPL3RS"),
	}); err != nil {
		t.Fatal(err)
	}
	ch, _, err := Image(context.Background(), path, ImageTar, 1<<20, 5*time.Second, nil)
	if err != nil {
		t.Fatalf("Image(multi-image tar): %v", err)
	}
	found := map[string]bool{}
	for it := range ch {
		if strings.Contains(it.Text, "AKIA4MNQ2RST7UVWX9YZ") {
			found["a"] = true
		}
		if strings.Contains(it.Text, "AKIA4ZX9QJ7K2MNPL3RS") {
			found["b"] = true
		}
	}
	if !found["a"] || !found["b"] {
		t.Errorf("multi-image tarball: both images' secrets must be scanned, got %v", found)
	}
}

// TestFinalFSMarking exercises the flatten index + MarkFinalImage across whiteout, overwrite, opaque,
// top-layer, config, and aborted cases.
func TestFinalFSMarking(t *testing.T) {
	fi := newFinalIndex()
	const L = "img"
	fi.apply(L, 0, "app/whiteme.txt")
	fi.apply(L, 0, "app/keep.txt")
	fi.apply(L, 0, "app/over.txt")
	fi.apply(L, 0, "data/a.txt")
	fi.apply(L, 1, "app/.wh.whiteme.txt") // plain whiteout
	fi.apply(L, 1, "app/over.txt")        // overwrite -> layer0 copy is historical
	fi.apply(L, 1, "app/new.txt")
	fi.apply(L, 2, "data/.wh..wh..opq") // opaque: hides lower-layer data/*
	fi.apply(L, 2, "data/b.txt")
	fi.apply(L, 0, "secrets/db.txt")
	fi.apply(L, 1, ".wh.secrets") // directory whiteout removes the whole secrets/ subtree
	fi.apply(L, 1, "app/.wh.")    // malformed empty whiteout must be ignored (not sweep app/)

	cases := []struct {
		path string
		want string // "true" | "false" | "nil"
	}{
		{L + "|layer0:app/whiteme.txt", "false"}, // whiteouted
		{L + "|layer0:app/keep.txt", "true"},     // survives
		{L + "|layer0:app/over.txt", "false"},    // overwritten by layer1
		{L + "|layer1:app/over.txt", "true"},     // the surviving copy
		{L + "|layer1:app/new.txt", "true"},      // top layer
		{L + "|layer0:data/a.txt", "false"},      // hidden by opaque
		{L + "|layer2:data/b.txt", "true"},       // added with the opaque
		{L + "|layer0:secrets/db.txt", "false"},  // dir whiteout removed the subtree
		{L + "|image:config/env", "nil"},         // config: never marked
	}
	fs := make([]model.Finding, len(cases))
	for i, c := range cases {
		fs[i] = model.Finding{Path: c.path}
	}
	MarkFinalImage(fs, []*FinalIndex{fi})
	for i, c := range cases {
		got := "nil"
		if fs[i].InFinalImage != nil {
			got = strconv.FormatBool(*fs[i].InFinalImage)
		}
		if got != c.want {
			t.Errorf("%s: InFinalImage=%s, want %s", c.path, got, c.want)
		}
	}

	fi.markAborted() // a budget-aborted index must never assert a verdict
	if !fi.Aborted() {
		t.Error("markAborted must make Aborted() report true (drives the fail-closed exit code)")
	}
	abort := []model.Finding{{Path: L + "|layer0:app/keep.txt"}}
	MarkFinalImage(abort, []*FinalIndex{fi})
	if abort[0].InFinalImage != nil {
		t.Error("aborted index must yield nil (unknown), not a verdict")
	}

	// foreign-index: an index that never folded a finding's label must read as unknown there, so a
	// multi-image batch never cross-marks (the wrong index is consulted first here on purpose).
	a, b := newFinalIndex(), newFinalIndex()
	a.apply("imgA", 0, "x/key.txt")
	b.apply("imgB", 0, "y/key.txt")
	multi := []model.Finding{
		{Path: "imgB|layer0:y/key.txt"},
		{Path: "imgA|layer0:x/key.txt"},
	}
	MarkFinalImage(multi, []*FinalIndex{a, b})
	for _, f := range multi {
		if f.InFinalImage == nil || !*f.InFinalImage {
			t.Errorf("%s: want InFinalImage=true from its own index, got %v", f.Path, f.InFinalImage)
		}
	}
}

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
		ok = emitLayer(context.Background(), ch, "", 0, fakeLayer{tarBytes}, 1<<20, nil, b, newFinalIndex(), "")
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
		ok = emitLayer(context.Background(), ch, "", 0, fakeLayer{tarBytes}, 1<<20, nil, b, newFinalIndex(), "")
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
		ok = emitLayer(context.Background(), ch, "", 0, fakeLayer{tarBytes}, 1<<20, nil, b, newFinalIndex(), "")
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

	_, _, err := Image(context.Background(), "127.0.0.1:9/foo/bar:latest", ImageRef, 1<<20, 2*time.Second, nil)
	if err == nil {
		t.Fatal("pull of an internal-address registry ref should fail (SSRF guard)")
	}
	if !strings.Contains(err.Error(), "refusing to connect to internal address") {
		t.Fatalf("error %q does not show the SSRF dial guard fired; crane may be using an unguarded transport", err)
	}
}
