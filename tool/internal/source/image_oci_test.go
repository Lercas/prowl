package source

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func TestLocalOCICompatibilityAndPartialFailure(t *testing.T) {
	img, err := tarball.ImageFromPath(writeImageTarball(t, map[string]string{"prod.env": "AWS = AKIANAFGYOEYPXU1DSYP"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	lp, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	if err := lp.AppendImage(img); err != nil {
		t.Fatal(err)
	}
	for _, failed := range []bool{false, true} {
		if failed {
			if err := lp.AppendDescriptor(v1.Descriptor{Digest: indexHash(900), MediaType: "application/vnd.oci.image.index.v1+json"}); err != nil {
				t.Fatal(err)
			}
		}
		ch, fi, err := Image(context.Background(), dir, ImageOCIDir, 1<<20, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		found, diagnostic := false, false
		for it := range ch {
			found = found || strings.Contains(it.Text, "AKIANAFGYOEYPXU1DSYP")
			diagnostic = diagnostic || it.Error != nil
		}
		if !found || diagnostic != failed || fi.Aborted() != failed {
			t.Fatalf("failed=%v: secret=%v diagnostic=%v aborted=%v", failed, found, diagnostic, fi.Aborted())
		}
	}
}

func TestOCIMetadataCacheAndSharedBudget(t *testing.T) {
	dir := t.TempDir()
	h := indexHash(1)
	blobs := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blobs, h.Hex), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &ociStore{ctx: context.Background(), dir: dir, cache: map[v1.Hash][]byte{}, bytes: maxOCIMetadataTotalBytes - 4}
	for i := 0; i < 2; i++ {
		if raw, err := s.metadata(h); err != nil || string(raw) != "data" {
			t.Fatalf("cached blob read %d: %q %v", i, raw, err)
		}
	}
	if s.bytes != maxOCIMetadataTotalBytes {
		t.Fatal("shared metadata was charged more than once")
	}
	if _, err := s.metadata(indexHash(2)); err == nil {
		t.Fatal("metadata budget ignored")
	}
	s = &ociStore{ctx: context.Background(), dir: dir, cache: map[v1.Hash][]byte{}, bytes: maxOCIMetadataTotalBytes - 3}
	if _, err := s.metadata(h); !errors.Is(err, errSourceTooLarge) {
		t.Fatalf("remaining metadata budget ignored before allocation: %v", err)
	}
}

func TestOCIBlobRejectsSymlinksAndInvalidDigests(t *testing.T) {
	dir := t.TempDir()
	blobs := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobs, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "external")
	if err := os.WriteFile(target, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(blobs, indexHash(1).Hex)); err != nil {
		t.Fatal(err)
	}
	s := &ociStore{ctx: context.Background(), dir: dir}
	for _, h := range []v1.Hash{indexHash(1), {Algorithm: "../..", Hex: "external"}} {
		if f, err := s.openBlob(h); err == nil {
			_ = f.Close()
			t.Fatal("unsafe OCI blob accepted")
		}
	}
}

func TestOCIIndexMetadataIsBoundedBeforeJSONParsing(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxImageMetadataBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, err = loadOCILayout(context.Background(), dir)
	if err == nil || !strings.Contains(err.Error(), "max-size") {
		t.Fatalf("oversized metadata reached JSON parser: %v", err)
	}
}
