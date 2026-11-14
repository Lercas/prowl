package source

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func TestImageLabelsRemainDistinct(t *testing.T) {
	inputs := []struct {
		arg  string
		i, n int
	}{
		{"a|b.tar", 0, 1}, {"a_b.tar", 0, 1}, {"a%7Cb.tar", 0, 1},
		{"save.tar#0", 0, 1}, {"save.tar", 0, 2}, {"save.tar", 1, 2},
	}
	seen := map[string]bool{}
	for _, in := range inputs {
		label := imageLabel(in.arg, in.i, in.n)
		if seen[label] {
			t.Fatalf("image label collision: %q", label)
		}
		seen[label] = true
	}
}

func dockerSaveBytes(t *testing.T, tagMode string, broken bool) []byte {
	t.Helper()
	layers := [][]byte{makeTar(t, 1, []byte("AWS = \"AKIANAFGYOEYPXU1DSYP\"")), makeTar(t, 1, []byte("AWS = \"AKIA4ZX9QJ7K2MNPL3RS\""))}
	var manifest tarball.Manifest
	files := map[string][]byte{}
	for i, suffix := range []string{"a", "b"} {
		digest, _, err := v1.SHA256(bytes.NewReader(layers[i]))
		if err != nil {
			t.Fatal(err)
		}
		cfg := v1.ConfigFile{RootFS: v1.RootFS{Type: "layers", DiffIDs: []v1.Hash{digest}}}
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		files[suffix+".json"] = raw
		files[suffix+".tar"] = layers[i]
		var tags []string
		switch tagMode {
		case "duplicate":
			tags = []string{"local-test:latest"}
		case "invalid":
			tags = []string{"not a tag"}
		}
		manifest = append(manifest, tarball.Descriptor{Config: suffix + ".json", RepoTags: tags, Layers: []string{suffix + ".tar"}})
	}
	if broken {
		manifest[1].Config = "missing.json"
	}
	rawManifest, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	files["manifest.json"] = rawManifest
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestTarballSelectsEveryDescriptorWithoutDependingOnTags(t *testing.T) {
	for _, tagMode := range []string{"untagged", "duplicate", "invalid"} {
		t.Run(tagMode, func(t *testing.T) {
			raw := dockerSaveBytes(t, tagMode, false)
			imgs, err := imagesFromTar(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }, "save.tar")
			if err != nil || len(imgs) != 2 {
				t.Fatalf("descriptor loss: n=%d err=%v", len(imgs), err)
			}
			ch := make(chan model.Item, 32)
			fi := newFinalIndex()
			budget := &imageBudget{}
			for i, img := range imgs {
				emitImage(context.Background(), ch, img, imageLabel("save.tar", i, len(imgs)), 1<<20, nil, budget, fi)
			}
			close(ch)
			found := map[string]bool{}
			for it := range ch {
				if it.Error != nil {
					t.Fatal(it.Error)
				}
				for _, key := range []string{"AKIANAFGYOEYPXU1DSYP", "AKIA4ZX9QJ7K2MNPL3RS"} {
					found[key] = found[key] || strings.Contains(it.Text, key)
				}
			}
			if !found["AKIANAFGYOEYPXU1DSYP"] || !found["AKIA4ZX9QJ7K2MNPL3RS"] {
				t.Fatal("distinct descriptor contents were lost")
			}
		})
	}
}

func TestBrokenTarDescriptorPreservesSiblingsAndError(t *testing.T) {
	raw := dockerSaveBytes(t, "untagged", true)
	imgs, err := imagesFromTar(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }, "save.tar")
	if err != nil || len(imgs) != 2 {
		t.Fatalf("descriptor positions lost: n=%d err=%v", len(imgs), err)
	}
	ch := make(chan model.Item, 32)
	fi := newFinalIndex()
	budget := &imageBudget{}
	for i, img := range imgs {
		emitImage(context.Background(), ch, img, imageLabel("save.tar", i, len(imgs)), 1<<20, nil, budget, fi)
	}
	close(ch)
	failed, found := false, false
	for it := range ch {
		failed = failed || (it.Error != nil && strings.Contains(it.Path, "#1"))
		found = found || strings.Contains(it.Text, "AKIANAFGYOEYPXU1DSYP")
	}
	if !failed || !found || !fi.Aborted() {
		t.Fatal("partial tarball was certified complete or lost a readable sibling")
	}
}

func TestPrefixedTarKeepsSeekSemantics(t *testing.T) {
	r := &prefixedImageTar{prefix: []byte("abc"), original: seekableImageInput{bytes.NewReader([]byte("def"))}}
	if pos, err := r.Seek(-4, io.SeekEnd); pos != 2 || err != nil {
		t.Fatalf("seek into prefix: pos=%d err=%v", pos, err)
	}
	raw, err := io.ReadAll(r)
	if err != nil || string(raw) != "cdef" {
		t.Fatalf("prefix read=%q err=%v", raw, err)
	}
	if pos, err := r.Seek(-4, io.SeekCurrent); pos != 2 || err != nil {
		t.Fatalf("relative seek: pos=%d err=%v", pos, err)
	}
	if _, err := r.Seek(-10, io.SeekEnd); err == nil {
		t.Fatal("negative seek accepted")
	}
	raw, err = io.ReadAll(r)
	if err != nil || string(raw) != "cdef" {
		t.Fatalf("invalid seek changed position: %q err=%v", raw, err)
	}
}

type seekableImageInput struct{ *bytes.Reader }

func (seekableImageInput) Close() error { return nil }

func TestImageMetadataCapPrecedesAllocation(t *testing.T) {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Typeflag: tar.TypeReg, Size: maxImageMetadataBytes + 1}); err != nil {
		t.Fatal(err)
	}
	_, err := readImageManifest(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw.Bytes())), nil })
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized metadata was read: %v", err)
	}
}

func TestImageStdinCancellationInterruptsBlockedRead(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, err := loadImageStdin(ctx, r); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error=%v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("image stdin remained blocked")
	}
}

func TestCompressedLayerChecksTrailerAfterTarEOF(t *testing.T) {
	var raw bytes.Buffer
	gw := gzip.NewWriter(&raw)
	if _, err := gw.Write(makeTar(t, 1, []byte("visible content"))); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	compressed := raw.Bytes()
	compressed[len(compressed)-8] ^= 1
	ch := make(chan model.Item, 8)
	fi := newFinalIndex()
	emitLayer(context.Background(), ch, "image", 0, gzipImageLayer{fakeLayer: fakeLayer{compressed}}, 1024, nil, &imageBudget{}, fi, "")
	close(ch)
	failed, found := false, false
	for it := range ch {
		failed = failed || it.Error != nil
		found = found || it.Text == "visible content"
	}
	if !failed || !found || !fi.Aborted() {
		t.Fatal("compressed trailer failure was hidden")
	}
}

type gzipImageLayer struct{ fakeLayer }

func (f gzipImageLayer) Uncompressed() (io.ReadCloser, error) {
	return gzip.NewReader(bytes.NewReader(f.tarBytes))
}

func TestWhiteoutPreservesSameLayerFile(t *testing.T) {
	fi := newFinalIndex()
	fi.apply("img", 0, "prod.env")
	fi.apply("img", 1, "prod.env")
	fi.apply("img", 1, ".wh.prod.env")
	if final, known := fi.inFinal("img", 1, "/prod.env"); !known || !final {
		t.Fatal("whiteout removed same-layer content")
	}
}

func TestRepeatedPathInOneLayerIsNotCertifiedAsFinal(t *testing.T) {
	fi := newFinalIndex()
	fi.apply("image", 0, "prod.env")
	fi.apply("image", 0, "prod.env")
	fs := MarkFinalImage([]model.Finding{{Path: "image|layer0:prod.env"}}, []*FinalIndex{fi})
	if fs[0].InFinalImage != nil {
		t.Fatal("finding without an entry identity got a definitive final-image verdict")
	}
}

func TestRepeatedLayerEntriesKeepTheirOwnFinalVerdict(t *testing.T) {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, value := range []string{"first secret", "last secret"} {
		if err := tw.WriteHeader(&tar.Header{Name: "prod.env", Typeflag: tar.TypeReg, Size: int64(len(value)), Mode: 0o600}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	ch := make(chan model.Item, 8)
	fi := newFinalIndex()
	if !emitLayer(context.Background(), ch, "image", 0, fakeLayer{raw.Bytes()}, 1024, nil, &imageBudget{}, fi, "") {
		t.Fatal("layer failed")
	}
	close(ch)
	var fs []model.Finding
	for it := range ch {
		fs = append(fs, model.Finding{Path: it.Path, ImageEntry: it.ImageEntry})
	}
	MarkFinalImage(fs, []*FinalIndex{fi})
	if len(fs) != 2 || fs[0].InFinalImage == nil || *fs[0].InFinalImage || fs[1].InFinalImage == nil || !*fs[1].InFinalImage {
		t.Fatalf("repeated layer entries: %+v", fs)
	}
}

func TestFinalImageParentReplacementAndUnknownReset(t *testing.T) {
	fi := newFinalIndex()
	fi.apply("img", 0, "app/prod.env")
	fi.apply("img", 1, "app")
	if final, known := fi.inFinal("img", 0, "/app/prod.env"); !known || final {
		t.Fatal("child survived replacement of its directory by a file")
	}
	fi = newFinalIndex()
	fi.apply("img", 0, "app/prod.env")
	fi.applyType("img", 1, "app", tar.TypeDir)
	fs := MarkFinalImage([]model.Finding{{Path: "img|layer0:app/prod.env"}}, []*FinalIndex{fi})
	if fs[0].InFinalImage == nil || !*fs[0].InFinalImage {
		t.Fatal("directory header hid a surviving child")
	}
	fi.markAborted()
	MarkFinalImage(fs, []*FinalIndex{fi})
	if fs[0].InFinalImage != nil {
		t.Fatal("stale final-image verdict survived an incomplete index")
	}
}
