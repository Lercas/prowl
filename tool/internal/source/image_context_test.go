package source

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/secretindex"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

const imageOwnedKey = "AKIANAFGYOEYPXU1DSYP"

func imageTestPipeline(t *testing.T) *scan.Pipeline {
	t.Helper()
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	id, err := secretindex.LoadIdentity(filepath.Join(t.TempDir(), "index"), true)
	if err != nil {
		t.Fatal(err)
	}
	return scan.New(scan.Options{Detector: detect.New(tax), IdentityKey: bytes.Repeat([]byte{7}, 32), ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location})
}

func imageTarBytes(t *testing.T, entries []struct {
	name string
	body []byte
}) []byte {
	t.Helper()
	var out bytes.Buffer
	w := tar.NewWriter(&out)
	for _, e := range entries {
		if err := w.WriteHeader(&tar.Header{Name: e.name, Mode: 0600, Typeflag: tar.TypeReg, Size: int64(len(e.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestImageObservedDigestsAndFinalizedOccurrenceIdentity(t *testing.T) {
	first := []byte("AWS=" + imageOwnedKey + "\n")
	second := []byte("AWS=" + imageOwnedKey + "\n# second physical entry\n")
	raw := imageTarBytes(t, []struct {
		name string
		body []byte
	}{{"prod #?秘密.env", first}, {"prod #?秘密.env", second}})
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil })
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Config.Env = []string{"AWS=" + imageOwnedKey}
	img, err = mutate.ConfigFile(img, cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "image #?.tar")
	ref, _ := name.NewTag("owned:fixture")
	if err := tarball.WriteToFile(p, ref, img); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := loadTarball(p)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loaded[0].RawManifest()
	if err != nil {
		t.Fatal(err)
	}
	config, err := loaded[0].RawConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	coverage := model.NewCoverage()
	ctx := model.WithCoverage(t.Context(), coverage)
	ctx = model.WithProvenance(ctx, map[string]any{"commit": strings.Repeat("f", 40), "digest": strings.Repeat("a", 64)})
	ctx = model.WithSourceLocator(ctx, func(string) string { return "https://foreign.invalid/old" })
	ch, fi, err := Image(ctx, p, ImageTar, 1<<20, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	var fs []model.Finding
	pipeline := imageTestPipeline(t)
	for it := range ch {
		if it.Error != nil {
			t.Fatal("valid local image produced an error")
		}
		if it.ImageScope == nil || it.ImagePath != it.Path || it.Meta["commit"] != nil {
			t.Fatal("image acquisition inherited foreign provenance or lost private coordinates")
		}
		u, err := url.Parse(it.ArtifactURI)
		if err != nil || u.Scheme != "image+file" || u.Path != p || it.Meta["source_url"] != it.ArtifactURI {
			t.Fatal("image URI lost source components")
		}
		if it.Meta["image_digest"] != imageBytesDigest(manifest) || it.Meta["config_digest"] != imageBytesDigest(config) {
			t.Fatal("manifest/config observation digest mismatch")
		}
		for _, f := range pipeline.Findings(t.Context(), it) {
			if f.Type == "aws_access_key_id" {
				fs = append(fs, f)
			}
		}
	}
	if len(fs) != 3 {
		t.Fatalf("expected config and two physical file findings, got %d", len(fs))
	}
	before := map[string]string{}
	for _, f := range fs {
		before[f.IndexLocationID] = f.OccurrenceID
		if f.Provenance["layer_diff_id"] != "" {
			t.Fatal("layer digest was stamped before producer finalization")
		}
	}
	fs = MarkFinalImage(fs, []*FinalIndex{fi}, bytes.Repeat([]byte{7}, 32))
	physical := []model.Finding{}
	for _, f := range fs {
		if strings.Contains(f.ImagePath, "|layer") {
			physical = append(physical, f)
			if f.Provenance["layer_diff_id"] != imageBytesDigest(raw) || f.OccurrenceID == before[f.IndexLocationID] || f.InFinalImage == nil {
				t.Fatal("finalization lost full layer digest or occurrence update")
			}
		} else if f.Provenance["layer_diff_id"] != "" {
			t.Fatal("config borrowed a layer digest")
		}
	}
	if len(physical) != 2 || physical[0].ImageEntry == physical[1].ImageEntry || physical[0].IndexLocationID == physical[1].IndexLocationID || physical[0].OccurrenceID == physical[1].OccurrenceID || *physical[0].InFinalImage || !*physical[1].InFinalImage {
		t.Fatal("repeated TAR observations or flattened ownership collapsed")
	}
	if physical[0].Provenance["digest"] != imageBytesDigest(first) || physical[1].Provenance["digest"] != imageBytesDigest(second) {
		t.Fatal("file digest described the layer or decoded view")
	}
	complete, _, _ := coverage.Snapshot()
	if !complete {
		t.Fatal("valid image is incomplete")
	}
	for _, f := range fs {
		copy := f
		model.UpdateOccurrenceIdentity(&copy, bytes.Repeat([]byte{7}, 32))
		if copy.OccurrenceID != f.OccurrenceID {
			t.Fatal("finalized identity is inconsistent with provenance")
		}
	}
}

type observedImageLayer struct {
	v1.Layer
	raw      []byte
	closeErr bool
	tailErr  bool
}

func (l observedImageLayer) Uncompressed() (io.ReadCloser, error) {
	return &observedImageStream{Reader: bytes.NewReader(l.raw), closeErr: l.closeErr, tailErr: l.tailErr}, nil
}

type observedImageStream struct {
	*bytes.Reader
	closeErr, tailErr bool
}

func (r *observedImageStream) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err == io.EOF && r.tailErr {
		return n, errors.New("PRIVATE_TRANSPORT_FAILURE")
	}
	return n, err
}
func (r *observedImageStream) Close() error {
	if r.closeErr {
		return errors.New("PRIVATE_CLOSE_FAILURE")
	}
	return nil
}

func TestImageLayerDigestRequiresCompleteStreamAndClose(t *testing.T) {
	raw := imageTarBytes(t, []struct {
		name string
		body []byte
	}{{"prod.env", []byte("AWS=" + imageOwnedKey)}})
	for _, mode := range []string{"complete", "tail", "close", "mismatch"} {
		t.Run(mode, func(t *testing.T) {
			coverage := model.NewCoverage()
			ctx := model.WithCoverage(t.Context(), coverage)
			ctx, _, err := imageContext(ctx, "image.tar", ImageTar, 1<<20, time.Second, nil)
			if err != nil {
				t.Fatal(err)
			}
			fi := newFinalIndex()
			ctx = withImageOrigin(ctx, "image.tar", 0, fi)
			if mode == "mismatch" {
				ctx = context.WithValue(ctx, imageLayerExpectedKey{}, strings.Repeat("a", 64))
			}
			ch := make(chan model.Item, 8)
			emitLayer(ctx, ch, "image.tar", 0, observedImageLayer{raw: raw, tailErr: mode == "tail", closeErr: mode == "close"}, 1<<20, nil, &imageBudget{}, fi, "")
			close(ch)
			pipeline := imageTestPipeline(t)
			var fs []model.Finding
			for it := range ch {
				if it.Error != nil && strings.Contains(it.Error.Error(), "PRIVATE_") {
					t.Fatal("raw layer error reflected private bytes")
				}
				for _, f := range pipeline.Findings(t.Context(), it) {
					if f.Type == "aws_access_key_id" {
						fs = append(fs, f)
					}
				}
			}
			if len(fs) != 1 {
				t.Fatal("readable member was discarded")
			}
			fs = MarkFinalImage(fs, []*FinalIndex{fi}, bytes.Repeat([]byte{7}, 32))
			wantDigest := mode == "complete" || mode == "mismatch"
			if (fs[0].Provenance["layer_diff_id"] != "") != wantDigest || fi.Aborted() != (mode != "complete") {
				t.Fatal("incomplete layer was given an unproven digest or complete status")
			}
			if mode != "complete" && fs[0].InFinalImage != nil {
				t.Fatal("incomplete image was certified flattened")
			}
		})
	}
}

func TestImageFailureDoesNotReflectSelectedCredentials(t *testing.T) {
	coverage := model.NewCoverage()
	ctx := model.WithCoverage(t.Context(), coverage)
	ch := ImageFailure(ctx, "https://alice:PRIVATE_AUTH@owned.invalid/image?sig=PRIVATE_QUERY", ImageRef, 1<<20, time.Second, nil)
	var items []model.Item
	for it := range ch {
		items = append(items, it)
	}
	raw, err := json.Marshal(items)
	if err != nil || bytes.Contains(raw, []byte("PRIVATE_")) || len(items) != 1 || items[0].Error == nil {
		t.Fatal("invalid image selection leaked or lost failure")
	}
	complete, _, _ := coverage.Snapshot()
	if complete {
		t.Fatal("failed image acquisition certified complete")
	}
}

func TestImageSameRelativeLabelUsesOwnFlattenIndex(t *testing.T) {
	var all []model.Finding
	var indexes []*FinalIndex
	pipeline := imageTestPipeline(t)
	for n := 0; n < 2; n++ {
		dir := t.TempDir()
		body := imageTarBytes(t, []struct {
			name string
			body []byte
		}{{"prod.env", []byte("AWS=" + imageOwnedKey)}})
		layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil })
		if err != nil {
			t.Fatal(err)
		}
		img, err := mutate.AppendLayers(empty.Image, layer)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			whiteout := imageTarBytes(t, []struct {
				name string
				body []byte
			}{{".wh.prod.env", nil}})
			top, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(whiteout)), nil })
			if err != nil {
				t.Fatal(err)
			}
			img, err = mutate.AppendLayers(img, top)
			if err != nil {
				t.Fatal(err)
			}
		}
		ref, _ := name.NewTag("owned:fixture")
		if err := tarball.WriteToFile(filepath.Join(dir, "same.tar"), ref, img); err != nil {
			t.Fatal(err)
		}
		t.Chdir(dir)
		ch, fi, err := Image(t.Context(), "same.tar", ImageTar, 1<<20, time.Second, nil)
		if err != nil {
			t.Fatal(err)
		}
		indexes = append(indexes, fi)
		for it := range ch {
			if it.Error != nil {
				t.Fatal("valid relative image failed")
			}
			for _, f := range pipeline.Findings(t.Context(), it) {
				if f.Type == "aws_access_key_id" {
					all = append(all, f)
				}
			}
		}
	}
	if len(all) != 2 || all[0].Path != all[1].Path || all[0].ImageScope == all[1].ImageScope || all[0].Fingerprint == all[1].Fingerprint {
		t.Fatal("relative display label collapsed acquisition identity")
	}
	all = MarkFinalImage(all, indexes, bytes.Repeat([]byte{7}, 32))
	if all[0].InFinalImage == nil || all[1].InFinalImage == nil || *all[0].InFinalImage || !*all[1].InFinalImage {
		t.Fatal("finding borrowed another acquisition's flatten map")
	}
}

type rawConfigImage struct {
	v1.Image
	raw []byte
}

func (img rawConfigImage) RawConfigFile() ([]byte, error) { return img.raw, nil }

func TestImageConfigDigestBindsActualRenderedSnapshot(t *testing.T) {
	base, err := empty.Image.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	base.Config.Env = []string{"AWS=" + imageOwnedKey}
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	fi := newFinalIndex()
	ch := make(chan model.Item, 16)
	ctx, _, err := imageContext(t.Context(), "snapshot.tar", ImageTar, 1<<20, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx = withImageOrigin(ctx, "snapshot.tar", 0, fi)
	emitImage(ctx, ch, rawConfigImage{Image: empty.Image, raw: raw}, "snapshot.tar", 1<<20, nil, &imageBudget{}, fi)
	close(ch)
	found, failed := false, false
	for it := range ch {
		failed = failed || it.Error != nil
		if strings.Contains(it.Text, imageOwnedKey) {
			found = true
			if it.Meta["config_digest"] != imageBytesDigest(raw) {
				t.Fatal("rendered config used metadata from a different snapshot")
			}
		}
	}
	if !found || !failed || !fi.Aborted() {
		t.Fatal("config mismatch lost observed text or certified the image")
	}
}
