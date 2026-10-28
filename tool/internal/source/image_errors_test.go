package source

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

type failingImage struct {
	v1.Image
	configErr error
	layersErr error
	layers    []v1.Layer
}

func (img failingImage) ConfigFile() (*v1.ConfigFile, error) {
	if img.configErr != nil {
		return nil, img.configErr
	}
	return img.Image.ConfigFile()
}
func (img failingImage) Layers() ([]v1.Layer, error) { return img.layers, img.layersErr }

type failingLayer struct{ v1.Layer }

func (f failingLayer) Digest() (v1.Hash, error) { return v1.Hash{}, errors.New("unreadable digest") }

func (f failingLayer) Uncompressed() (io.ReadCloser, error) {
	return nil, errors.New("unreadable layer")
}

func TestImageFailuresReachTheItemStream(t *testing.T) {
	for name, img := range map[string]v1.Image{
		"config":         failingImage{Image: empty.Image, configErr: errors.New("unreadable config")},
		"layers":         failingImage{Image: empty.Image, layersErr: errors.New("unreadable layer list")},
		"open":           failingImage{Image: empty.Image, layers: []v1.Layer{failingLayer{}}},
		"malformed tar":  failingImage{Image: empty.Image, layers: []v1.Layer{fakeLayer{[]byte("not a tar")}}},
		"truncated file": failingImage{Image: empty.Image, layers: []v1.Layer{fakeLayer{makeTar(t, 1, bytes.Repeat([]byte("x"), 1000))[:520]}}},
	} {
		t.Run(name, func(t *testing.T) {
			ch := make(chan model.Item, 32)
			fi := newFinalIndex()
			emitImage(context.Background(), ch, img, "image", 1024, nil, &imageBudget{}, fi)
			close(ch)
			failed := false
			for it := range ch {
				failed = failed || it.Error != nil
			}
			if !failed || !fi.Aborted() {
				t.Fatalf("source failure was certified complete: diagnostic=%v aborted=%v", failed, fi.Aborted())
			}
		})
	}
}

func TestImageOversizeAndLayerCapAreIncomplete(t *testing.T) {
	for _, mode := range []string{"file", "layers", "config"} {
		t.Run(mode, func(t *testing.T) {
			t.Cleanup(restoreImageCaps(maxImageTotalBytes, maxImageEntries, maxImageLayers))
			var img v1.Image = failingImage{Image: empty.Image, layers: []v1.Layer{fakeLayer{makeTar(t, 1, []byte("oversized text"))}}}
			if mode == "layers" {
				maxImageLayers = 0
			}
			if mode == "config" {
				cfg, err := empty.Image.ConfigFile()
				if err != nil {
					t.Fatal(err)
				}
				cfg.Config.Env = []string{strings.Repeat("x", 20)}
				img, err = mutate.ConfigFile(empty.Image, cfg)
				if err != nil {
					t.Fatal(err)
				}
			}
			ch := make(chan model.Item, 32)
			emitImage(context.Background(), ch, img, "image", 4, nil, &imageBudget{}, newFinalIndex())
			close(ch)
			failed := false
			for it := range ch {
				failed = failed || it.Error != nil
			}
			if !failed {
				t.Fatal("extraction cap was silent")
			}
		})
	}
}

func TestImageBudgetCannotOverflow(t *testing.T) {
	b := imageBudget{totalBytes: 1}
	if b.addEntry(math.MaxInt64) || b.err == nil {
		t.Fatal("image byte budget overflowed")
	}
}
