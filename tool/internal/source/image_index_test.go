package source

import (
	"context"
	"errors"
	"fmt"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestOCIIndexDescriptorBudgetIsSharedAcrossBranches(t *testing.T) {
	idx := &testImageIndex{manifest: &v1.IndexManifest{}, images: map[v1.Hash]v1.Image{indexHash(1): empty.Image}}
	idx.manifest.Manifests = append(idx.manifest.Manifests, v1.Descriptor{Digest: indexHash(1), MediaType: types.OCIManifestSchema1})
	for i := 0; i < maxImageIndexDescriptors; i++ {
		idx.manifest.Manifests = append(idx.manifest.Manifests, v1.Descriptor{Digest: indexHash(1), MediaType: types.OCIManifestSchema1})
	}
	imgs, err := flattenIndex(idx)
	if err != nil || len(imgs) != 2 {
		t.Fatalf("descriptor cap lost image or diagnostic: images=%d err=%v", len(imgs), err)
	}
	if _, err := imgs[1].ConfigFile(); err == nil {
		t.Fatal("descriptor cap was silently ignored")
	}
}

func TestOCIIndexCancellationPrecedesManifestRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := flattenIndexContext(ctx, &testImageIndex{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled OCI traversal: %v", err)
	}
}

type imageIndexStub = v1.ImageIndex

type testImageIndex struct {
	imageIndexStub
	manifest *v1.IndexManifest
	err      error
	indexes  map[v1.Hash]v1.ImageIndex
	images   map[v1.Hash]v1.Image
}

func (idx *testImageIndex) IndexManifest() (*v1.IndexManifest, error) { return idx.manifest, idx.err }
func (idx *testImageIndex) Image(h v1.Hash) (v1.Image, error) {
	if img, ok := idx.images[h]; ok {
		return img, nil
	}
	return nil, errors.New("missing image")
}
func (idx *testImageIndex) ImageIndex(h v1.Hash) (v1.ImageIndex, error) {
	if child, ok := idx.indexes[h]; ok {
		return child, nil
	}
	return nil, errors.New("missing child index")
}
func indexHash(i int) v1.Hash { return v1.Hash{Algorithm: "sha256", Hex: fmt.Sprintf("%064x", i)} }

func TestIndexFailuresPreserveHealthyImagesAndDiagnostics(t *testing.T) {
	for _, mode := range []string{"missing child", "unreadable child", "cycle", "nil child", "nil manifest", "nil image"} {
		t.Run(mode, func(t *testing.T) {
			good, bad := indexHash(1), indexHash(2)
			idx := &testImageIndex{
				manifest: &v1.IndexManifest{Manifests: []v1.Descriptor{
					{Digest: good, MediaType: types.OCIManifestSchema1},
					{Digest: bad, MediaType: types.OCIImageIndex},
				}},
				images: map[v1.Hash]v1.Image{good: empty.Image}, indexes: map[v1.Hash]v1.ImageIndex{},
			}
			switch mode {
			case "unreadable child":
				idx.indexes[bad] = &testImageIndex{err: errors.New("bad index")}
			case "cycle":
				idx.indexes[bad] = idx
			case "nil child":
				idx.indexes[bad] = nil
			case "nil manifest":
				idx.indexes[bad] = &testImageIndex{}
			case "nil image":
				idx.manifest.Manifests[1].MediaType = types.OCIManifestSchema1
				idx.images[bad] = nil
			}
			imgs, err := flattenIndex(idx)
			if err != nil {
				t.Fatalf("healthy sibling lost to child error: %v", err)
			}
			readable, failed := 0, 0
			for _, img := range imgs {
				if _, err := img.ConfigFile(); err != nil {
					failed++
				} else {
					readable++
				}
			}
			if readable != 1 || failed != 1 {
				t.Fatalf("readable=%d diagnostics=%d, want one each", readable, failed)
			}
		})
	}
}

func TestRepeatedOCIIndexIsNotACycle(t *testing.T) {
	h := indexHash(1)
	child := &testImageIndex{manifest: &v1.IndexManifest{Manifests: []v1.Descriptor{{Digest: indexHash(2), MediaType: types.OCIManifestSchema1}}}, images: map[v1.Hash]v1.Image{indexHash(2): empty.Image}}
	idx := &testImageIndex{manifest: &v1.IndexManifest{Manifests: []v1.Descriptor{
		{Digest: h, MediaType: types.OCIImageIndex}, {Digest: h, MediaType: types.OCIImageIndex},
	}}, indexes: map[v1.Hash]v1.ImageIndex{h: child}}
	imgs, err := flattenIndex(idx)
	if err != nil || len(imgs) != 1 {
		t.Fatalf("repeated completed index: images=%d err=%v", len(imgs), err)
	}
	if _, err := imgs[0].ConfigFile(); err != nil {
		t.Fatal(err)
	}
}

func TestOCIIndexDepthLimitPreservesHealthySiblings(t *testing.T) {
	child := &testImageIndex{manifest: &v1.IndexManifest{}}
	for i := 0; i < 34; i++ {
		h := indexHash(i + 100)
		child = &testImageIndex{manifest: &v1.IndexManifest{Manifests: []v1.Descriptor{{Digest: h, MediaType: types.OCIImageIndex}}}, indexes: map[v1.Hash]v1.ImageIndex{h: child}}
	}
	child.manifest.Manifests = append([]v1.Descriptor{{Digest: indexHash(1), MediaType: types.OCIManifestSchema1}}, child.manifest.Manifests...)
	child.images = map[v1.Hash]v1.Image{indexHash(1): empty.Image}
	imgs, err := flattenIndex(child)
	if err != nil || len(imgs) != 2 {
		t.Fatalf("depth limit lost healthy sibling: images=%d err=%v", len(imgs), err)
	}
	if _, err := imgs[1].ConfigFile(); err == nil {
		t.Fatal("depth limit did not produce a diagnostic")
	}
}
