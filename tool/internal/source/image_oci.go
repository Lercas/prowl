package source

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const maxOCIMetadataTotalBytes int64 = 128 << 20

// ociStore bounds actual metadata reads before handing JSON to the image library. Shared blobs
// are cached once, so the cumulative budget also bounds retained raw metadata across the layout.
type ociStore struct {
	ctx   context.Context
	dir   string
	mu    sync.Mutex
	bytes int64
	cache map[v1.Hash][]byte
}

func readLocalOCIIndex(ctx context.Context, dir string) (v1.ImageIndex, error) {
	s := &ociStore{ctx: ctx, dir: dir, cache: map[v1.Hash][]byte{}}
	raw, err := s.readMetadata(func() (*os.File, error) {
		return os.OpenFile(filepath.Join(dir, "index.json"), os.O_RDONLY|sourceOpenFlags, 0)
	})
	if err != nil {
		return nil, err
	}
	return newLocalOCIIndex(s, raw, types.OCIImageIndex)
}

func (s *ociStore) readMetadata(open func() (*os.File, error)) ([]byte, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	remaining := maxOCIMetadataTotalBytes - s.bytes
	if remaining <= 0 {
		return nil, errors.New("OCI metadata byte budget exceeded")
	}
	raw, err := readSourceFile(open, min(maxImageMetadataBytes, remaining))
	if err != nil {
		return nil, err
	}
	s.bytes += int64(len(raw))
	return raw, nil
}

func (s *ociStore) metadata(h v1.Hash) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if raw, ok := s.cache[h]; ok {
		return raw, nil
	}
	raw, err := s.readMetadata(func() (*os.File, error) { return s.openBlob(h) })
	if err != nil {
		return nil, err
	}
	s.cache[h] = raw
	return raw, nil
}

func (s *ociStore) openBlob(h v1.Hash) (*os.File, error) {
	if _, err := v1.NewHash(h.String()); err != nil {
		return nil, err
	}
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	p := filepath.Join(s.dir, "blobs", h.Algorithm, h.Hex)
	info, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("OCI blob is not a regular file")
	}
	f, err := os.OpenFile(p, os.O_RDONLY|sourceOpenFlags, 0)
	if err != nil {
		return nil, err
	}
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || !os.SameFile(info, stat) {
		_ = f.Close()
		return nil, errors.New("OCI blob changed while opening")
	}
	return f, nil
}

type localOCIIndex struct {
	store *ociStore
	raw   []byte
	mf    *v1.IndexManifest
	mt    types.MediaType
}

func newLocalOCIIndex(s *ociStore, raw []byte, mt types.MediaType) (*localOCIIndex, error) {
	var mf v1.IndexManifest
	if err := json.Unmarshal(raw, &mf); err != nil {
		return nil, err
	}
	return &localOCIIndex{store: s, raw: raw, mf: &mf, mt: mt}, nil
}

func (idx *localOCIIndex) MediaType() (types.MediaType, error)       { return idx.mt, nil }
func (idx *localOCIIndex) Digest() (v1.Hash, error)                  { return partial.Digest(idx) }
func (idx *localOCIIndex) Size() (int64, error)                      { return int64(len(idx.raw)), nil }
func (idx *localOCIIndex) RawManifest() ([]byte, error)              { return idx.raw, nil }
func (idx *localOCIIndex) IndexManifest() (*v1.IndexManifest, error) { return idx.mf, nil }

func (idx *localOCIIndex) descriptor(h v1.Hash) (v1.Descriptor, error) {
	for _, d := range idx.mf.Manifests {
		if d.Digest == h {
			return d, nil
		}
	}
	return v1.Descriptor{}, fmt.Errorf("OCI descriptor not found: %s", h)
}

func (idx *localOCIIndex) ImageIndex(h v1.Hash) (v1.ImageIndex, error) {
	d, err := idx.descriptor(h)
	if err != nil {
		return nil, err
	}
	if !d.MediaType.IsIndex() {
		return nil, errors.New("OCI descriptor is not an index")
	}
	raw, err := idx.store.metadata(h)
	if err != nil {
		return nil, err
	}
	return newLocalOCIIndex(idx.store, raw, d.MediaType)
}

func (idx *localOCIIndex) Image(h v1.Hash) (v1.Image, error) {
	d, err := idx.descriptor(h)
	if err != nil {
		return nil, err
	}
	if !d.MediaType.IsImage() {
		return nil, errors.New("OCI descriptor is not an image")
	}
	raw, err := idx.store.metadata(h)
	if err != nil {
		return nil, err
	}
	mf, err := v1.ParseManifest(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	if len(mf.Layers) > maxImageLayers {
		return nil, errors.New("OCI image exceeds layer limit")
	}
	return partial.CompressedToImage(&localOCIImage{store: idx.store, raw: raw, mf: mf, mt: d.MediaType})
}

type localOCIImage struct {
	store *ociStore
	raw   []byte
	mf    *v1.Manifest
	mt    types.MediaType
}

func (img *localOCIImage) MediaType() (types.MediaType, error) { return img.mt, nil }
func (img *localOCIImage) RawManifest() ([]byte, error)        { return img.raw, nil }
func (img *localOCIImage) RawConfigFile() ([]byte, error) {
	return img.store.metadata(img.mf.Config.Digest)
}
func (img *localOCIImage) LayerByDigest(h v1.Hash) (partial.CompressedLayer, error) {
	for _, d := range img.mf.Layers {
		if d.Digest == h {
			return &localOCILayer{store: img.store, desc: d}, nil
		}
	}
	return nil, fmt.Errorf("OCI layer not found: %s", h)
}

type localOCILayer struct {
	store *ociStore
	desc  v1.Descriptor
}

func (l *localOCILayer) Digest() (v1.Hash, error)            { return l.desc.Digest, nil }
func (l *localOCILayer) Size() (int64, error)                { return l.desc.Size, nil }
func (l *localOCILayer) MediaType() (types.MediaType, error) { return l.desc.MediaType, nil }
func (l *localOCILayer) Compressed() (io.ReadCloser, error)  { return l.store.openBlob(l.desc.Digest) }
