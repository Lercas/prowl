package source

import (
	"context"
	"errors"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
)

const maxImageIndexDescriptors = 1000

// flattenIndex retains readable images alongside failed descriptors. Active ancestors identify
// cycles, while completed indexes and images may be shared legitimately by several branches.
func flattenIndex(idx v1.ImageIndex) ([]v1.Image, error) {
	return flattenIndexContext(context.Background(), idx)
}

func flattenIndexContext(ctx context.Context, idx v1.ImageIndex) ([]v1.Image, error) {
	w := indexWalker{ctx: ctx, active: map[v1.Hash]bool{}, done: map[v1.Hash]bool{}, images: map[v1.Hash]bool{}}
	return w.walk(idx, 0)
}

type indexWalker struct {
	ctx          context.Context
	active, done map[v1.Hash]bool
	images       map[v1.Hash]bool
	visited      int
	stopped      bool
}

func failedIndexImage(err error) v1.Image {
	return unreadableImage{Image: empty.Image, err: err}
}

func (w *indexWalker) walk(idx v1.ImageIndex, depth int) ([]v1.Image, error) {
	if err := w.ctx.Err(); err != nil {
		return nil, err
	}
	if idx == nil {
		return nil, errors.New("nil OCI index")
	}
	if depth > 32 {
		return nil, errors.New("OCI index nested too deeply")
	}
	mf, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}
	if mf == nil {
		return nil, errors.New("nil OCI index manifest")
	}
	var out []v1.Image
	for _, desc := range mf.Manifests {
		if err := w.ctx.Err(); err != nil {
			return nil, err
		}
		w.visited++
		if w.visited > maxImageIndexDescriptors {
			w.stopped = true
			return append(out, failedIndexImage(errors.New("OCI index descriptor limit exceeded"))), nil
		}
		switch {
		case desc.MediaType.IsIndex():
			if w.active[desc.Digest] {
				out = append(out, failedIndexImage(fmt.Errorf("OCI index cycle at %s", desc.Digest)))
				continue
			}
			if w.done[desc.Digest] {
				continue
			}
			w.active[desc.Digest] = true
			child, childErr := idx.ImageIndex(desc.Digest)
			var imgs []v1.Image
			if childErr == nil {
				imgs, childErr = w.walk(child, depth+1)
			}
			delete(w.active, desc.Digest)
			w.done[desc.Digest] = true
			if childErr != nil {
				out = append(out, failedIndexImage(fmt.Errorf("OCI index %s: %w", desc.Digest, childErr)))
			} else {
				out = append(out, imgs...)
			}
			if w.stopped {
				return out, nil
			}
		case desc.MediaType.IsImage():
			if w.images[desc.Digest] {
				continue
			}
			w.images[desc.Digest] = true
			img, err := idx.Image(desc.Digest)
			if err == nil && img == nil {
				err = errors.New("nil OCI image")
			}
			if err != nil {
				img = failedIndexImage(fmt.Errorf("OCI image %s: %w", desc.Digest, err))
			}
			out = append(out, img)
		}
	}
	return out, nil
}
