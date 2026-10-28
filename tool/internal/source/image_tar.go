package source

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"path"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

const maxImageMetadataBytes int64 = 64 << 20

type unreadableImage struct {
	v1.Image
	err error
}

func (img unreadableImage) ConfigFile() (*v1.ConfigFile, error) { return nil, img.err }

func readImageManifest(opener tarball.Opener) (tarball.Manifest, error) {
	raw, err := readImageMetadata(opener, "manifest.json", map[string]bool{})
	if err != nil {
		return nil, err
	}
	var manifest tarball.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	if len(manifest) > maxImageLayers {
		return nil, errors.New("too many image descriptors in tarball")
	}
	return manifest, nil
}

// readImageMetadata bounds metadata before the dependency's unbounded config read. Links are
// resolved inside the tar namespace, never through the filesystem.
func readImageMetadata(opener tarball.Opener, name string, seen map[string]bool) ([]byte, error) {
	name = path.Clean(name)
	if seen[name] || len(seen) >= 32 {
		return nil, errors.New("image metadata link cycle or depth limit")
	}
	seen[name] = true
	rc, err := opener()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	tr := tar.NewReader(rc)
	for n := 0; n < maxImageEntries; n++ {
		hdr, err := tr.Next()
		if err != nil {
			return nil, fmt.Errorf("read image metadata %q: %w", name, err)
		}
		if path.Clean(hdr.Name) != name {
			continue
		}
		if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink {
			// This resolves a member name inside the TAR only; it never opens a filesystem path.
			return readImageMetadata(opener, path.Join(path.Dir(name), hdr.Linkname), seen) //nolint:gosec // No files are extracted or opened by member name.
		}
		if (hdr.Typeflag != tar.TypeReg && hdr.Typeflag != 0) || hdr.Size < 0 {
			return nil, errors.New("image metadata is not a regular file")
		}
		if hdr.Size > maxImageMetadataBytes {
			return nil, errors.New("image metadata exceeds size limit")
		}
		return readSourceBytes(tr, maxImageMetadataBytes)
	}
	return nil, errors.New("image metadata exceeds header limit")
}

// descriptorOpener presents one descriptor as the first manifest. Selection by position also
// supports untagged, duplicate-tagged, and noncanonical-tagged images without losing siblings.
func descriptorOpener(opener tarball.Opener, descriptor tarball.Descriptor) (tarball.Opener, error) {
	if _, err := readImageMetadata(opener, descriptor.Config, map[string]bool{}); err != nil {
		return nil, err
	}
	if len(descriptor.Layers) > maxImageLayers {
		return nil, errors.New("image descriptor exceeds layer limit")
	}
	raw, err := json.Marshal(tarball.Manifest{descriptor})
	if err != nil {
		return nil, err
	}
	var prefix bytes.Buffer
	tw := tar.NewWriter(&prefix)
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Typeflag: tar.TypeReg, Size: int64(len(raw))}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(raw); err != nil {
		return nil, err
	}
	// Flush pads the member without adding TAR end markers that would hide the original stream.
	if err := tw.Flush(); err != nil {
		return nil, err
	}
	data := prefix.Bytes()
	return func() (io.ReadCloser, error) {
		rc, err := opener()
		if err != nil {
			return nil, err
		}
		return &prefixedImageTar{prefix: data, original: rc}, nil
	}, nil
}

// prefixedImageTar preserves seeking so archive/tar can skip large unselected layer bodies cheaply.
type prefixedImageTar struct {
	prefix   []byte
	original io.ReadCloser
	pos      int64
}

func (r *prefixedImageTar) Read(p []byte) (int, error) {
	if r.pos < int64(len(r.prefix)) {
		n := copy(p, r.prefix[r.pos:])
		r.pos += int64(n)
		return n, nil
	}
	n, err := r.original.Read(p)
	r.pos += int64(n)
	return n, err
}

func (r *prefixedImageTar) Seek(offset int64, whence int) (int64, error) {
	s, ok := r.original.(io.Seeker)
	if !ok {
		return 0, errors.New("image tar source cannot seek")
	}
	prefixSize := int64(len(r.prefix))
	var target int64
	switch whence {
	case io.SeekStart:
		target = offset
	case io.SeekCurrent:
		if offset > math.MaxInt64-r.pos || offset < -r.pos {
			return 0, errors.New("invalid image tar seek position")
		}
		target = r.pos + offset
	case io.SeekEnd:
		pos, err := s.Seek(0, io.SeekEnd)
		if err != nil {
			return 0, err
		}
		if pos < 0 || pos > math.MaxInt64-prefixSize {
			_, _ = s.Seek(max(0, r.pos-prefixSize), io.SeekStart)
			return 0, errors.New("image tar seek exceeds size limit")
		}
		target = prefixSize + pos
		if offset > math.MaxInt64-target || offset < -target {
			_, _ = s.Seek(max(0, r.pos-prefixSize), io.SeekStart)
			return 0, errors.New("invalid image tar seek position")
		}
		target += offset
	default:
		return 0, errors.New("invalid seek whence")
	}
	if target < 0 {
		return 0, errors.New("negative seek position")
	}
	if _, err := s.Seek(max(0, target-prefixSize), io.SeekStart); err != nil {
		return 0, err
	}
	r.pos = target
	return target, nil
}

func (r *prefixedImageTar) Close() error { return r.original.Close() }
