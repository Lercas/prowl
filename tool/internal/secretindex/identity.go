// Package secretindex maintains an opt-in local index without retaining secret values.
package secretindex

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Lercas/prowl/tool/internal/localfile"
)

const fingerprintPrefix = "hmac-sha256:v1:"
const locationPrefix = "hmac-location:v1:"

// Identity is immutable and safe to share between scan workers.
type Identity struct{ key [32]byte }

func (i *Identity) Fingerprint(value string) string {
	if value == "" {
		return ""
	}
	h := hmac.New(sha256.New, i.key[:])
	_, _ = io.WriteString(h, "prowl:value:v1\x00")
	_, _ = io.WriteString(h, value)
	return fingerprintPrefix + i.keyID() + ":" + hex.EncodeToString(h.Sum(nil))
}

func (i *Identity) keyID() string {
	h := hmac.New(sha256.New, i.key[:])
	_, _ = io.WriteString(h, "prowl:index-key-id:v1")
	return hex.EncodeToString(h.Sum(nil))
}

// Location identifies original coordinates independently of their sanitized
// display form, so URLs differing only in query parameters remain distinct.
func (i *Identity) Location(source, path string, line, col int) string {
	h := hmac.New(sha256.New, i.key[:])
	for _, part := range []string{"prowl:location:v1", source, path, fmt.Sprint(line), fmt.Sprint(col)} {
		_, _ = fmt.Fprintf(h, "%d:", len(part))
		_, _ = io.WriteString(h, part)
	}
	return locationPrefix + i.keyID() + ":" + hex.EncodeToString(h.Sum(nil))
}

// LoadIdentity creates a private directory/key only when explicitly requested.
// An existing database without its key never gets a replacement key.
func LoadIdentity(directory string, create bool) (*Identity, error) {
	if directory == "" {
		return nil, errors.New("index directory is required")
	}
	directory = filepath.Clean(directory)
	if create {
		if err := createIndexDirectory(directory); err != nil {
			return nil, fmt.Errorf("create index directory: %w", err)
		}
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !privatePermissions(info.Mode()) {
		return nil, errors.New("index directory must be private (0700), and not a symlink")
	}
	if err := checkPlatformPrivacy(directory, info); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err := localfile.CheckRootDestination(root, "key"); err != nil {
		return nil, err
	}
	_, err = root.Lstat("key")
	if errors.Is(err, os.ErrNotExist) && create {
		if _, dbErr := root.Lstat("index.sqlite"); !errors.Is(dbErr, os.ErrNotExist) {
			return nil, errors.New("existing index has no key; restore its original key")
		}
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			return nil, err
		}
		f, err := root.OpenFile("key", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		_, writeErr := f.Write(key[:])
		err = errors.Join(writeErr, f.Sync(), f.Close())
		if err != nil {
			return nil, fmt.Errorf("write index key: %w", err)
		}
	} else if err != nil {
		return nil, err
	}
	info, err = root.Lstat("key")
	if err != nil {
		return nil, err
	}
	if !privatePermissions(info.Mode()) || !singleLink(info) {
		return nil, errors.New("index key must be private (0600), with one hard link")
	}
	if err := checkPlatformPrivacy(filepath.Join(directory, "key"), info); err != nil {
		return nil, err
	}
	raw, err := localfile.ReadRootRegular(root, "key", 32)
	if err != nil {
		return nil, err
	}
	if len(raw) != 32 {
		return nil, errors.New("index key must contain exactly 32 bytes")
	}
	id := &Identity{}
	copy(id.key[:], raw)
	return id, nil
}

func createIndexDirectory(directory string) error {
	if _, err := os.Lstat(directory); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(directory), 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return err
	}
	return secureNewDirectory(directory)
}

func validFingerprint(s string) bool {
	return validIdentity(s, fingerprintPrefix)
}

func validIdentity(s, prefix string) bool {
	if len(s) != len(prefix)+129 || !strings.HasPrefix(s, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(s, prefix), ":")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		if len(part) != 64 {
			return false
		}
		if _, err := hex.DecodeString(part); err != nil {
			return false
		}
	}
	return true
}

func indexPath(directory string) (string, error) {
	path, err := filepath.Abs(directory)
	if err != nil {
		return "", err
	}
	return filepath.Join(path, "index.sqlite"), nil
}
