package rules

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/jsonstrict"
	"github.com/Lercas/prowl/tool/internal/localfile"
)

const (
	MaxProvenanceSize = 8 << 20
	MaxVersionSize    = 64 << 10
)

// ReadManifest returns zero only for an absent provenance file, never for a corrupt/unreadable one.
func ReadManifest(dir string) (Manifest, error) {
	raw, present, err := localfile.ReadOptionalDirectoryFile(dir, ManifestName, MaxProvenanceSize)
	if err != nil {
		return Manifest{}, fmt.Errorf("%s: %w", filepath.Join(dir, ManifestName), err)
	}
	if !present {
		return Manifest{}, nil
	}
	m, err := parseProvenance(raw)
	if err != nil {
		return Manifest{}, fmt.Errorf("%s: %w", filepath.Join(dir, ManifestName), err)
	}
	return m, nil
}

func readManifestRoot(root *os.Root, dir string) (Manifest, error) {
	raw, present, err := localfile.ReadOptionalRoot(root, ManifestName, MaxProvenanceSize)
	if err != nil {
		return Manifest{}, err
	}
	if !present {
		return Manifest{}, nil
	}
	m, err := parseProvenance(raw)
	if err != nil {
		return Manifest{}, fmt.Errorf("%s: %w", filepath.Join(dir, ManifestName), err)
	}
	return m, nil
}

func parseProvenance(raw []byte) (Manifest, error) {
	fields, err := jsonstrict.Object(raw, true)
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	for key, raw := range fields {
		var dst any
		switch key {
		case "source":
			dst = &m.Source
		case "version":
			dst = &m.Version
		case "updated_at":
			dst = &m.UpdatedAt
		case "count":
			dst = &m.Count
		case "files":
			continue
		default:
			return Manifest{}, fmt.Errorf("unknown provenance field")
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return Manifest{}, fmt.Errorf("provenance fields cannot be null")
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			return Manifest{}, fmt.Errorf("invalid provenance %s: %w", key, err)
		}
	}
	if _, exists := fields["count"]; !exists {
		return Manifest{}, fmt.Errorf("provenance requires count and files")
	}
	files, err := jsonstrict.Object(fields["files"], false)
	if err != nil {
		return Manifest{}, fmt.Errorf("invalid provenance files: %w", err)
	}
	if m.Count < 0 || m.Count != len(files) || len(files) > MaxLibraryFiles {
		return Manifest{}, fmt.Errorf("provenance count must match the bounded file inventory")
	}
	m.Files = make(map[string]string, len(files))
	for name, raw := range files {
		rel := filepath.ToSlash(name)
		ext := strings.ToLower(filepath.Ext(rel))
		if !fs.ValidPath(rel) || rel == "." || (ext != ".yaml" && ext != ".yml") {
			return Manifest{}, fmt.Errorf("invalid provenance file path")
		}
		if _, exists := m.Files[rel]; exists {
			return Manifest{}, fmt.Errorf("duplicate normalized provenance path")
		}
		var hash string
		if err := json.Unmarshal(raw, &hash); err != nil || len(hash) != 64 {
			return Manifest{}, fmt.Errorf("invalid provenance checksum")
		}
		if _, err := hex.DecodeString(hash); err != nil {
			return Manifest{}, fmt.Errorf("invalid provenance checksum")
		}
		m.Files[rel] = strings.ToLower(hash)
	}
	return m, nil
}

func readVersionFile(dir string) (string, error) {
	raw, present, err := localfile.ReadOptionalDirectoryFile(dir, "VERSION", MaxVersionSize)
	if err != nil || !present {
		return "", err
	}
	return parseVersion(raw)
}

func parseVersion(raw []byte) (string, error) {
	if !utf8.Valid(raw) {
		return "", fmt.Errorf("VERSION must contain valid UTF-8")
	}
	value := strings.TrimSpace(string(raw))
	if strings.ContainsAny(value, "\r\n\x00\x1b") {
		return "", fmt.Errorf("VERSION must contain a single version line")
	}
	return value, nil
}
