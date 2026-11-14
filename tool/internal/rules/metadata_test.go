package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateRejectsBrokenProvenance(t *testing.T) {
	for name, raw := range map[string]string{
		"malformed":       `{"count":`,
		"null":            `null`,
		"missing-files":   `{"count":1}`,
		"negative-count":  `{"count":-1,"files":{}}`,
		"count-mismatch":  `{"count":2,"files":{}}`,
		"duplicate-count": `{"count":2,"count":0,"files":{}}`,
		"case-alias":      `{"count":2,"COUNT":0,"files":{}}`,
		"unknown-field":   `{"count":0,"files":{},"unknown":true}`,
		"invalid-unicode": "{\"count\":0,\"files\":{},\"version\":\"\xff\"}",
		"surrogate":       `{"count":0,"files":{},"version":"\ud800"}`,
		"invalid-hash":    `{"count":1,"files":{"owned.yaml":"not a checksum"}}`,
		"escaping-path":   `{"count":1,"files":{"../outside.yaml":"` + strings.Repeat("0", 64) + `"}}`,
		"duplicate-file":  `{"count":1,"files":{"owned.yaml":"` + strings.Repeat("0", 64) + `","owned.yaml":"` + strings.Repeat("1", 64) + `"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			source, target := t.TempDir(), t.TempDir()
			writeRuleFile(t, source, "owned.yaml", minimalRule("owned"))
			writeRuleFile(t, target, ManifestName, raw)
			validated := false
			if _, err := Update(UpdateOpts{Source: source, Target: target, Check: true, Validate: func(string) error {
				validated = true
				return nil
			}}); err == nil {
				t.Fatal("invalid installed provenance treated as absent or usable metadata")
			}
			if validated {
				t.Fatal("source processing preceded installed provenance error")
			}
		})
	}
}

func TestUpdateDoesNotDiscardVersionReadErrors(t *testing.T) {
	source, target := t.TempDir(), t.TempDir()
	writeRuleFile(t, source, "owned.yaml", minimalRule("owned"))
	if err := os.Mkdir(filepath.Join(source, "VERSION"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Update(UpdateOpts{Source: source, Target: target, Check: true}); err == nil {
		t.Fatal("VERSION read failure silently replaced by local version")
	}
}

func TestMetadataReadBoundariesAndRootLinks(t *testing.T) {
	for _, extra := range []int{0, 1} {
		dir := t.TempDir()
		body := `{"count":0,"files":{},"version":"v-owned"}`
		body += strings.Repeat(" ", MaxProvenanceSize-len(body)+extra)
		writeRuleFile(t, dir, ManifestName, body)
		m, err := ReadManifest(dir)
		if (err != nil) != (extra != 0) || (err == nil && m.Version != "v-owned") {
			t.Fatalf("wrong manifest size boundary: extra=%d err=%v", extra, err)
		}
		writeRuleFile(t, dir, "VERSION", strings.Repeat("v", MaxVersionSize+extra))
		_, err = readVersionFile(dir)
		if (err != nil) != (extra != 0) {
			t.Fatalf("wrong VERSION size boundary: extra=%d err=%v", extra, err)
		}
	}
	outside := t.TempDir()
	writeRuleFile(t, outside, ManifestName, `{"count":0,"files":{}}`)
	for _, name := range []string{ManifestName, "VERSION"} {
		dir := t.TempDir()
		if err := os.Symlink(filepath.Join(outside, ManifestName), filepath.Join(dir, name)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if name == ManifestName {
			if _, err := ReadManifest(dir); err == nil {
				t.Fatal("provenance read escaped its selected directory")
			}
		} else if _, err := readVersionFile(dir); err == nil {
			t.Fatal("VERSION read escaped its selected directory")
		}
	}
}

func TestProvenanceWritePreservesHardlinkAlias(t *testing.T) {
	source, target, outside := t.TempDir(), t.TempDir(), filepath.Join(t.TempDir(), "old-metadata")
	writeRuleFile(t, source, "owned.yaml", minimalRule("owned"))
	const old = `{"count":0,"files":{},"version":"before"}`
	if err := os.WriteFile(outside, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(target, ManifestName)); err != nil {
		t.Skipf("hardlinks unavailable: %v", err)
	}
	if _, err := Update(UpdateOpts{Source: source, Target: target}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(outside)
	if err != nil || string(raw) != old {
		t.Fatalf("provenance overwrite changed an alias outside the library: err=%v", err)
	}
	if m, err := ReadManifest(target); err != nil || m.Count != 1 {
		t.Fatalf("new provenance not installed: count=%d err=%v", m.Count, err)
	}
}
