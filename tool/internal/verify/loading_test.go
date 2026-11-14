package verify

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifierLibraryBudgets(t *testing.T) {
	t.Run("actual-bytes", func(t *testing.T) {
		dir := t.TempDir()
		body := "#" + strings.Repeat("x", MaxVerifierSize-1)
		for i := 0; i < MaxSetBytes/MaxVerifierSize; i++ {
			writeFile(t, dir, fmt.Sprintf("%04d.yaml", i), body)
		}
		if _, err := readDirectorySnapshot(dir, false); err != nil {
			t.Fatalf("exact byte budget rejected: %v", err)
		}
		writeFile(t, dir, "overflow.yaml", "#")
		if _, err := readDirectorySnapshot(dir, false); err == nil {
			t.Fatal("library exceeded its actual byte budget")
		}
	})
	t.Run("file-count", func(t *testing.T) {
		dir := t.TempDir()
		for i := 0; i < MaxSetFiles; i++ {
			writeFile(t, dir, fmt.Sprintf("%05d.yaml", i), "")
		}
		if _, err := readDirectorySnapshot(dir, false); err != nil {
			t.Fatalf("exact file budget rejected: %v", err)
		}
		writeFile(t, dir, "overflow.yaml", "")
		if _, err := readDirectorySnapshot(dir, false); err == nil {
			t.Fatal("empty files bypassed the library count budget")
		}
	})
}

func TestVerifierLoaderRejectsIncompleteOrMistypedPolicy(t *testing.T) {
	for name, body := range map[string]string{
		"missing-id":        strings.Replace(headerVerifier, "id: hv\n", "", 1),
		"missing-match":     strings.Replace(headerVerifier, "match: [hv, hv_]\n", "", 1),
		"missing-url":       strings.Replace(headerVerifier, "    url: https://api.example.com/user\n", "", 1),
		"unknown-field":     headerVerifier + "unknown: true\n",
		"unknown-matcher":   strings.Replace(headerVerifier, "type: status", "type: statuz\n        negative: true", 1),
		"unknown-condition": strings.Replace(headerVerifier, "    matchers:", "    matchers-condition: xor\n    matchers:", 1),
		"empty-matcher":     strings.Replace(headerVerifier, "status: [200]", "status: []\n        negative: true", 1),
		"bad-part":          strings.Replace(headerVerifier, "type: status", "type: status\n        part: headers", 1),
	} {
		t.Run(name, func(t *testing.T) {
			p := writeFile(t, t.TempDir(), "owned.yaml", body)
			if _, err := Load(0, p); err == nil {
				t.Fatal("invalid verifier was silently accepted")
			}
		})
	}
}

func TestVerifierStreamConsumesDocumentEndSuffix(t *testing.T) {
	path := writeFile(t, t.TempDir(), "stream.yaml", headerVerifier+"...\nunknown: [\n")
	if _, err := Load(0, path); err == nil {
		t.Fatal("malformed content following an explicit document end was ignored")
	}
}

func TestVerifierIDsMustBeUniqueAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "one.yaml", headerVerifier)
	writeFile(t, dir, "two.yaml", headerVerifier)
	if _, err := Load(0, dir); err == nil {
		t.Fatal("duplicate verifier IDs silently selected a provider by file order")
	}
}

func TestVerifierManifestCannotSilentlyOverwriteDuplicateEntries(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "owned.yaml", headerVerifier)
	good, err := hashFile(p)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, ManifestName, strings.Repeat("0", 64)+"  owned.yaml\n"+good+"  owned.yaml\n")
	if _, err := Load(0, dir); err == nil {
		t.Fatal("duplicate manifest entry replaced an earlier checksum")
	}
}

func TestVerifierSizeIsBoundedBeforeParsing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "large.yaml")
	// A small valid verifier followed by a large comment used to load with no size limit.
	if err := os.WriteFile(p, []byte(headerVerifier+"#"+strings.Repeat("x", 512*1024)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(0, p); err == nil {
		t.Fatal("oversized verifier file accepted")
	}
}

func TestVerifierStreamAndCoLocatedTemplatesRemainSupported(t *testing.T) {
	body := "---\n" + headerVerifier + "...\n--- # next verifier\n" + strings.Replace(headerVerifier, "id: hv", "id: second", 1) + "---\n# empty trailing document\n"
	for _, raw := range []string{body, strings.ReplaceAll(body, "\n", "\r\n")} {
		p := writeFile(t, t.TempDir(), "stream.yaml", raw)
		if set, err := Load(0, p); err != nil || set.Count() != 2 {
			t.Fatalf("valid YAML stream failed: count=%d err=%v", set.Count(), err)
		}
	}
	dir := t.TempDir()
	writeFile(t, dir, "verifier.yaml", headerVerifier)
	writeFile(t, dir, "template.yaml", "id: owned-template\ninfo: {name: Owned, severity: high}\nmatchers:\n  - type: regex\n    regex: ['OWNED_[A-Z]{8}']\n")
	if set, err := Load(0, dir); err != nil || set.Count() != 1 {
		t.Fatalf("co-located valid detection template failed: count=%d err=%v", set.Count(), err)
	}
}

func TestExactVerifierSizeRemainsAccepted(t *testing.T) {
	body := headerVerifier + "#" + strings.Repeat("x", MaxVerifierSize-len(headerVerifier)-1)
	p := writeFile(t, t.TempDir(), "boundary.yaml", body)
	if set, err := Load(0, p); err != nil || set.Count() != 1 {
		t.Fatalf("exact file size rejected: count=%d err=%v", set.Count(), err)
	}
}

func TestRootScopedVerifierReads(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	external := writeFile(t, outside, "owned.yaml", headerVerifier)
	alias := filepath.Join(dir, "alias.yaml")
	if err := os.Symlink(external, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := Load(0, dir); err == nil {
		t.Fatal("directory loading followed a verifier outside its root")
	}
	if set, err := Load(0, alias); err != nil || set.Count() != 1 {
		t.Fatalf("explicitly selected loose symlink failed: count=%d err=%v", set.Count(), err)
	}
	inside := t.TempDir()
	writeFile(t, inside, "body.txt", headerVerifier)
	if err := os.Symlink("body.txt", filepath.Join(inside, "owned.yaml")); err != nil {
		t.Fatal(err)
	}
	if set, err := Load(0, inside); err != nil || set.Count() != 1 {
		t.Fatalf("in-root verifier link failed: count=%d err=%v", set.Count(), err)
	}
}

func TestManifestSizeAndPathValidation(t *testing.T) {
	for _, rel := range []string{"../outside.yaml", "/absolute.yaml", "a/../owned.yaml"} {
		dir := t.TempDir()
		writeFile(t, dir, "owned.yaml", headerVerifier)
		writeFile(t, dir, ManifestName, strings.Repeat("0", 64)+"  "+rel+"\n")
		if _, err := Load(0, dir); err == nil {
			t.Errorf("invalid manifest path %q accepted", rel)
		}
	}
	dir := t.TempDir()
	writeFile(t, dir, "owned.yaml", headerVerifier)
	writeFile(t, dir, ManifestName, "#"+strings.Repeat("x", MaxManifestSize))
	if _, err := Load(0, dir); err == nil {
		t.Fatal("oversized manifest accepted")
	}
}

func TestManifestPreservesSpacesInFileNames(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, " leading  spaces.yaml", headerVerifier)
	if n, err := GenerateManifest(dir); err != nil || n != 1 {
		t.Fatalf("generate: count=%d err=%v", n, err)
	}
	if set, err := Load(0, dir); err != nil || set.Count() != 1 {
		t.Fatalf("valid manifest path changed filename bytes: count=%d err=%v", set.Count(), err)
	}
}

func TestSnapshotUsesSameBytesForIntegrityAndCompilation(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "owned.yaml", headerVerifier)
	if _, err := GenerateManifest(dir); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readDirectorySnapshot(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "owned.yaml", strings.Replace(headerVerifier, "api.example.com", "changed.invalid", 1))
	if _, signed, err := checkSnapshot(dir, LoadPolicy{}, snapshot); err != nil || !signed {
		t.Fatalf("unchanged captured policy failed integrity: signed=%v err=%v", signed, err)
	}
	if !strings.Contains(string(snapshot.files[0].raw), "api.example.com") || strings.Contains(string(snapshot.files[0].raw), "changed.invalid") {
		t.Fatal("snapshot approved different bytes from those available for compilation")
	}
	if _, err := Load(0, dir); err == nil {
		t.Fatal("fresh load failed to notice subsequent disk tampering")
	}
}
