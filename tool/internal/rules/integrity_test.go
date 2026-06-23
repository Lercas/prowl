package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRuleFile writes a file under dir (creating parents) and fails the test on error.
func writeRuleFile(t *testing.T, dir, name, body string) string {
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

// awsTemplate is a well-formed rule template that actually detects an AWS key. The integrity gate is
// about whether these bytes are the ones the maintainer/third-party blessed — a malicious source would
// swap the regex for a never-matching one to silently disable detection.
const awsTemplate = `id: aws-key
info:
  name: AWS Access Key
  severity: high
matchers:
  - type: regex
    regex:
      - 'AKIA[0-9A-Z]{16}'
`

// TestManifestRoundTripPasses: a generated manifest blesses a dir and a bundled integrity check of
// that dir passes clean.
func TestManifestRoundTripPasses(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "aws.yaml", awsTemplate)
	if n, err := GenerateManifest(dir); err != nil || n != 1 {
		t.Fatalf("GenerateManifest: n=%d err=%v", n, err)
	}
	if err := CheckIntegrity(dir, IntegrityPolicy{}); err != nil {
		t.Fatalf("clean signed set should pass bundled check: %v", err)
	}
}

// TestUntrustedSourceTheaterClosed: an untrusted --source shipping its own fully-matching manifest is
// still refused without --allow-unsigned (a self-shipped manifest authenticates nothing); with the
// opt-in the same set installs.
func TestUntrustedSourceTheaterClosed(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "aws.yaml", awsTemplate)
	if _, err := GenerateManifest(dir); err != nil { // self-signed manifest
		t.Fatal(err)
	}

	err := CheckIntegrity(dir, IntegrityPolicy{Trust: TrustUntrusted})
	if err == nil {
		t.Fatal("a self-signed untrusted --source must be refused without --allow-unsigned (a shipped manifest proves nothing)")
	}
	if !strings.Contains(err.Error(), "allow-unsigned") || !strings.Contains(err.Error(), "cannot be authenticated") {
		t.Errorf("refusal should be honest about why the manifest is no proof and how to opt in: %v", err)
	}

	if err := CheckIntegrity(dir, IntegrityPolicy{Trust: TrustUntrusted, AllowUnsigned: true}); err != nil {
		t.Fatalf("--allow-unsigned should install the (self-signed) untrusted source at the operator's risk: %v", err)
	}
}

// TestUnsignedRemoteRefused: an untrusted remote set with no manifest is refused by default and
// passes only with explicit AllowUnsigned.
func TestUnsignedRemoteRefused(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "aws.yaml", awsTemplate) // no GenerateManifest -> unsigned

	err := CheckIntegrity(dir, IntegrityPolicy{Trust: TrustUntrusted})
	if err == nil {
		t.Fatal("unsigned remote rule set must be refused without --allow-unsigned")
	}
	if !strings.Contains(err.Error(), IntegrityManifestName) || !strings.Contains(err.Error(), "allow-unsigned") {
		t.Errorf("refusal should mention the missing manifest and the opt-in: %v", err)
	}

	if err := CheckIntegrity(dir, IntegrityPolicy{Trust: TrustUntrusted, AllowUnsigned: true}); err != nil {
		t.Fatalf("--allow-unsigned should let the unsigned set pass: %v", err)
	}
}

// TestUnsignedBundledDirPasses: a hand-authored dir with NO manifest still passes under bundled trust
// (so a plain `--rules-dir DIR` of local templates keeps working) — the manifest is verify-if-present.
func TestUnsignedBundledDirPasses(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "aws.yaml", awsTemplate)
	if err := CheckIntegrity(dir, IntegrityPolicy{}); err != nil {
		t.Fatalf("unsigned bundled dir should still pass: %v", err)
	}
}

// TestTamperedFileRejected: after a manifest is generated, neutering a template is caught and the bad
// file named — for a bundled set and for an untrusted set with --allow-unsigned (both consult the
// manifest). Without the opt-in an untrusted set is refused earlier (TestUntrustedSourceTheaterClosed).
func TestTamperedFileRejected(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "aws.yaml", awsTemplate)
	if _, err := GenerateManifest(dir); err != nil {
		t.Fatal(err)
	}
	// Tamper: swap the working regex for a never-matching one — detection silently disabled.
	writeRuleFile(t, dir, "aws.yaml", strings.Replace(awsTemplate, "AKIA[0-9A-Z]{16}", "NEVER_MATCH_ZZZ", 1))

	// Policies that DO consult the manifest (bundled, and untrusted-with-opt-in) must name the tampered file.
	for _, pol := range []IntegrityPolicy{{}, {Trust: TrustUntrusted, AllowUnsigned: true}} {
		err := CheckIntegrity(dir, pol)
		if err == nil {
			t.Fatalf("tampered file must be rejected for policy %+v", pol)
		}
		if !strings.Contains(err.Error(), "tampered") || !strings.Contains(err.Error(), "aws.yaml") {
			t.Errorf("error should name the tampered file for policy %+v: %v", pol, err)
		}
	}
}

// TestUnlistedFileRejected: a template present on disk but absent from the manifest fails the set.
func TestUnlistedFileRejected(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "aws.yaml", awsTemplate)
	if _, err := GenerateManifest(dir); err != nil {
		t.Fatal(err)
	}
	writeRuleFile(t, dir, "rogue.yaml", strings.Replace(awsTemplate, "id: aws-key", "id: rogue", 1))

	err := CheckIntegrity(dir, IntegrityPolicy{})
	if err == nil || !strings.Contains(err.Error(), "not in manifest") {
		t.Fatalf("unlisted file should be refused, got %v", err)
	}
}

// TestMissingFileRejected: a file listed in the manifest but removed from disk fails the set.
func TestMissingFileRejected(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "aws.yaml", awsTemplate)
	writeRuleFile(t, dir, "gh.yaml", strings.Replace(awsTemplate, "id: aws-key", "id: gh", 1))
	if _, err := GenerateManifest(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "gh.yaml")); err != nil {
		t.Fatal(err)
	}
	err := CheckIntegrity(dir, IntegrityPolicy{})
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing listed file should be refused, got %v", err)
	}
}

// TestCorruptManifestRefused: a malformed manifest refuses the set, never silently degrading to
// "unsigned".
func TestCorruptManifestRefused(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "aws.yaml", awsTemplate)
	writeRuleFile(t, dir, IntegrityManifestName, "this is not a valid manifest line\n")
	err := CheckIntegrity(dir, IntegrityPolicy{})
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("corrupt manifest should refuse the set, got %v", err)
	}
}

// TestUpdateUnsignedRemoteRefused exercises the full Update path with the CLI's integrity-then-lint
// hook: an unsigned remote set is refused before anything is written, and --allow-unsigned lets it
// through.
func TestUpdateUnsignedRemoteRefused(t *testing.T) {
	src := t.TempDir()
	writeRuleFile(t, src, "aws.yaml", awsTemplate) // unsigned remote
	target := filepath.Join(t.TempDir(), "installed")

	untrusted := func(dir string) error {
		if err := CheckIntegrity(dir, IntegrityPolicy{Trust: TrustUntrusted}); err != nil {
			return err
		}
		return ValidateForUpdate(dir)
	}
	_, err := Update(UpdateOpts{Source: src, Target: target, Now: "t", Validate: untrusted})
	if err == nil {
		t.Fatal("Update of an unsigned untrusted source must be refused")
	}
	if !strings.Contains(err.Error(), IntegrityManifestName) {
		t.Errorf("refusal should mention the missing manifest: %v", err)
	}
	// Nothing should have been written to the target on a refused update.
	if _, serr := os.Stat(filepath.Join(target, "aws.yaml")); serr == nil {
		t.Error("a refused update must not write any file into the target")
	}

	// With the unsigned opt-in the install proceeds.
	allow := func(dir string) error {
		if err := CheckIntegrity(dir, IntegrityPolicy{Trust: TrustUntrusted, AllowUnsigned: true}); err != nil {
			return err
		}
		return ValidateForUpdate(dir)
	}
	if _, err := Update(UpdateOpts{Source: src, Target: target, Now: "t", Validate: allow}); err != nil {
		t.Fatalf("--allow-unsigned Update should succeed: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(target, "aws.yaml")); serr != nil {
		t.Errorf("allow-unsigned install should have written the template: %v", serr)
	}
}

// TestUpdateSelfSignedRemoteStillNeedsOptIn drives the full Update path against a remote that
// self-signed its own files: refused without --allow-unsigned (nothing written), installs with it, and
// the installed set verifies under bundled trust once re-blessed.
func TestUpdateSelfSignedRemoteStillNeedsOptIn(t *testing.T) {
	src := t.TempDir()
	writeRuleFile(t, src, "aws.yaml", awsTemplate)
	if _, err := GenerateManifest(src); err != nil { // self-signed source
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "installed")

	untrusted := func(dir string) error {
		if err := CheckIntegrity(dir, IntegrityPolicy{Trust: TrustUntrusted}); err != nil {
			return err
		}
		return ValidateForUpdate(dir)
	}
	_, err := Update(UpdateOpts{Source: src, Target: target, Now: "t", Validate: untrusted})
	if err == nil {
		t.Fatal("a self-signed untrusted Update must be refused without --allow-unsigned")
	}
	if !strings.Contains(err.Error(), "allow-unsigned") {
		t.Errorf("refusal should point at the --allow-unsigned opt-in: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(target, "aws.yaml")); serr == nil {
		t.Error("a refused update must not write any file into the target")
	}

	allow := func(dir string) error {
		if err := CheckIntegrity(dir, IntegrityPolicy{Trust: TrustUntrusted, AllowUnsigned: true}); err != nil {
			return err
		}
		return ValidateForUpdate(dir)
	}
	res, err := Update(UpdateOpts{Source: src, Target: target, Now: "t", Validate: allow})
	if err != nil {
		t.Fatalf("--allow-unsigned Update should succeed: %v", err)
	}
	if len(res.Added) != 1 {
		t.Errorf("expected 1 added template, got %d", len(res.Added))
	}
	// The installed set, once re-blessed, verifies under bundled trust (the binary-anchored tamper-check).
	if _, err := GenerateManifest(target); err != nil {
		t.Fatal(err)
	}
	if err := CheckIntegrity(target, IntegrityPolicy{}); err != nil {
		t.Errorf("installed+blessed set should verify: %v", err)
	}
}

// TestDirSizeCap covers the clone disk-fill backstop: dirSize sums a tree exactly under the cap and
// trips (returns > limit) once it exceeds the cap, so fetch can refuse an oversized checkout.
func TestDirSizeCap(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "a.yaml", strings.Repeat("x", 100))
	writeRuleFile(t, dir, "sub/b.yaml", strings.Repeat("y", 200))

	// Generous limit: exact total (300), and the early-stop never fires.
	if n, err := dirSize(dir, 1<<20); err != nil || n != 300 {
		t.Fatalf("dirSize under cap = %d (err %v), want 300", n, err)
	}
	// Tight limit: the running total must exceed it (the cap trips), refusing the tree.
	if n, err := dirSize(dir, 150); err != nil || n <= 150 {
		t.Fatalf("dirSize over cap = %d (err %v), want > 150", n, err)
	}
}

// TestBundledRulesManifestVerifies guards the shipped rules/MANIFEST.sha256: the committed bundled
// set must verify against its own manifest under bundled trust. Editing a bundled template without
// re-running `prowl rules manifest rules` fails this loudly.
func TestBundledRulesManifestVerifies(t *testing.T) {
	// internal/rules -> ../../rules
	dir := filepath.Join("..", "..", "rules")
	if _, err := os.Stat(filepath.Join(dir, IntegrityManifestName)); err != nil {
		t.Skipf("bundled rules manifest not present (%v) — skipping", err)
	}
	if err := CheckIntegrity(dir, IntegrityPolicy{}); err != nil {
		t.Fatalf("bundled rule set must verify against its committed %s (re-run 'prowl rules manifest rules'): %v", IntegrityManifestName, err)
	}
}
