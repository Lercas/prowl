package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/Lercas/prowl/tool/internal/localfile"
	"github.com/Lercas/prowl/tool/internal/logx"
)

// ManifestName is the sha256sum-format checksum manifest of a verifier set. It only tamper-detects
// the bundled set (anchored by the binary); a manifest an untrusted set ships is self-attested and
// authenticates nothing, so untrusted sets need the explicit --allow-unsigned opt-in (see Trust).
const ManifestName = "MANIFEST.sha256"

// Trust selects how strictly a verifier source's integrity is enforced at load.
type Trust int

const (
	// TrustBundled is the default for the shipped set (anchored by the binary). A manifest, when
	// present, is enforced (mismatched/unlisted/missing files refused); a manifest-less set still loads
	// so a hand-authored `--verifiers DIR` keeps working. The exfil guard always applies.
	TrustBundled Trust = iota
	// TrustUntrusted is for a third-party/remote set, which has no trust anchor. It loads only with the
	// explicit AllowUnsigned opt-in, regardless of any (self-attested) manifest it ships.
	TrustUntrusted
)

// LoadPolicy controls integrity enforcement. The zero value is the safe default: bundled trust, no
// unsigned escape hatch.
type LoadPolicy struct {
	Trust Trust
	// AllowUnsigned (the --allow-unsigned flag) is the operator's explicit "load at my own risk"
	// opt-in: it lets an untrusted set load (with or without a manifest) and downgrades the exfil
	// guard from refuse to warn. For an untrusted set it is the only way to load.
	AllowUnsigned bool
}

// integrityError describes why a set (or part of it) failed its integrity check. It never embeds a
// secret — only file paths and hashes.
type integrityError struct {
	dir       string
	untrusted bool     // an untrusted set was loaded without --allow-unsigned (manifest or not)
	mismatch  []string // files whose on-disk hash != manifest
	unlisted  []string // .yaml/.yml on disk but absent from the manifest
	missing   []string // listed in the manifest but absent on disk
}

func (e *integrityError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "verifier set %s failed integrity check", e.dir)
	if e.untrusted {
		fmt.Fprintf(&b, ": a third-party --source cannot be authenticated (a %s it ships proves nothing — an attacker plants an exfil verifier and signs their own copy); re-run with --allow-unsigned to install it at your own risk", ManifestName)
		return b.String()
	}
	if len(e.mismatch) > 0 {
		fmt.Fprintf(&b, "; tampered/modified: %s", strings.Join(e.mismatch, ", "))
	}
	if len(e.unlisted) > 0 {
		fmt.Fprintf(&b, "; not in manifest: %s", strings.Join(e.unlisted, ", "))
	}
	if len(e.missing) > 0 {
		fmt.Fprintf(&b, "; listed but missing: %s", strings.Join(e.missing, ", "))
	}
	return b.String()
}

// hashFile returns the lowercase hex sha256 of a file's bytes.
func hashFile(path string) (string, error) {
	raw, err := localfile.ReadRegular(path, MaxVerifierSize)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// GenerateManifest (re)computes and writes MANIFEST.sha256 for dir, blessing its current contents
// (exposed via `prowl verifiers manifest`). It returns the number of files recorded.
func GenerateManifest(dir string) (n int, err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	snapshot, err := readDirectorySnapshotRoot(root, dir, false)
	if err != nil {
		return 0, err
	}
	var b strings.Builder
	for _, file := range snapshot.files {
		sum := sha256.Sum256(file.raw)
		b.WriteString(localfile.SHA256ManifestLine(sum, file.rel))
		if b.Len() > MaxManifestSize {
			return 0, fmt.Errorf("generated manifest exceeds %d bytes", MaxManifestSize)
		}
	}
	// The manifest contains public checksums and must remain readable by non-owner scanner processes.
	if err := localfile.WriteRootAtomic(root, ManifestName, []byte(b.String()), 0o644); err != nil {
		return 0, err
	}
	return len(snapshot.files), nil
}

// parseManifest preserves filename bytes after the sha256sum separator and rejects duplicate paths.
func parseManifest(raw []byte) (map[string]string, error) {
	return localfile.ParseSHA256Manifest(raw, ManifestName)
}

// checkSnapshot verifies the captured bytes against policy and returns the relpaths cleared to load (empty when
// refused), whether the set is signed, and a hard-refusal error. signed is true only for a bundled
// set with a verified manifest (the only real trust signal the exfil guard may downgrade on).
//   - untrusted: refused unless AllowUnsigned; with it, loads signed=false (any manifest still consistency-checked).
//   - bundled + manifest: every listed file must match; an unlisted/missing file fails.
//   - bundled, no manifest: allow all.
func checkSnapshot(dir string, policy LoadPolicy, snapshot *directorySnapshot) (allowed map[string]bool, signed bool, err error) {
	manifest, present := snapshot.manifest, snapshot.manifest != nil
	rels := make([]string, 0, len(snapshot.files))
	for _, file := range snapshot.files {
		rels = append(rels, file.rel)
	}
	// An untrusted set's self-shipped manifest authenticates nothing, so refuse without the opt-in.
	if policy.Trust == TrustUntrusted && !policy.AllowUnsigned {
		return nil, false, &integrityError{dir: dir, untrusted: true}
	}
	if !present {
		if policy.Trust == TrustUntrusted { // AllowUnsigned: load but make the trust downgrade loud
			logx.Warn("loading UNSIGNED verifier set (no "+ManifestName+"): integrity NOT verified, source NOT authenticated",
				"dir", dir, "files", len(rels))
		}
		allowed = map[string]bool{}
		for _, rel := range rels {
			allowed[rel] = true
		}
		return allowed, false, nil
	}

	ie := &integrityError{dir: dir}
	onDisk := map[string]bool{}
	for _, file := range snapshot.files {
		rel := file.rel
		onDisk[rel] = true
		want, ok := manifest[rel]
		if !ok {
			ie.unlisted = append(ie.unlisted, rel)
			continue
		}
		sum := sha256.Sum256(file.raw)
		got := hex.EncodeToString(sum[:])
		if got != want {
			ie.mismatch = append(ie.mismatch, rel)
		}
	}
	for rel := range manifest {
		if !onDisk[rel] {
			ie.missing = append(ie.missing, rel)
		}
	}
	sort.Strings(ie.mismatch)
	sort.Strings(ie.unlisted)
	sort.Strings(ie.missing)
	if len(ie.mismatch) > 0 || len(ie.unlisted) > 0 || len(ie.missing) > 0 {
		return nil, false, ie
	}
	allowed = map[string]bool{}
	for _, rel := range rels {
		allowed[rel] = true
	}
	// signed only for a bundled set: its manifest is binary-anchored. An untrusted set reaches here
	// only via AllowUnsigned (already warn-mode), so its self-shipped manifest never counts as signed.
	return allowed, policy.Trust == TrustBundled, nil
}

// reBase64Secret matches a {{base64(EXPR)}} token whose EXPR references the secret (so the URL would
// carry a base64-encoded copy of the live value).
var reBase64Secret = regexp.MustCompile(`\{\{base64\([^)]*secret[^)]*\)\}\}`)

// urlInterpolatesSecret reports whether a URL interpolates the live secret ({{secret}} or
// base64(...secret...)) — the exfil pattern, since a legit verifier puts the secret in a header or
// body, not a URL. Headers/body and public-half context vars (e.g. {{aws_access_key_id}}) are allowed.
func urlInterpolatesSecret(rawURL string) bool {
	return strings.Contains(rawURL, "{{secret}}") || reBase64Secret.MatchString(rawURL)
}

// exfilRequests returns the indices of a verifier's requests whose URL exfiltrates the secret.
func exfilRequests(v *Verifier) []int {
	var idx []int
	for i := range v.Requests {
		if urlInterpolatesSecret(v.Requests[i].URL) {
			idx = append(idx, i)
		}
	}
	return idx
}
