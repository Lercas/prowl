package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Lercas/prowl/tool/internal/localfile"
	"github.com/Lercas/prowl/tool/internal/logx"
)

// IntegrityManifestName is a sha256sum-format checksum manifest of every rule-template file, used for
// post-install tamper-detection of the bundled/installed set (the binary is the trust anchor). It
// cannot authenticate an untrusted --source — a self-shipped manifest proves nothing, so those need
// --allow-unsigned (see CheckIntegrity). Distinct from ManifestName (the version/provenance record).
const IntegrityManifestName = "MANIFEST.sha256"

// Trust selects how strictly a rule source's integrity is enforced at install/load.
type Trust int

const (
	// TrustBundled is the default for the shipped/installed set (anchored by the binary). A present
	// MANIFEST.sha256 is enforced — the real tamper-check for a later edit; a manifest-less set still
	// loads, so a hand-authored `--rules-dir DIR` keeps working.
	TrustBundled Trust = iota
	// TrustUntrusted is a third-party/remote `--source` with no trust anchor. It installs ONLY with the
	// explicit AllowUnsigned opt-in, regardless of any carried manifest (which authenticates nothing).
	TrustUntrusted
)

// IntegrityPolicy controls integrity enforcement. The zero value is the safe default: bundled trust,
// no unsigned escape hatch.
type IntegrityPolicy struct {
	Trust Trust
	// AllowUnsigned is the operator's explicit `--allow-unsigned` opt-in: the only way to install an
	// untrusted --source (a manifest the source ships does not substitute for it).
	AllowUnsigned bool
}

// integrityError describes why a rule set failed its integrity check, carrying only file paths and
// the mismatch kind (never rule content).
type integrityError struct {
	dir       string
	untrusted bool     // an untrusted --source was installed without --allow-unsigned (manifest or not)
	mismatch  []string // files whose on-disk hash != manifest
	unlisted  []string // .yaml/.yml on disk but absent from the manifest
	missing   []string // listed in the manifest but absent on disk
}

func (e *integrityError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "rule set %s failed integrity check", e.dir)
	if e.untrusted {
		fmt.Fprintf(&b, ": a third-party --source cannot be authenticated (a %s it ships proves nothing — an attacker neuters the rules and signs their own copy); re-run with --allow-unsigned to install it at your own risk", IntegrityManifestName)
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

// hashFileBytes returns the lowercase hex sha256 of a file's bytes.
func hashFileBytes(path string) (string, error) {
	raw, err := localfile.ReadRegular(path, MaxTemplateSize)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// GenerateManifest (re)computes and writes MANIFEST.sha256 for the rule set in dir, blessing its
// current contents (exposed via `prowl rules manifest` and used by `rules update` to re-bless what it
// installed). Returns the number of files recorded.
func GenerateManifest(dir string) (n int, err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	snapshot, err := readLibrarySnapshotRoot(root, dir, false)
	if err != nil {
		return 0, err
	}
	var b strings.Builder
	for _, file := range snapshot.files {
		sum := sha256.Sum256(file.raw)
		b.WriteString(localfile.SHA256ManifestLine(sum, file.rel))
		if b.Len() > MaxIntegrityManifestSize {
			return 0, fmt.Errorf("generated manifest exceeds %d bytes", MaxIntegrityManifestSize)
		}
	}
	// The manifest contains public checksums and must remain readable by non-owner scanner processes.
	if err := localfile.WriteRootAtomic(root, IntegrityManifestName, []byte(b.String()), 0o644); err != nil {
		return 0, err
	}
	return len(snapshot.files), nil
}

// CheckIntegrity verifies the rule set in dir against policy, returning an error that refuses the set
// when it fails:
//   - TrustUntrusted: refused unless AllowUnsigned, even with a manifest; with AllowUnsigned, a present
//     manifest is still consistency-checked and a manifest-less set is warned.
//   - TrustBundled: a present manifest is authoritative (mismatch/unlisted/missing fails); no manifest
//     passes (hand-authored --rules-dir keeps working).
func CheckIntegrity(dir string, policy IntegrityPolicy) error {
	snapshot, err := readLibrarySnapshot(dir, true)
	if err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	return checkLibrarySnapshot(dir, policy, snapshot)
}

// checkLibrarySnapshot checks the exact captured bytes available to the compiler.
func checkLibrarySnapshot(dir string, policy IntegrityPolicy, snapshot *librarySnapshot) error {
	manifest, present := snapshot.manifest, snapshot.manifest != nil
	// An untrusted --source is trusted only by the explicit opt-in; a self-shipped manifest can't
	// substitute for it, so refuse outright when AllowUnsigned is absent.
	if policy.Trust == TrustUntrusted && !policy.AllowUnsigned {
		return &integrityError{dir: dir, untrusted: true}
	}
	if !present {
		if policy.Trust == TrustUntrusted { // AllowUnsigned: accept but make the trust downgrade loud
			logx.Warn("installing UNSIGNED rule set (no "+IntegrityManifestName+"): integrity NOT verified, source NOT authenticated",
				"dir", dir, "files", len(snapshot.files))
		}
		return nil
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
		return ie
	}
	return nil
}
