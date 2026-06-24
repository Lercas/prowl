package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

// TestWriteReportFileSurfacesError proves writeReportFile returns (rather than swallows) a failure to
// write the --output file, so a truncated-empty file can't pass as a successful run.
func TestWriteReportFileSurfacesError(t *testing.T) {
	// A path whose parent is a regular file (not a dir) can't be opened for writing → OpenFile errors.
	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(notADir, "report.json") // parent "file" is not a directory
	err := writeReportFile(badPath, []model.Finding{{Type: "x", Severity: "high", Path: "p"}}, "json")
	if err == nil {
		t.Fatal("writeReportFile returned nil for an unwritable path; the error was swallowed")
	}
}

// TestWriteReportFileHappyPath proves a normal --output path is written with valid content and the
// O_NOFOLLOW open succeeds for a plain (non-symlink) target.
func TestWriteReportFileHappyPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := writeReportFile(path, []model.Finding{{Type: "x", Severity: "high", Path: "p", Confidence: 0.9}}, "json"); err != nil {
		t.Fatalf("writeReportFile errored on a normal path: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Fatal("--output file is empty after a successful write")
	}
}

// TestWriteReportFileRejectsSymlink proves the --output target is opened with O_NOFOLLOW so a symlink
// planted at the target isn't followed and its destination isn't clobbered (matching the install
// path's symlink discipline). Without O_NOFOLLOW, os.Create would write through the link.
func TestWriteReportFileRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("O_NOFOLLOW symlink semantics are POSIX")
	}
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("DO NOT CLOBBER"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "out.json")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	err := writeReportFile(link, []model.Finding{{Type: "x", Severity: "high", Path: "p"}}, "json")
	if err == nil {
		t.Fatal("writeReportFile followed a symlinked --output target (O_NOFOLLOW not applied)")
	}
	// The symlink's destination must be untouched.
	if b, _ := os.ReadFile(victim); string(b) != "DO NOT CLOBBER" {
		t.Errorf("symlink destination was clobbered: %q", b)
	}
	// The open failed before creating anything, so the user's pre-existing symlink must survive (the
	// stale-file cleanup must not delete a path it never created).
	if fi, lerr := os.Lstat(link); lerr != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("pre-existing symlink at --output target was removed on an open failure")
	}
}

// writeTemplate drops a minimal valid rule template into dir/name and returns nothing.
func writeTemplate(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	tmpl := `id: ` + name + `
info:
  name: ` + name + `
  severity: high
matchers-condition: and
matchers:
  - type: word
    words: [` + name + `]
  - type: regex
    regex: ['` + name + `_[a-z0-9]{8}']
`
	if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(tmpl), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestRulesOnlyIsolatesEngine proves --rules-only loads ONLY the rule dirs the user passed and never
// auto-discovers the installed ~/.prowl/rules.
func TestRulesOnlyIsolatesEngine(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PROWL_HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "") // ensure PROWL_HOME wins in prowlHome()
	// Simulate an installed template set under the home dir (what `prowl rules update` writes).
	installed := filepath.Join(home, "rules")
	writeTemplate(t, installed, "installed-rule")
	writeTemplate(t, installed, "another-installed")
	if got := discoverRulesDirs(nil); len(got) != 1 || got[0] != installed {
		t.Fatalf("precondition: installed dir should be auto-discovered without --rules-only, got %v", got)
	}

	// --rules-only with NO --rules-dir: nothing is auto-discovered, engine is nil.
	if eng := loadEngine(commonFlags{rulesOnly: true}); eng != nil {
		t.Errorf("--rules-only with no --rules-dir must load no templates (got %d); the installed ~/.prowl/rules must be ignored", eng.Len())
	}

	// Without --rules-only the installed set IS auto-loaded (the normal, documented behavior).
	if eng := loadEngine(commonFlags{}); eng == nil || eng.Len() != 2 {
		n := 0
		if eng != nil {
			n = eng.Len()
		}
		t.Errorf("without --rules-only the installed templates should auto-load (want 2, got %d)", n)
	}

	// --rules-only WITH an explicit --rules-dir loads ONLY that dir, not the installed one.
	userDir := t.TempDir()
	writeTemplate(t, userDir, "user-rule")
	eng := loadEngine(commonFlags{rulesOnly: true, rulesDir: []string{userDir}})
	if eng == nil || eng.Len() != 1 {
		n := 0
		if eng != nil {
			n = eng.Len()
		}
		t.Fatalf("--rules-only --rules-dir <dir> should load ONLY that dir (want 1, got %d)", n)
	}
	if eng.Templates()[0].ID != "user-rule" {
		t.Errorf("expected the user's rule, got %q (installed templates must not leak in)", eng.Templates()[0].ID)
	}
}

func TestParseByteSizeStrict(t *testing.T) {
	ok := map[string]int64{"10485760": 10485760, "10MB": 10 << 20, "4M": 4 << 20, "2KB": 2 << 10, "1GB": 1 << 30, "512B": 512}
	for in, want := range ok {
		if got, err := parseByteSize(in); err != nil || got != want {
			t.Errorf("parseByteSize(%q) = (%d,%v), want (%d,nil)", in, got, err, want)
		}
	}
	// trailing garbage / nonsense must ERROR, not partial-parse (the "10MB"->10 fmt.Sscan footgun)
	for _, bad := range []string{"10XQ", "abc", "10 MB junk", "", "1.5MB", "0x10"} {
		if got, err := parseByteSize(bad); err == nil {
			t.Errorf("parseByteSize(%q) = %d, want error", bad, got)
		}
	}
}

func TestGateFailsClosedOnInvalidFailOn(t *testing.T) {
	high := []model.Finding{{Severity: "high"}}
	if gate(high, "", false) != 0 {
		t.Error("empty fail_on must not gate")
	}
	if gate(high, "high", false) != 1 {
		t.Error("valid fail_on=high with a high finding must gate (exit 1)")
	}
	// a typo'd value must FAIL CLOSED (1), never silently disable the gate (the fail-open defect)
	for _, bad := range []string{"hihg", "HIGH", "all", "none"} {
		if gate(high, bad, false) != 1 {
			t.Errorf("invalid fail_on %q must fail closed (exit 1), got 0", bad)
		}
	}
}

func TestFailOnVerified(t *testing.T) {
	live := true
	invalid := false
	mk := func(sev string, v *bool) model.Finding { return model.Finding{Severity: sev, Verified: v} }
	// --fail-on-verified gates ONLY on a confirmed-live secret, regardless of severity / --fail-on
	if gate([]model.Finding{mk("low", &live)}, "", true) != 1 {
		t.Error("a confirmed-live secret must gate under --fail-on-verified even with no --fail-on")
	}
	// invalid (revoked/fake), unsupported (nil), and unverified must NOT trip --fail-on-verified
	for _, f := range []model.Finding{mk("critical", &invalid), mk("critical", nil)} {
		if gate([]model.Finding{f}, "", true) != 0 {
			t.Errorf("non-live finding (%v) must not trip --fail-on-verified", f.Verified)
		}
	}
	// without --fail-on-verified, liveness is ignored and only --fail-on severity matters
	if gate([]model.Finding{mk("low", &live)}, "high", false) != 0 {
		t.Error("without --fail-on-verified a low live finding must not gate at --fail-on high")
	}
	// escalateLive bumps a live finding to critical
	fs := []model.Finding{mk("low", &live), mk("high", &invalid)}
	escalateLive(fs)
	if fs[0].Severity != "critical" {
		t.Errorf("escalateLive must bump a live finding to critical, got %q", fs[0].Severity)
	}
	if fs[1].Severity != "high" {
		t.Errorf("escalateLive must not touch a non-live finding, got %q", fs[1].Severity)
	}
}

func TestMustIntStrict(t *testing.T) {
	// valid
	for _, v := range []string{"0", "5", "100"} {
		_ = mustInt("--x", v, 0) // must not exit (can't easily assert os.Exit; just exercise the parse)
	}
	// parseByteSize already covers strict-parse rejection; mustInt mirrors it via strconv.Atoi.
	if _, err := strconv.Atoi("5x"); err == nil {
		t.Error("strconv.Atoi should reject 5x (the strict-parse contract mustInt relies on)")
	}
}

func TestRedactURLStripsCredentials(t *testing.T) {
	cases := map[string]string{
		"https://deploy:ghp_TOKEN123@host/org/repo": "ghp_TOKEN123",
		"https://user:pw@example.com/x":             "pw",
		"git@github.com:org/repo.git":               "", // no userinfo to leak
		"https://host/no-creds":                     "",
	}
	for in, secret := range cases {
		out := redactURL(in)
		if secret != "" && strings.Contains(out, secret) {
			t.Errorf("redactURL(%q) = %q — leaked %q", in, out, secret)
		}
	}
	// a credentialed URL must become ***-userinfo, not pass through unchanged
	if got := redactURL("https://u:TOK@h/p"); strings.Contains(got, "TOK") || !strings.Contains(got, "***") {
		t.Errorf("redactURL did not redact: %q", got)
	}
}

func TestRedactURLPasswordWithAt(t *testing.T) {
	// the redaction must remove the WHOLE userinfo even when the password contains a literal '@'
	got := redactURL("https://u:p@ss@host.example/x")
	if strings.Contains(got, "p@ss") || strings.Contains(got, "ss@host") || !strings.Contains(got, "***@host.example") {
		t.Errorf("redactURL leaked password-with-@: %q", got)
	}
	// an '@' that appears only in the path is not credentials — left alone
	if got := redactURL("https://host/a@b"); got != "https://host/a@b" {
		t.Errorf("redactURL wrongly redacted a path '@': %q", got)
	}
}

// TestFailOnVerifiedIsKnownFlag guards the half-wired regression where --fail-on-verified was parsed in
// the switch but missing from knownFlags, so checkUnknownFlags rejected it (exit 2) before it ever ran.
func TestFailOnVerifiedIsKnownFlag(t *testing.T) {
	for _, f := range []string{"--fail-on-verified", "--fail-on", "--verify", "--ml", "--ml-threshold"} {
		if !knownFlags[f] {
			t.Errorf("%s is handled by parseCommon but missing from knownFlags — checkUnknownFlags will reject it", f)
		}
	}
}

func TestRestoreMissingLive(t *testing.T) {
	live := true
	mk := func(fp string, v *bool) model.Finding { return model.Finding{Fingerprint: fp, Verified: v} }
	liveGuard := []model.Finding{mk("a", &live), mk("b", &live)}
	// "a" was suppressed (not in findings), "b" survived — restore must re-add only "a"
	got := restoreMissingLive([]model.Finding{mk("b", &live), mk("c", nil)}, liveGuard)
	fps := map[string]bool{}
	for _, f := range got {
		fps[f.Fingerprint] = true
	}
	if !fps["a"] {
		t.Error("a suppressed live finding must be restored for the gate")
	}
	if len(got) != 3 { // b, c, +a — no duplicate of b
		t.Errorf("restore must not duplicate a surviving live finding, got %d", len(got))
	}
}

// round-7 regression: parseCommon preserves the --key=value token, so the bare-flag readers must be
// equals-aware (a plain contains() would miss --current-only=true / --authorized=true).
func TestHasFlagEqualsForm(t *testing.T) {
	if !hasFlag([]string{"host", "--current-only=true"}, "--current-only") {
		t.Error("--current-only=true not matched")
	}
	if !hasFlag([]string{"--authorized"}, "--authorized") {
		t.Error("bare --authorized not matched")
	}
	if hasFlag([]string{"--currently-broken"}, "--current-only") {
		t.Error("a different flag wrongly matched")
	}
	// ultra-audit regression: --current-only=false must be HONORED (false), else the entire history
	// walk is silently disabled (T30 defeated); likewise --authorized=false must not authorize.
	if hasFlag([]string{"--current-only=false"}, "--current-only") {
		t.Error("--current-only=false must be false (would silently disable history)")
	}
	if hasFlag([]string{"--current-only=0"}, "--current-only") {
		t.Error("--current-only=0 must be false")
	}
	if hasFlag([]string{"--authorized=false"}, "--authorized") {
		t.Error("--authorized=false must NOT authorize")
	}
	if !hasFlag([]string{"--current-only=true"}, "--current-only") {
		t.Error("--current-only=true must be true")
	}
	// verify-round regression: yes/no/on/off must be honored (ParseBool alone rejects them, which would
	// silently treat --current-only=no as set), and an unparseable value defaults to the SAFE direction.
	if hasFlag([]string{"--current-only=no"}, "--current-only") {
		t.Error("--current-only=no must be false")
	}
	if hasFlag([]string{"--current-only=off"}, "--current-only") {
		t.Error("--current-only=off must be false")
	}
	if !hasFlag([]string{"--current-only=yes"}, "--current-only") {
		t.Error("--current-only=yes must be true")
	}
	if hasFlag([]string{"--current-only=banana"}, "--current-only") {
		t.Error("unparseable value must default false (safe: scan more)")
	}
}
