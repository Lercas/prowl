package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".prowl.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAllowlistAndDetectors(t *testing.T) {
	c, err := Load(writeCfg(t, `
detectors:
  disable: [generic_high_entropy]
  enable: [aws_access_key_id, github_pat_classic]
  custom:
    - {id: acme, regex: 'acme_[0-9]+', category: vcs}
allowlist:
  values: ["AKIAEXACTVALUE"]
  paths: ["vendor/"]
  regexes: ['(?i)example']
`))
	if err != nil {
		t.Fatal(err)
	}
	// allowlist
	if !c.Allowed("AKIAEXACTVALUE", "a.py") {
		t.Error("value allowlist failed")
	}
	if !c.Allowed("anything", "x/vendor/lib.js") {
		t.Error("path allowlist failed")
	}
	if !c.Allowed("MyEXAMPLEkey", "a.py") {
		t.Error("regex allowlist failed")
	}
	if c.Allowed("AKIAREALSECRET99", "src/a.py") {
		t.Error("non-allowlisted wrongly allowed")
	}
	// enable/disable: enable list is exclusive
	if !c.TypeEnabled("aws_access_key_id") {
		t.Error("enabled type reported disabled")
	}
	if c.TypeEnabled("stripe_secret_key") {
		t.Error("type not in enable-list reported enabled")
	}
	if c.TypeEnabled("generic_high_entropy") {
		t.Error("disabled type reported enabled")
	}
	if len(c.Detectors.Custom) != 1 || c.Detectors.Custom[0].ID != "acme" {
		t.Errorf("custom rule not parsed: %+v", c.Detectors.Custom)
	}
}

func TestValidateUnknownKeyFlagged(t *testing.T) {
	// `allowlsit:` and `detctors:` are typos a plain Unmarshal silently ignores; the validator catches them.
	c, err := Load(writeCfg(t, `
version: 1
allowlsit:
  values: ["AKIAEXACTVALUE"]
detctors:
  disable: [stripe_secret_key]
`))
	if err != nil {
		t.Fatal(err)
	}
	probs := c.Validate()
	if !anyContains(probs, "allowlsit") || !anyContains(probs, "detctors") {
		t.Errorf("expected unknown-key typos flagged, got %v", probs)
	}
}

func TestValidateUnknownNestedKey(t *testing.T) {
	c, err := Load(writeCfg(t, `
allowlist:
  pathz: ["vendor/"]
detectors:
  custm: []
`))
	if err != nil {
		t.Fatal(err)
	}
	probs := c.Validate()
	if !anyContains(probs, "pathz") || !anyContains(probs, "custm") {
		t.Errorf("expected unknown nested keys flagged, got %v", probs)
	}
}

func TestEmptyCustomRegexRejectedAtLoad(t *testing.T) {
	for _, body := range []string{
		"detectors:\n  custom:\n    - {id: bad, regex: '', category: vcs}\n",
		"detectors:\n  custom:\n    - {id: dot, regex: '.*', category: vcs}\n",
		"detectors:\n  custom:\n    - {id: anchored, regex: '^.*$', category: vcs}\n",
		"detectors:\n  custom:\n    - {id: flagged, regex: '(?i).*', category: vcs}\n",
		"detectors:\n  custom:\n    - {id: grouped, regex: '(.*)', category: vcs}\n",
	} {
		if _, err := Load(writeCfg(t, body)); err == nil {
			t.Errorf("expected Load to reject match-everything custom regex for %q", body)
		}
	}
	// a real regex must still load
	if _, err := Load(writeCfg(t, "detectors:\n  custom:\n    - {id: ok, regex: 'acme_[0-9]+', category: vcs}\n")); err != nil {
		t.Errorf("valid custom regex wrongly rejected: %v", err)
	}
}

// TestMatchAllBypassesRejected asserts the behavioural match-all guard catches `.*`-equivalents a
// fixed denylist would miss (`[\s\S]*`, `[\d\D]+`, `(?s)^.*$`, ...) and refuses them at Load.
func TestMatchAllBypassesRejected(t *testing.T) {
	bypass := []string{`[\s\S]*`, `[\s\S]+`, `[\d\D]*`, `[\d\D]+`, `(?s)^.*$`, `(?s).+`, `[\w\W]*`, `.{0,}`}
	for _, rx := range bypass {
		body := "detectors:\n  custom:\n    - {id: bad, regex: '" + rx + "', category: vcs}\n"
		if _, err := Load(writeCfg(t, body)); err == nil {
			t.Errorf("expected Load to reject match-all bypass regex %q", rx)
		}
		if !matchEverythingRe(rx) {
			t.Errorf("matchEverythingRe(%q) = false, want true (effectively match-all)", rx)
		}
	}
	// Real secret-shaped detectors must NOT be flagged as match-all.
	for _, rx := range []string{`AKIA[0-9A-Z]{16}`, `acme_[0-9]+`, `sk_live_[0-9a-zA-Z]{24}`, `[A-Z]{3}`, `\d{4}-\d{4}`} {
		if matchEverythingRe(rx) {
			t.Errorf("matchEverythingRe(%q) = true, want false (a normal detector wrongly rejected)", rx)
		}
	}
}

// TestAllowlistMatchAllRejected asserts an over-broad allowlist regex is flagged by Issues and
// dropped from the active allow set, so a real secret is still reported.
func TestAllowlistMatchAllRejected(t *testing.T) {
	for _, rx := range []string{`.*`, `[\s\S]*`, `(?s)^.*$`} {
		c, err := Load(writeCfg(t, "allowlist:\n  regexes: ['"+rx+"']\n"))
		if err != nil {
			t.Fatalf("Load with allowlist regex %q: %v", rx, err)
		}
		if !anyContains(c.Issues(), "matches everything") {
			t.Errorf("allowlist regex %q not flagged by Issues(): %v", rx, c.Issues())
		}
		if c.Allowed("AKIAREALSECRET99999X", "src/app.py") {
			t.Errorf("allowlist regex %q silently suppressed a real finding (match-all not dropped)", rx)
		}
	}
	// A narrow allowlist regex still works and is not flagged.
	c, err := Load(writeCfg(t, "allowlist:\n  regexes: ['(?i)example']\n"))
	if err != nil {
		t.Fatal(err)
	}
	if anyContains(c.Issues(), "matches everything") {
		t.Errorf("narrow allowlist regex wrongly flagged as match-all: %v", c.Issues())
	}
	if !c.Allowed("MyEXAMPLEkey", "a.py") {
		t.Error("narrow allowlist regex should still suppress its matching value")
	}
}

// TestAllowlistPathMatchAllRejected asserts a near-universal allowlist.paths entry (".", "/", a
// single char) is flagged and dropped, while a targeted entry like "test/" still suppresses its paths.
func TestAllowlistPathMatchAllRejected(t *testing.T) {
	for _, p := range []string{".", "/", "a", "e"} {
		c, err := Load(writeCfg(t, "allowlist:\n  paths: ['"+p+"']\n"))
		if err != nil {
			t.Fatalf("Load with allowlist path %q: %v", p, err)
		}
		if !anyContains(c.Issues(), "matches every path") {
			t.Errorf("allowlist path %q not flagged by Issues(): %v", p, c.Issues())
		}
		if c.Allowed("AKIA4ZX9QJ7K2MNPL3RS", "src/app.py") {
			t.Errorf("allowlist path %q silently suppressed a real finding (match-all not dropped)", p)
		}
	}
	// A legitimately targeted path entry must still work and not be flagged.
	c, err := Load(writeCfg(t, "allowlist:\n  paths: ['test/']\n"))
	if err != nil {
		t.Fatal(err)
	}
	if anyContains(c.Issues(), "matches every path") {
		t.Errorf("narrow allowlist path wrongly flagged as match-all: %v", c.Issues())
	}
	if !c.Allowed("AKIA4ZX9QJ7K2MNPL3RS", "test/leak.py") {
		t.Error("narrow allowlist path should still suppress its matching path")
	}
	if c.Allowed("AKIA4ZX9QJ7K2MNPL3RS", "src/leak.py") {
		t.Error("narrow allowlist path should NOT suppress a non-matching path")
	}
}

// TestAllowlistStopWordMatchAllRejected asserts a single-char allowlist.stopwords entry is flagged
// and dropped, while a real multi-char stopword like "EXAMPLE" still suppresses values containing it.
func TestAllowlistStopWordMatchAllRejected(t *testing.T) {
	for _, w := range []string{"a", "e", "0"} {
		c, err := Load(writeCfg(t, "allowlist:\n  stopwords: ['"+w+"']\n"))
		if err != nil {
			t.Fatalf("Load with allowlist stopword %q: %v", w, err)
		}
		if !anyContains(c.Issues(), "matches every value") {
			t.Errorf("allowlist stopword %q not flagged by Issues(): %v", w, c.Issues())
		}
		if c.Allowed("AKIA4ZX9QJ7K2MNPL3RS", "src/app.py") {
			t.Errorf("allowlist stopword %q silently suppressed a real finding (match-all not dropped)", w)
		}
	}
	// A real multi-char stopword must still suppress a value that contains it, and not be flagged.
	c, err := Load(writeCfg(t, "allowlist:\n  stopwords: [EXAMPLE]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if anyContains(c.Issues(), "matches every value") {
		t.Errorf("narrow allowlist stopword wrongly flagged as match-all: %v", c.Issues())
	}
	if !c.Allowed("AKIAIOSFODNN7EXAMPLE", "src/app.py") {
		t.Error("narrow allowlist stopword should still suppress a value containing it")
	}
	if c.Allowed("AKIA4ZX9QJ7K2MNPL3RS", "src/app.py") {
		t.Error("narrow allowlist stopword should NOT suppress a value lacking it")
	}
}

// TestFailOnValidation asserts a typo'd output.fail_on is flagged (it would fail open in CI) while
// every valid severity is accepted silently.
func TestFailOnValidation(t *testing.T) {
	c, err := Load(writeCfg(t, "output:\n  fail_on: hihg\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !anyContains(c.Issues(), "hihg") || !anyContains(c.Issues(), "not a valid severity") {
		t.Errorf("typo'd fail_on not flagged by Issues(): %v", c.Issues())
	}
	if !anyContains(c.Validate(), "hihg") {
		t.Errorf("typo'd fail_on not flagged by Validate(): %v", c.Validate())
	}
	// Every valid severity (mirrors model.SeverityOrder) must be accepted without a fail_on warning.
	for _, lvl := range []string{"info", "low", "medium", "high", "critical"} {
		c, err := Load(writeCfg(t, "output:\n  fail_on: "+lvl+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		if anyContains(c.Issues(), "fail_on") {
			t.Errorf("valid fail_on %q wrongly flagged: %v", lvl, c.Issues())
		}
	}
	// An empty fail_on (the default — no gate) is not flagged.
	c2, _ := Load(writeCfg(t, "version: 1\n"))
	if anyContains(c2.Issues(), "fail_on") {
		t.Errorf("empty fail_on wrongly flagged: %v", c2.Issues())
	}
}

func TestValidateUnknownCategory(t *testing.T) {
	// A recognized-shape regex with a bogus category, so Load succeeds and Validate flags the category.
	c, err := Load(writeCfg(t, "detectors:\n  custom:\n    - {id: rule1, regex: 'tok_[0-9]+', category: bananas}\n"))
	if err != nil {
		t.Fatal(err)
	}
	probs := c.Validate()
	if !anyContains(probs, "bananas") || !anyContains(probs, "unknown category") {
		t.Errorf("expected unknown category flagged, got %v", probs)
	}
	// a known category is clean
	c2, _ := Load(writeCfg(t, "detectors:\n  custom:\n    - {id: rule2, regex: 'tok_[0-9]+', category: db}\n"))
	for _, p := range c2.Validate() {
		if anyContains([]string{p}, "unknown category") {
			t.Errorf("known category wrongly flagged: %v", p)
		}
	}
}

// TestEnableKillSwitchFlagged asserts EnableResolvesToZero/EnableIssues flag an enable list that
// resolves to zero known detectors (a restrict-to-only kill-switch) and name the bogus entries,
// while a list naming at least one real type is not flagged.
func TestEnableKillSwitchFlagged(t *testing.T) {
	// The valid type-id set lives in the taxonomy, so the caller supplies it.
	known := []string{"aws_access_key_id", "github_pat_classic", "stripe_secret_key"}

	// (1) enable:[bogus] -> kill-switch: resolves to zero, flagged, bogus entry named.
	cBogus, err := Load(writeCfg(t, "detectors:\n  enable: [nonexistent_type]\n"))
	if err != nil {
		t.Fatal(err)
	}
	zero, bogus := cBogus.EnableResolvesToZero(known)
	if !zero {
		t.Errorf("enable:[nonexistent_type] should resolve to zero detectors, got zero=false")
	}
	if len(bogus) != 1 || bogus[0] != "nonexistent_type" {
		t.Errorf("bogus entries = %v, want [nonexistent_type]", bogus)
	}
	if iss := cBogus.EnableIssues(known); !anyContains(iss, "nonexistent_type") || !anyContains(iss, "disable ALL detection") {
		t.Errorf("EnableIssues should flag the bogus enable kill-switch, got %v", iss)
	}

	// (2) enable:[aws_access_key_id] (a REAL type) -> NOT a kill-switch, NOT flagged.
	cReal, err := Load(writeCfg(t, "detectors:\n  enable: [aws_access_key_id]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if zero, _ := cReal.EnableResolvesToZero(known); zero {
		t.Errorf("enable:[aws_access_key_id] (real type) wrongly reported as zero-resolving")
	}
	if iss := cReal.EnableIssues(known); len(iss) != 0 {
		t.Errorf("legit enable list of real types wrongly flagged: %v", iss)
	}

	// (3) a mixed list with at least one real type is a legit filter, NOT a kill-switch.
	cMixed, _ := Load(writeCfg(t, "detectors:\n  enable: [aws_access_key_id, bogus_extra]\n"))
	if zero, _ := cMixed.EnableResolvesToZero(known); zero {
		t.Errorf("mixed enable list with a real type wrongly reported as zero-resolving")
	}
	if iss := cMixed.EnableIssues(known); len(iss) != 0 {
		t.Errorf("mixed enable list with a real type should not be flagged as kill-switch: %v", iss)
	}

	// (4) no enable filter -> never a kill-switch (all types run).
	cNone, _ := Load(writeCfg(t, "version: 1\n"))
	if zero, _ := cNone.EnableResolvesToZero(known); zero {
		t.Errorf("empty enable list wrongly reported as zero-resolving")
	}
	if iss := cNone.EnableIssues(known); len(iss) != 0 {
		t.Errorf("empty enable list wrongly flagged: %v", iss)
	}

	// EnableSet exposes the raw enable list for the CLI/LSP to resolve against the taxonomy.
	if got := cBogus.EnableSet(); len(got) != 1 || got[0] != "nonexistent_type" {
		t.Errorf("EnableSet() = %v, want [nonexistent_type]", got)
	}
	if got := cNone.EnableSet(); len(got) != 0 {
		t.Errorf("EnableSet() on no-enable config = %v, want empty", got)
	}
}

func TestPathMatchGlob(t *testing.T) {
	cases := []struct {
		name, pattern, path string
		want                bool
	}{
		{"txt glob nested", "*.txt", "a/b/c.txt", true},
		{"txt glob root", "*.txt", "c.txt", true},
		{"txt glob no-match ext", "*.txt", "a/b/c.go", false},
		{"txt glob suffix only", "*.txt", "notes.txtx", false},
		{"doublestar vendor mid", "**/vendor/**", "x/vendor/lib.js", true},
		{"doublestar vendor root", "**/vendor/**", "vendor/lib.js", true},
		{"doublestar vendor deep", "**/vendor/**", "a/b/vendor/c/d.js", true},
		{"doublestar vendor miss", "**/vendor/**", "a/vend/lib.js", false},
		{"substring legacy", "vendor/", "x/vendor/lib.js", true},
		{"substring legacy root", "node_modules", "node_modules/x.js", true},
		{"empty is no-op", "", "anything/at/all", false},
		{"anchored dir glob", "src/*.py", "src/a.py", true},
		{"anchored dir glob suffix", "src/*.py", "proj/src/a.py", true},
		{"anchored dir glob too deep", "src/*.py", "src/sub/a.py", false},
		{"question mark", "id_?sa", "ssh/id_rsa", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PathMatch(tc.pattern, tc.path); got != tc.want {
				t.Errorf("PathMatch(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
			}
		})
	}
}

func TestExcludeGlobViaAllowlistPaths(t *testing.T) {
	// allowlist.paths shares PathMatch with exclude; verify both glob forms suppress a finding.
	c, err := Load(writeCfg(t, "allowlist:\n  paths: ['*.txt', '**/vendor/**']\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Allowed("SECRET", "deep/dir/notes.txt") {
		t.Error("*.txt glob did not suppress finding in allowlist.paths")
	}
	if !c.Allowed("SECRET", "app/vendor/pkg/lib.js") {
		t.Error("**/vendor/** glob did not suppress finding in allowlist.paths")
	}
	if c.Allowed("SECRET", "src/main.go") {
		t.Error("non-matching path wrongly suppressed")
	}
}

func anyContains(xs []string, sub string) bool {
	for _, x := range xs {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}

func TestDiscoverNoConfig(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	os.Chdir(dir)
	c := Discover() // no file -> empty config, all types enabled, nothing allowlisted
	if c == nil || !c.TypeEnabled("aws_access_key_id") || c.Allowed("x", "y") {
		t.Error("empty Discover() behaved unexpectedly")
	}
}

func TestTuningSectionsParseAndValidate(t *testing.T) {
	c, err := Load(writeCfg(t, `
detection:
  generic_entropy_min: 4.0
  placeholder_max_entropy: 4.5
  max_matches_per_file: 1000
performance:
  verify_concurrency: 16
  verify_timeout: 12s
  ml_threshold: 0.4
limits:
  org_max_pages: 50
  clone_timeout: 3m
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Detection.GenericEntropyMin != 4.0 || c.Detection.MaxMatchesPerFile != 1000 {
		t.Errorf("detection not parsed: %+v", c.Detection)
	}
	if c.Performance.VerifyConcurrency != 16 || c.Performance.VerifyTimeout != "12s" || c.Performance.MLThreshold != 0.4 {
		t.Errorf("performance not parsed: %+v", c.Performance)
	}
	if c.Limits.OrgMaxPages != 50 || c.Limits.CloneTimeout != "3m" {
		t.Errorf("limits not parsed: %+v", c.Limits)
	}
	if len(c.Issues()) != 0 {
		t.Errorf("healthy tuning config flagged issues: %v", c.Issues())
	}
}

func TestBadDurationAndUnknownTuningKeyFlagged(t *testing.T) {
	c, _ := Load(writeCfg(t, "limits:\n  clone_timeout: 3hours\n"))
	if got := c.Issues(); len(got) == 0 {
		t.Error("malformed clone_timeout should be flagged by Issues")
	}
	c2, _ := Load(writeCfg(t, "detection:\n  generic_entropy_minn: 4.0\n"))
	flagged := false
	for _, v := range c2.Validate() {
		if containsSub(v, "generic_entropy_minn") {
			flagged = true
		}
	}
	if !flagged {
		t.Errorf("typo'd detection key should be flagged by Validate, got %v", c2.Validate())
	}
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// --- regex-bomb guard (saferegex) + file-size cap ---

// TestRegexBombAllowlistRefusedFast asserts a giant-repetition allowlist regex is dropped from the
// active allow set (not added, not OOMing) and Issues reports it.
func TestRegexBombAllowlistRefusedFast(t *testing.T) {
	cfg := "allowlist:\n  regexes:\n    - 'a{1000000000}'\n"
	c, err := Load(writeCfg(t, cfg))
	if err != nil {
		t.Fatalf("Load should not fail on a bomb allowlist regex (it's dropped): %v", err)
	}
	// The bomb regex must NOT be in the active allow set (saferegex rejected it).
	if len(c.allowRe) != 0 {
		t.Errorf("bomb allowlist regex should be dropped, got %d active", len(c.allowRe))
	}
	// Issues() must report it as a bad regex.
	issues := c.Issues()
	found := false
	for _, s := range issues {
		if strings.Contains(s, "a{1000000000}") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Issues to flag the bomb allowlist regex, got %v", issues)
	}
}

// TestRegexBombCustomRuleReportedNotOOM asserts a bomb custom-rule regex is surfaced as a bad regex
// by Issues rather than blowing up the validation pass.
func TestRegexBombCustomRuleReportedNotOOM(t *testing.T) {
	cfg := "detectors:\n  custom:\n    - id: bomb\n      regex: 'x{900000000}'\n"
	c, err := Load(writeCfg(t, cfg))
	if err != nil {
		// saferegex rejects it, so matchEverythingRe is false; Load should accept it and let Issues flag it.
		t.Fatalf("Load should not fail on a bomb custom regex: %v", err)
	}
	issues := c.Issues()
	found := false
	for _, s := range issues {
		if strings.Contains(s, "bomb") && strings.Contains(s, "bad regex") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Issues to flag bomb custom rule as bad regex, got %v", issues)
	}
}

// TestConfigFileSizeCapRefused proves a config file past MaxConfigSize is refused (not slurped whole).
func TestConfigFileSizeCapRefused(t *testing.T) {
	// A valid-YAML comment line padded just past the cap (no real GB allocated).
	big := "# " + strings.Repeat("a", MaxConfigSize+16)
	if _, err := Load(writeCfg(t, big)); err == nil {
		t.Fatal("expected Load to refuse an oversized config, got nil error")
	}
}

// TestNormalConfigStillLoads asserts a realistic config with a normal allowlist regex loads and the
// allowlist is honoured.
func TestNormalConfigStillLoads(t *testing.T) {
	cfg := "allowlist:\n  regexes:\n    - 'EXAMPLE[0-9]{4}'\n  values:\n    - 'AKIAIOSFODNN7EXAMPLE'\n"
	c, err := Load(writeCfg(t, cfg))
	if err != nil {
		t.Fatalf("normal config should load: %v", err)
	}
	if len(c.allowRe) != 1 {
		t.Fatalf("normal allowlist regex should be active, got %d", len(c.allowRe))
	}
	if !c.Allowed("EXAMPLE1234", "x.txt") {
		t.Error("allowlist regex EXAMPLE[0-9]{4} should suppress EXAMPLE1234")
	}
	if len(c.Issues()) != 0 {
		t.Errorf("normal config should have no issues, got %v", c.Issues())
	}
}
