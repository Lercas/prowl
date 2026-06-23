// Package config loads .prowl.yaml settings (precedence: CLI flags > file > defaults).
package config

import (
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/saferegex"
	"gopkg.in/yaml.v3"
)

// MaxConfigSize caps a .prowl.yaml so an attacker-supplied (auto-discovered) config can't OOM the
// loader. Real configs are a few KB; 8 MiB leaves ample headroom.
const MaxConfigSize = 8 << 20 // 8 MiB

// readCapped reads path but refuses a file larger than MaxConfigSize. Stat rejects up front; a
// bounded io.LimitReader guards against a file that grows between Stat and read.
func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > MaxConfigSize {
		return nil, fmt.Errorf("config %s too large (%d bytes > %d limit)", path, fi.Size(), MaxConfigSize)
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxConfigSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > MaxConfigSize {
		return nil, fmt.Errorf("config %s too large (> %d limit)", path, MaxConfigSize)
	}
	return raw, nil
}

// knownCategories mirrors scan.categorySeverity (custom-rule Category -> severity); an unknown
// category there silently falls through to "medium", so Validate flags anything not in this set.
// Keep in sync with internal/scan.categorySeverity.
var knownCategories = map[string]bool{
	"pki": true, "payment": true, "db": true,
	"cloud": true, "vcs": true, "ai": true, "comms": true, "messaging": true,
	"ci": true, "saas": true, "observability": true, "auth": true,
	"generic": true,
}

// matchAllProbes are single-line secret values spanning char classes; a pattern matching "" or all
// of these is effectively match-all. Deliberately no whitespace/newline (real secrets are
// single-line), else `.+`/`\S+`/`\w+` would slip through.
var matchAllProbes = []string{"0", "a", "Z9", "p@ss-_.", "λx", "AKIAIOSFODNN7EXAMPLE"}

// pathProbes are diverse finding paths; an allowlist.paths substring contained in every one is
// effectively match-all. A normal entry like "test/" or "vendor/" is not.
var pathProbes = []string{
	"main.go", "src/app/server.go", "a/b/c.txt", "lib/util.js",
	"deploy/prod.yaml", "README", "Makefile", "x.py",
}

// valueProbes are diverse provider-shaped secret values; an allowlist.stopwords entry (case-
// insensitive contains-match) that is a substring of every one is effectively match-all.
var valueProbes = []string{
	"AKIA4ZX9QJ7K2MNPL3RS", "xKq3pNvR8sT2wYbZ7mGfH4jLcD6aE1uViO9rW5nQ",
	"sk_live_4eC39HqLyjWDarjtT1zdp7dc", "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
	"glpat-aB3dE7fGhIjK9LmNoPqR", "0123456789",
}

// matchAllPathEntry reports whether an allowlist.paths entry is effectively match-all (it would
// suppress 100% of findings). It flags an entry whose PathMatch fires against every pathProbe; globs
// are exempt (intentionally targeted) and probe only plain substrings.
func matchAllPathEntry(entry string) bool {
	if entry == "" {
		return false // empty entry is already a no-op in PathMatch
	}
	if hasGlobMeta(entry) {
		return false // globs are evaluated as patterns, not universal substrings
	}
	// A single char (".", "/", a common letter) is a substring of essentially every path; the probe
	// set can't represent every conceivable path, so treat any one-rune entry as match-all directly.
	if utf8.RuneCountInString(entry) == 1 {
		return true
	}
	for _, p := range pathProbes {
		if !PathMatch(entry, p) {
			return false
		}
	}
	return true
}

// matchAllStopWord reports whether an allowlist.stopwords entry is effectively match-all. It flags a
// word contained (case-insensitively, matching Allowed) in every valueProbe; a normal "EXAMPLE" is not.
func matchAllStopWord(word string) bool {
	if word == "" {
		return false // an empty stopword is already skipped in Allowed
	}
	// A single char is contained in essentially every secret value (a contains-match) -> match-all.
	if utf8.RuneCountInString(word) == 1 {
		return true
	}
	low := strings.ToLower(word)
	for _, v := range valueProbes {
		if !strings.Contains(strings.ToLower(v), low) {
			return false
		}
	}
	return true
}

// validFailOnLevels mirrors the severity set the CI exit-code gate accepts (model.SeverityOrder). A
// value outside this set fails open, so Issues/Validate flag the typo. A local mirror avoids a
// dependency on internal/model.
var validFailOnLevels = []string{"info", "low", "medium", "high", "critical"}

func isValidFailOn(level string) bool {
	for _, v := range validFailOnLevels {
		if level == v {
			return true
		}
	}
	return false
}

// matchEverythingRe reports whether a regex is effectively match-all (would fire on every line). It
// probes behaviourally rather than denylisting source strings (which an equivalent like `[\s\S]*`
// trivially bypasses): see matchesEverything. An uncompilable regex returns false (reported as a
// compile error elsewhere).
func matchEverythingRe(re string) bool {
	// saferegex caps an attacker-supplied custom/allowlist regex (in-repo .prowl.yaml is auto-loaded)
	// so this probe can't OOM while compiling.
	rx, err := saferegex.Compile(re)
	if err != nil {
		return false // a bad/oversized regex is reported as a compile error elsewhere, not as match-all
	}
	return matchesEverything(rx)
}

// matchesEverything flags an already-compiled regex as match-all if it matches "" (accepts an empty
// span -> fires on every line) or matches every probe in matchAllProbes (a min-one-char pattern like
// `.+` that still fires on every non-empty line).
func matchesEverything(rx *regexp.Regexp) bool {
	if rx.MatchString("") {
		return true
	}
	for _, p := range matchAllProbes {
		if !rx.MatchString(p) {
			return false
		}
	}
	return true
}

// Issues returns human-readable problems with the config (invalid or match-everything regexes);
// empty if healthy. It is the cheap subset of Validate that callers run on every Load.
func (c *Config) Issues() []string {
	var out []string
	for _, cr := range c.Detectors.Custom {
		// saferegex so a regex-bomb custom rule is reported as bad rather than OOMing validation.
		if _, err := saferegex.Compile(cr.Regex); err != nil {
			out = append(out, fmt.Sprintf("custom rule %q: bad regex: %v", cr.ID, err))
			continue
		}
		if matchEverythingRe(cr.Regex) {
			out = append(out, fmt.Sprintf("custom rule %q: regex %q matches everything (empty or .*-equivalent); would flag every line as a critical finding", cr.ID, cr.Regex))
		}
	}
	for _, rx := range c.Allowlist.Regexes {
		// saferegex so a regex-bomb allowlist regex is reported as bad rather than OOMing validation.
		if _, err := saferegex.Compile(rx); err != nil {
			out = append(out, fmt.Sprintf("allowlist regex %q: %v", rx, err))
			continue
		}
		// A match-all allowlist regex suppresses every finding (a no-op scanner). Flag it; Load also
		// drops it from the active allow set.
		if matchEverythingRe(rx) {
			out = append(out, fmt.Sprintf("allowlist regex %q matches everything (.*-equivalent); it would suppress EVERY finding -- ignoring it", rx))
		}
	}
	// A near-universal allowlist.paths substring suppresses every finding; flag it (Load drops it too).
	for _, p := range c.Allowlist.Paths {
		if matchAllPathEntry(p) {
			out = append(out, fmt.Sprintf("allowlist path %q matches every path (near-universal substring); it would suppress EVERY finding -- ignoring it", p))
		}
	}
	// A near-universal allowlist.stopword suppresses every finding; flag it (Load drops it too).
	for _, w := range c.Allowlist.StopWords {
		if matchAllStopWord(w) {
			out = append(out, fmt.Sprintf("allowlist stopword %q matches every value (near-universal substring); it would suppress EVERY finding -- ignoring it", w))
		}
	}
	// A typo'd output.fail_on fails open (CI treats it as no gate), so flag a value outside the valid set.
	if c.Output.FailOn != "" && !isValidFailOn(c.Output.FailOn) {
		out = append(out, fmt.Sprintf("output.fail_on %q is not a valid severity (valid: %s); the CI gate would silently treat it as no gate (fail-open)", c.Output.FailOn, strings.Join(validFailOnLevels, ", ")))
	}
	// Duration knobs: a malformed value is silently ignored (the default is kept), so surface it.
	for _, d := range []struct{ key, val string }{
		{"performance.verify_timeout", c.Performance.VerifyTimeout},
		{"limits.clone_timeout", c.Limits.CloneTimeout},
	} {
		if d.val != "" {
			if _, err := time.ParseDuration(d.val); err != nil {
				out = append(out, fmt.Sprintf("%s %q: %v (using the default)", d.key, d.val, err))
			}
		}
	}
	return out
}

// knownTopKeys are the recognized top-level config keys. A plain yaml.Unmarshal silently drops
// unknown keys (so `allowlsit:` typos vanish without error); Validate uses this set to flag them.
var knownTopKeys = map[string]bool{
	"version": true, "exclude": true, "detectors": true, "allowlist": true,
	"output": true, "performance": true, "detection": true, "limits": true,
}

// knownDetectorKeys / knownAllowlistKeys / ... back the nested typo checks in Validate.
var knownDetectorKeys = map[string]bool{"enable": true, "disable": true, "custom": true}
var knownAllowlistKeys = map[string]bool{"paths": true, "values": true, "regexes": true, "stopwords": true}
var knownDetectionKeys = map[string]bool{"generic_entropy_min": true, "placeholder_max_entropy": true, "max_matches_per_file": true}
var knownPerformanceKeys = map[string]bool{"max_size": true, "workers": true, "verify_concurrency": true, "verify_timeout": true, "ml_threshold": true}
var knownLimitsKeys = map[string]bool{"org_max_pages": true, "clone_timeout": true}

// unknownKeys re-parses raw YAML as a node tree and returns any mapping keys (at the documented
// nesting levels) that aren't in the allowed sets, so callers can catch typos like `allowlsit:` or
// `detctors:` that Unmarshal would otherwise ignore.
func unknownKeys(raw []byte) []string {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil // malformed YAML surfaces as a Load error instead
	}
	root := &doc
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return nil
	}
	var out []string
	for i := 0; i+1 < len(root.Content); i += 2 {
		k := root.Content[i]
		v := root.Content[i+1]
		key := k.Value
		if !knownTopKeys[key] {
			out = append(out, fmt.Sprintf("unknown top-level key %q (did you mean one of: allowlist, detection, detectors, exclude, limits, output, performance, version?)", key))
			continue
		}
		switch key {
		case "detectors":
			out = append(out, unknownChildKeys(v, "detectors", knownDetectorKeys)...)
		case "allowlist":
			out = append(out, unknownChildKeys(v, "allowlist", knownAllowlistKeys)...)
		case "detection":
			out = append(out, unknownChildKeys(v, "detection", knownDetectionKeys)...)
		case "performance":
			out = append(out, unknownChildKeys(v, "performance", knownPerformanceKeys)...)
		case "limits":
			out = append(out, unknownChildKeys(v, "limits", knownLimitsKeys)...)
		}
	}
	return out
}

func unknownChildKeys(n *yaml.Node, parent string, known map[string]bool) []string {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	var out []string
	for i := 0; i+1 < len(n.Content); i += 2 {
		key := n.Content[i].Value
		if !known[key] {
			out = append(out, fmt.Sprintf("unknown key %q under %q", key, parent))
		}
	}
	return out
}

// Validate is the strict validator behind `prowl config validate`. It extends Issues with unknown
// top-level/nested key detection (typos Unmarshal would swallow) and unknown custom-rule categories
// (silently downgraded to "medium"), one problem per line. It uses the file bytes captured at Load;
// for a Config built another way, use ValidateBytes.
func (c *Config) Validate() []string {
	return c.ValidateBytes(c.raw)
}

// ValidateBytes is Validate against caller-supplied raw YAML (e.g. when validating a file without
// fully loading it). Pass nil to skip the unknown-key pass.
func (c *Config) ValidateBytes(raw []byte) []string {
	var out []string
	out = append(out, unknownKeys(raw)...)
	out = append(out, c.Issues()...)
	for _, cr := range c.Detectors.Custom {
		if cr.ID == "" {
			out = append(out, "custom rule with empty id")
		}
		if cr.Category != "" && !knownCategories[cr.Category] {
			out = append(out, fmt.Sprintf("custom rule %q: unknown category %q (would silently become severity \"medium\"); known: %s", cr.ID, cr.Category, knownCategoryList()))
		}
	}
	return out
}

func knownCategoryList() string {
	cats := make([]string, 0, len(knownCategories))
	for k := range knownCategories {
		cats = append(cats, k)
	}
	sort.Strings(cats)
	return strings.Join(cats, ", ")
}

// CustomRule is a user-defined detector; Category drives severity.
type CustomRule struct {
	ID       string `yaml:"id"`
	Regex    string `yaml:"regex"`
	Category string `yaml:"category"`
}

type Config struct {
	Version   int      `yaml:"version"`
	Exclude   []string `yaml:"exclude"`
	Detectors struct {
		Enable  []string     `yaml:"enable"` // if set, allow ONLY these type ids
		Disable []string     `yaml:"disable"`
		Custom  []CustomRule `yaml:"custom"`
	} `yaml:"detectors"`
	Allowlist struct {
		Paths     []string `yaml:"paths"`     // substring match on finding path
		Values    []string `yaml:"values"`    // exact values to ignore
		Regexes   []string `yaml:"regexes"`   // ignore values matching any
		StopWords []string `yaml:"stopwords"` // ignore values containing any word
	} `yaml:"allowlist"`
	Output struct {
		Format string `yaml:"format"`
		FailOn string `yaml:"fail_on"`
		Redact *bool  `yaml:"redact"`
	} `yaml:"output"`
	// Detection tuning thresholds; 0 means "use the built-in default" (see internal/detect/tuning.go).
	Detection struct {
		GenericEntropyMin     float64 `yaml:"generic_entropy_min"`     // min entropy for a generic high-entropy hit (default 3.5)
		PlaceholderMaxEntropy float64 `yaml:"placeholder_max_entropy"` // below this, a weak-word value is a placeholder (default 4.2)
		MaxMatchesPerFile     int     `yaml:"max_matches_per_file"`    // per-Scan DoS cap on raw matches (default 50000)
	} `yaml:"detection"`
	Performance struct {
		MaxSize           int64   `yaml:"max_size"`
		Workers           int     `yaml:"workers"`
		VerifyConcurrency int     `yaml:"verify_concurrency"` // simultaneous live-verification calls (default 8)
		VerifyTimeout     string  `yaml:"verify_timeout"`     // per-verifier HTTP timeout, e.g. "8s" (default 8s)
		MLThreshold       float64 `yaml:"ml_threshold"`       // ML keep-threshold; --ml-threshold overrides (default 0.2)
	} `yaml:"performance"`
	// Operational limits; 0/"" means "use the built-in default".
	Limits struct {
		OrgMaxPages  int    `yaml:"org_max_pages"` // max API pages enumerating an org/group (default 200)
		CloneTimeout string `yaml:"clone_timeout"` // git clone timeout for repo/org scans, e.g. "5m" (default 5m)
	} `yaml:"limits"`

	allowRe        []*regexp.Regexp
	allowVal       map[string]bool
	allowPaths     []string // active allowlist.paths with match-all entries (".", "/", ...) dropped
	allowStopWords []string // active allowlist.stopwords with match-all entries dropped
	loadedAt       string
	raw            []byte // original file bytes, kept for Validate's key-typo (yaml.Node) pass
}

var defaultNames = []string{".prowl.yaml", ".prowl.yml", "prowl.yaml"}

// Discover looks for a config file in the current directory; returns nil if none.
func Discover() *Config {
	for _, n := range defaultNames {
		if _, err := os.Stat(n); err == nil {
			if c, err := Load(n); err == nil {
				return c
			}
		}
	}
	return &Config{}
}

func Load(path string) (*Config, error) {
	raw, err := readCapped(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := yaml.Unmarshal(raw, c); err != nil {
		return nil, err
	}
	// Reject a match-everything custom detector up front — the one config error fatal enough to refuse
	// to load (other problems are reported non-fatally via Issues/Validate).
	for _, cr := range c.Detectors.Custom {
		if matchEverythingRe(cr.Regex) {
			return nil, fmt.Errorf("custom rule %q: regex %q matches everything (empty or .*-equivalent); refusing to load (it would flag every line as a critical finding)", cr.ID, cr.Regex)
		}
	}
	c.loadedAt = path
	c.raw = raw
	c.allowVal = map[string]bool{}
	for _, v := range c.Allowlist.Values {
		c.allowVal[v] = true
	}
	for _, r := range c.Allowlist.Regexes {
		// saferegex so a regex-bomb allowlist regex can't OOM during Load; one that fails is skipped
		// (and Issues reports it).
		re, err := saferegex.Compile(r)
		if err != nil {
			continue
		}
		// A match-all allowlist regex would suppress every finding; don't add it to the active set (it
		// stays in c.Allowlist.Regexes so Issues/Validate report it).
		if matchesEverything(re) {
			continue
		}
		c.allowRe = append(c.allowRe, re)
	}
	// Build the active path/stopword sets, dropping match-all entries (reported by Issues/Validate but
	// not honoured), mirroring the match-all regex handling.
	for _, p := range c.Allowlist.Paths {
		if !matchAllPathEntry(p) {
			c.allowPaths = append(c.allowPaths, p)
		}
	}
	for _, w := range c.Allowlist.StopWords {
		if !matchAllStopWord(w) {
			c.allowStopWords = append(c.allowStopWords, w)
		}
	}
	return c, nil
}

// LoadedFrom reports the file the config came from (empty if defaults).
func (c *Config) LoadedFrom() string { return c.loadedAt }

// Allowed reports whether a finding (value at path) is allowlisted and should be suppressed.
func (c *Config) Allowed(value, path string) bool {
	if c == nil {
		return false
	}
	if c.allowVal[value] {
		return true
	}
	// allowPaths/allowStopWords are the active sets with match-all entries already dropped at
	// Load/MergeAllowlist, so an in-repo .prowl.yaml can't silently disable scanning.
	for _, p := range c.allowPaths {
		if PathMatch(p, path) {
			return true
		}
	}
	for _, re := range c.allowRe {
		if re.MatchString(value) {
			return true
		}
	}
	if len(c.allowStopWords) > 0 {
		low := strings.ToLower(value)
		for _, w := range c.allowStopWords {
			if w != "" && strings.Contains(low, strings.ToLower(w)) {
				return true
			}
		}
	}
	return false
}

// hasGlobMeta reports whether a pattern uses glob metacharacters (so we should glob-match instead
// of substring-match). `**` (doublestar) counts even though filepath.Match doesn't understand it.
func hasGlobMeta(p string) bool {
	return strings.ContainsAny(p, "*?[")
}

// PathMatch reports whether a path matches an exclude or allowlist.paths pattern (both share these
// semantics):
//  1. empty pattern -> never matches (a blank entry is a no-op, not match-all).
//  2. glob metacharacters (`*`, `?`, `[`) -> matched as a glob, never a substring. `**` matches
//     across `/` doublestar-style; the pattern is tried against the full path and each trailing
//     suffix (so `*.txt` matches `a/b/c.txt`). An invalid glob falls back to substring.
//  3. no metacharacters -> plain substring match (`vendor/` matches `x/vendor/lib.js`).
//
// Matching uses forward-slash paths; callers should pass slash-separated paths.
func PathMatch(pattern, p string) bool {
	if pattern == "" {
		return false
	}
	pat := filepathToSlash(pattern)
	pth := filepathToSlash(p)
	if !hasGlobMeta(pat) {
		return strings.Contains(pth, pat)
	}
	// Try the whole path and each trailing segment boundary so a relative pattern matches anywhere.
	if globMatch(pat, pth) {
		return true
	}
	if !strings.HasPrefix(pat, "/") && !strings.HasPrefix(pat, "**") {
		for i := 0; i < len(pth); i++ {
			if pth[i] == '/' && globMatch(pat, pth[i+1:]) {
				return true
			}
		}
	}
	return false
}

// globMatch matches a single glob against a path, supporting `**` (matches across `/`). It expands
// `**` into a small regex; everything else defers to path.Match. On an unparseable glob it falls
// back to a substring check so the pattern is never silently a no-op.
func globMatch(pattern, p string) bool {
	if strings.Contains(pattern, "**") {
		return doublestarMatch(pattern, p)
	}
	ok, err := path.Match(pattern, p)
	if err != nil {
		return strings.Contains(p, strings.TrimRight(strings.TrimLeft(pattern, "*?["), "*?["))
	}
	return ok
}

// doublestarMatch compiles a `**`-bearing glob to a regexp. `**` matches any run of characters
// including `/`; `*` matches any run except `/`; `?` matches one non-`/` char. Other regex-special
// characters are escaped. `**/` is also allowed to match zero leading segments so `**/vendor/**`
// matches `vendor/lib.js`.
func doublestarMatch(pattern, p string) bool {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				i++ // consume second '*'
				// "**/" may match nothing (zero segments) or several; make the trailing slash optional.
				if i+1 < len(pattern) && pattern[i+1] == '/' {
					i++
					b.WriteString("(?:.*/)?")
				} else {
					b.WriteString(".*")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '.', '+', '(', ')', '|', '^', '$', '{', '}', '\\', '[', ']':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteString("$")
	// Built from a glob (only `.*`/`[^/]*`/escaped literals, never a user repetition bound), so it
	// can't be a regex-bomb — a plain regexp.Compile is correct here.
	re, err := regexp.Compile(b.String())
	if err != nil {
		return strings.Contains(p, strings.ReplaceAll(strings.ReplaceAll(pattern, "**", ""), "*", ""))
	}
	return re.MatchString(p)
}

// filepathToSlash normalizes OS path separators to '/' (local to avoid a filepath dependency).
func filepathToSlash(s string) string {
	if os.PathSeparator == '/' {
		return s
	}
	return strings.ReplaceAll(s, string(os.PathSeparator), "/")
}

// MergeAllowlist folds an imported allow-set into this config and recompiles the regexes.
func (c *Config) MergeAllowlist(regexes, paths, stopwords []string) {
	c.Allowlist.Paths = append(c.Allowlist.Paths, paths...)
	c.Allowlist.Regexes = append(c.Allowlist.Regexes, regexes...)
	c.Allowlist.StopWords = append(c.Allowlist.StopWords, stopwords...)
	for _, r := range regexes {
		// saferegex so a regex-bomb imported regex can't OOM the merge; a match-all regex is skipped too.
		if re, err := saferegex.Compile(r); err == nil && !matchesEverything(re) {
			c.allowRe = append(c.allowRe, re)
		}
	}
	// Mirror the Load-time guard: fold only non-match-all path/stopword entries into the active sets.
	for _, p := range paths {
		if !matchAllPathEntry(p) {
			c.allowPaths = append(c.allowPaths, p)
		}
	}
	for _, w := range stopwords {
		if !matchAllStopWord(w) {
			c.allowStopWords = append(c.allowStopWords, w)
		}
	}
}

// TypeEnabled reports whether a type id is active under the enable/disable rules.
func (c *Config) TypeEnabled(id string) bool {
	if c == nil {
		return true
	}
	for _, d := range c.Detectors.Disable {
		if d == id {
			return false
		}
	}
	if len(c.Detectors.Enable) > 0 {
		for _, e := range c.Detectors.Enable {
			if e == id {
				return true
			}
		}
		return false
	}
	return true
}

// EnableSet returns the detectors.enable list (the restrict-to-only filter), empty when unset.
// Exposed so the CLI/LSP can resolve it against the taxonomy (see EnableResolvesToZero).
func (c *Config) EnableSet() []string {
	if c == nil {
		return nil
	}
	return c.Detectors.Enable
}

// EnableResolvesToZero reports whether a non-empty detectors.enable list names no known type id —
// a restrict-to-only filter that resolves to nothing silently disables ALL detection. `known` is the
// valid type-id set (taxonomy + custom-rule ids), supplied by the caller since it lives outside
// config. The second return is the bogus entries, so the caller can name them in a warning; an empty
// enable list returns (false, nil).
func (c *Config) EnableResolvesToZero(known []string) (zero bool, bogus []string) {
	if c == nil || len(c.Detectors.Enable) == 0 {
		return false, nil // no enable filter -> all types run, not a kill-switch
	}
	knownSet := make(map[string]bool, len(known))
	for _, k := range known {
		knownSet[k] = true
	}
	anyValid := false
	for _, e := range c.Detectors.Enable {
		if knownSet[e] {
			anyValid = true
		} else {
			bogus = append(bogus, e)
		}
	}
	// Zero detectors run iff no enable entry matched a known type; one real entry makes it a legit
	// restrict-to-only filter (not flagged), even alongside some bogus ids.
	return !anyValid, bogus
}

// EnableIssues is the enable-kill-switch counterpart to Issues(), which can't flag it without the
// valid type-id set. Given `known`, it returns a warning naming the bogus entries when a non-empty
// enable list resolves to zero detectors, else nil. The CLI/LSP append this to Issues() output.
func (c *Config) EnableIssues(known []string) []string {
	zero, bogus := c.EnableResolvesToZero(known)
	if !zero {
		return nil
	}
	return []string{fmt.Sprintf(
		"detectors.enable %v resolves to ZERO known detector types (bogus: %s); enable is a restrict-to-only filter, so it would disable ALL detection (every scan exits clean)",
		c.Detectors.Enable, strings.Join(bogus, ", "))}
}
