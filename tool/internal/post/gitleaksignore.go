package post

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/localfile"
	"github.com/Lercas/prowl/tool/internal/model"
)

// GitleaksIgnore suppresses findings listed in a gitleaks `.gitleaksignore` file, so a repo already
// triaged with gitleaks keeps those findings quiet under Prowl (zero-friction migration).
//
// A gitleaks fingerprint is "{file}:{ruleID}:{startLine}" (or "{commit}:…" for a git scan); the ruleID
// only matches a Prowl Type when the .gitleaks.toml is loaded. To stay useful with Prowl's own
// detectors (whose type names differ), a finding is suppressed on an exact OR a relaxed (file, line) match.
type GitleaksIgnore struct {
	exact   map[string]bool  // full fingerprint lines, matched against "{path}:{type}:{line}"
	relaxed map[int][]string // startLine -> file components (suffix-matched against a finding's path)
}

const (
	maxSuppressionBytes   = 16 * 1024 * 1024
	maxSuppressionEntries = 100000
	maxIgnoreLineBytes    = 1024 * 1024
)

// LoadGitleaksIgnore reads the whole selected policy or returns an error. An unreadable suffix
// must never leave the caller with a partially populated suppressor.
func LoadGitleaksIgnore(path string) (*GitleaksIgnore, error) {
	g := &GitleaksIgnore{exact: map[string]bool{}, relaxed: map[int][]string{}}
	raw, err := localfile.ReadRegular(path, maxSuppressionBytes)
	if err != nil {
		return nil, fmt.Errorf("gitleaksignore read: %w", err)
	}
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("gitleaksignore must be valid UTF-8")
	}

	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), maxIgnoreLineBytes)
	entries, lineNumber := 0, 0
	for sc.Scan() {
		lineNumber++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries++
		if entries > maxSuppressionEntries {
			return nil, fmt.Errorf("gitleaksignore exceeds %d entries", maxSuppressionEntries)
		}
		file, ln, ok := parseGitleaksFP(line)
		if !ok {
			return nil, fmt.Errorf("gitleaksignore invalid fingerprint at line %d", lineNumber)
		}
		if !g.exact[line] {
			g.exact[line] = true
			g.relaxed[ln] = append(g.relaxed[ln], file)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("gitleaksignore parse: %w", err)
	}
	return g, nil
}

// parseGitleaksFP splits a fingerprint into its file component and start line, tolerating the
// optional leading commit hash of a git-scan fingerprint. Returns ok=false if it doesn't end in
// ":{rule}:{line}".
func parseGitleaksFP(line string) (file string, startLine int, ok bool) {
	parts := strings.Split(line, ":")
	if len(parts) < 3 {
		return "", 0, false
	}
	ln, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil || ln < 0 || parts[len(parts)-2] == "" {
		return "", 0, false
	}
	remaining := parts[:len(parts)-2] // drop ":{rule}:{line}"
	// A git fingerprint prefixes the file with a commit sha; strip it so the file component is clean.
	if len(remaining) >= 2 && looksLikeCommit(remaining[0]) {
		remaining = remaining[1:]
	}
	file = filepath.ToSlash(strings.Join(remaining, ":"))
	return file, ln, strings.TrimSpace(file) != ""
}

func looksLikeCommit(s string) bool {
	if len(s) < 7 || len(s) > 40 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// Suppress drops findings whose location was accepted in the .gitleaksignore.
func (g *GitleaksIgnore) Suppress(fs []model.Finding) []model.Finding {
	if g == nil || len(g.exact) == 0 {
		return fs
	}
	out := fs[:0]
	for _, f := range fs {
		if model.IsIncompleteFinding(f) || !g.match(f) {
			out = append(out, f)
		}
	}
	return out
}

func (g *GitleaksIgnore) match(f model.Finding) bool {
	// Exact gitleaks fingerprint: lines up when the matching .gitleaks.toml is loaded (type == ruleID).
	if g.exact[f.Path+":"+f.Type+":"+strconv.Itoa(f.Line)] {
		return true
	}
	// Relaxed: same start line, and the ignore's file is the finding's path (abs/rel tolerant).
	fp := filepath.ToSlash(f.Path)
	for _, file := range g.relaxed[f.Line] {
		if pathTailMatch(fp, file) {
			return true
		}
	}
	return false
}

// pathTailMatch reports whether two paths refer to the same file when one is absolute and the other
// repo-relative: equal, or one is a path-segment suffix of the other.
func pathTailMatch(a, b string) bool {
	if a == b {
		return true
	}
	return strings.HasSuffix(a, "/"+b) || strings.HasSuffix(b, "/"+a)
}
