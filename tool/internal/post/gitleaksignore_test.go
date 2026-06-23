package post

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func writeIgnore(t *testing.T, lines string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".gitleaksignore")
	if err := os.WriteFile(p, []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGitleaksIgnore_ExactFingerprint(t *testing.T) {
	// Exact gitleaks dir-scan fingerprint: file:rule:line. Lines up when the .gitleaks.toml is loaded
	// so a Prowl finding's Type equals the gitleaks ruleID.
	g := LoadGitleaksIgnore(writeIgnore(t, "config/app.yaml:aws-access-token:42\n"))
	in := []model.Finding{
		{Path: "config/app.yaml", Type: "aws-access-token", Line: 42},
		{Path: "config/app.yaml", Type: "aws-access-token", Line: 7}, // different line, kept
	}
	out := g.Suppress(in)
	if len(out) != 1 || out[0].Line != 7 {
		t.Fatalf("exact fingerprint not suppressed: got %+v", out)
	}
}

func TestGitleaksIgnore_RelaxedFileLine(t *testing.T) {
	// Scanning with Prowl's own detectors, the type differs from the gitleaks ruleID — the finding is
	// still suppressed on (file, line), which is what accepting a finding at that location means.
	g := LoadGitleaksIgnore(writeIgnore(t, "src/secrets.go:generic-api-key:10\n"))
	in := []model.Finding{{Path: "/abs/repo/src/secrets.go", Type: "aws_access_key_id", Line: 10}}
	if out := g.Suppress(in); len(out) != 0 {
		t.Fatalf("relaxed (file,line) match should suppress regardless of type: got %+v", out)
	}
}

func TestGitleaksIgnore_GitCommitPrefix(t *testing.T) {
	// A git-scan fingerprint prefixes the file with a commit sha; the file+line still matches.
	g := LoadGitleaksIgnore(writeIgnore(t, "a1b2c3d4e5f6071829304152637485960aabbcc:lib/key.rb:gitleaks-generic:3\n"))
	in := []model.Finding{{Path: "lib/key.rb", Type: "whatever", Line: 3}}
	if out := g.Suppress(in); len(out) != 0 {
		t.Fatalf("commit-prefixed fingerprint should match on file+line: got %+v", out)
	}
}

func TestGitleaksIgnore_NoFalseSuppression(t *testing.T) {
	g := LoadGitleaksIgnore(writeIgnore(t, "src/a.go:rule:5\n"))
	in := []model.Finding{
		{Path: "src/b.go", Type: "rule", Line: 5},   // different file
		{Path: "src/a.go", Type: "rule", Line: 6},   // different line
		{Path: "other/a.go", Type: "rule", Line: 5}, // same basename, different dir -> not a tail match
	}
	if out := g.Suppress(in); len(out) != 3 {
		t.Fatalf("unrelated findings must be kept: got %d of 3", len(out))
	}
}

func TestGitleaksIgnore_CommentsAndBlanks(t *testing.T) {
	g := LoadGitleaksIgnore(writeIgnore(t, "# a comment\n\n  \nsrc/a.go:rule:5\n"))
	if len(g.exact) != 1 {
		t.Fatalf("comments/blanks should be skipped, got %d entries", len(g.exact))
	}
}

func TestGitleaksIgnore_MissingFileIsNoop(t *testing.T) {
	g := LoadGitleaksIgnore(filepath.Join(t.TempDir(), "nope"))
	in := []model.Finding{{Path: "a", Type: "b", Line: 1}}
	if out := g.Suppress(in); len(out) != 1 {
		t.Fatal("missing ignore file must suppress nothing")
	}
}
