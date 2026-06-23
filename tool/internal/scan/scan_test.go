package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func detector(t *testing.T) *detect.Detector {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	return detect.New(tax)
}

func feed(items ...model.Item) <-chan model.Item {
	ch := make(chan model.Item, len(items))
	for _, it := range items {
		ch <- it
	}
	close(ch)
	return ch
}

func TestRunSeverityPragmaAllow(t *testing.T) {
	det := detector(t)
	fs := Run(context.Background(), feed(
		model.Item{Text: `AWS = "AKIANAFGYOEYPXU1DSYP"`, Source: "code", Path: "a.py"},
		model.Item{Text: `K = "AKIAZZ11YY22XX33WW44"  // prowl:allow`, Source: "code", Path: "b.py"},
	), det, nil, nil, 2, nil, nil)

	if len(fs) != 1 {
		t.Fatalf("expected 1 finding (pragma suppresses the other), got %d", len(fs))
	}
	f := fs[0]
	if f.Path != "a.py" || f.Type != "aws_access_key_id" {
		t.Errorf("unexpected finding: %+v", f)
	}
	if f.Severity != "high" { // cloud category -> high
		t.Errorf("aws severity = %q, want high", f.Severity)
	}
	if f.Line != 1 || f.Redacted == "" || f.Redacted == "AKIANAFGYOEYPXU1DSYP" {
		t.Errorf("expected redacted value on line 1, got %q line %d", f.Redacted, f.Line)
	}
}

func TestRunAllowFunc(t *testing.T) {
	det := detector(t)
	allow := func(value, path string) bool { return value == "AKIANAFGYOEYPXU1DSYP" }
	fs := Run(context.Background(), feed(model.Item{Text: `AWS = "AKIANAFGYOEYPXU1DSYP"`, Source: "code", Path: "a.py"}), det, nil, nil, 1, allow, nil)
	if len(fs) != 0 {
		t.Errorf("allow func should have suppressed the finding, got %d", len(fs))
	}
}

func TestRunEmptyInput(t *testing.T) {
	if fs := Run(context.Background(), feed(), detector(t), nil, nil, 4, nil, nil); len(fs) != 0 {
		t.Errorf("empty input produced %d findings", len(fs))
	}
}

func TestRunCancelledShortCircuits(t *testing.T) {
	det := detector(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled
	items := make(chan model.Item, 3)
	for i := 0; i < 3; i++ {
		items <- model.Item{Text: `AWS = "AKIANAFGYOEYPXU1DSYP"`, Source: "code", Path: "a.py"}
	}
	close(items)
	fs := Run(ctx, items, det, nil, nil, 2, nil, nil) // must return promptly, not hang
	if len(fs) != 0 {
		t.Errorf("cancelled scan should yield no findings, got %d", len(fs))
	}
}

func TestExamplePathAndComment(t *testing.T) {
	for _, p := range []string{"src/test/x.py", "a/__tests__/b.js", "config.example.yaml", "fixtures/k.go", "x.lock", "SAMPLE_cfg.json"} {
		if !isExamplePath(p) {
			t.Errorf("%q should be an example/test path", p)
		}
	}
	if isExamplePath("src/config/settings.py") {
		t.Error("normal path wrongly flagged")
	}
	if !newLineIndex("ok\n  // key = AKIA...").isComment(9) {
		t.Error("comment line not detected")
	}
	if newLineIndex(`key = "x"`).isComment(3) {
		t.Error("code line flagged as comment")
	}
}

// TestLockfileKeepsCredentialGeneric guards the fix that narrowed the lockfile drop to true
// hash-noise generics only: a credential-bearing generic (basic_auth_header — a real
// user:token@registry URL, the classic package-lock.json leak) must be REPORTED, while
// generic_high_entropy package-integrity noise and a pure-hash go.sum are still dropped.
func TestLockfileKeepsCredentialGeneric(t *testing.T) {
	det := detector(t)
	run := func(text, path string) []model.Finding {
		return Run(context.Background(), feed(model.Item{Text: text, Source: "code", Path: path}), det, nil, nil, 1, nil, nil)
	}

	// basic_auth_header (URL userinfo form) carries a REAL credential — kept in a lockfile.
	fs := run("\"registry\": \"https://deploy:s3cr3tD3pl0yT0k3nXYZ9q@registry.example.com/r\"\n", "dir/package-lock.json")
	if len(fs) != 1 || fs[0].Type != "basic_auth_header" {
		t.Fatalf("basic_auth_header in package-lock.json should be FOUND, got %+v", fs)
	}

	// generic_high_entropy is pure hash noise in a lockfile — still dropped.
	if fs := run("\"integrity\": \"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789aBcDeFgHi\"\n", "dir/yarn.lock"); len(fs) != 0 {
		t.Errorf("generic_high_entropy hash noise in a lockfile should be dropped, got %+v", fs)
	}

	// go.sum of pure module hashes — still nothing.
	if fs := run("github.com/a/b v1.2.3 h1:vj9j2Cgf8Vt3vZh7M3DM6vL7c8jc7E0YQ8Ksa8yLU=\n", "dir/go.sum"); len(fs) != 0 {
		t.Errorf("go.sum hash noise should yield 0 findings, got %+v", fs)
	}

	// The same credential URL in a NON-lockfile is unaffected (sanity: it's a real basic_auth_header).
	if fs := run("url = \"https://deploy:s3cr3tD3pl0yT0k3nXYZ9q@registry.example.com/r\"\n", "src/config.json"); len(fs) != 1 || fs[0].Type != "basic_auth_header" {
		t.Errorf("basic_auth_header in a normal file should be found, got %+v", fs)
	}
}

// TestChecksumBuiltinSurvivesTemplate guards the fix that a checksum-proven builtin (Stage
// L1-checksum — cryptographic proof) is NEVER superseded by a colliding template, however high the
// template's self-declared severity. A non-checksum generic builtin is still superseded by a
// specific template, so the legit precision case keeps working.
func TestChecksumBuiltinSurvivesTemplate(t *testing.T) {
	det := detector(t)
	const ghTok = "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" // checksum-valid github PAT

	loadRules := func(t *testing.T, body string) *rules.Engine {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		eng, err := rules.Load(dir)
		if err != nil {
			t.Fatalf("load rules: %v", err)
		}
		return eng
	}

	// An over-broad `severity: critical` template at the same value+line must NOT clobber the
	// checksum-proven github builtin: it keeps its type, severity, and L1-checksum proof.
	eng := loadRules(t, `
id: catch-all-critical
info:
  name: overbroad critical
  severity: critical
  tags: generic
matchers:
  - type: regex
    regex:
      - 'ghp_[A-Za-z0-9]+'
`)
	fs := Findings(context.Background(), det, eng, nil, model.Item{
		Text: `token = "` + ghTok + `"`, Source: "code", Path: "app.py",
	}, nil, nil)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}
	if fs[0].Type != "github_pat_classic" || fs[0].Severity != "high" || fs[0].Stage != "L1-checksum" {
		t.Errorf("checksum builtin clobbered by template: got Type=%s Severity=%s Stage=%s, want github_pat_classic/high/L1-checksum",
			fs[0].Type, fs[0].Severity, fs[0].Stage)
	}

	// Legit case: a specific template still supersedes a NON-checksum generic builtin. The same
	// template, matching a high-entropy value that the builtin reports only as a generic (no
	// checksum), wins on its higher severity — proving the fix didn't break template specificity.
	const genVal = "aB3xQ9zP7mK2wL5vN8tR4yC6dF1gH0jK"
	eng2 := loadRules(t, `
id: specific-token
info:
  name: specific token rule
  severity: critical
  tags: generic
matchers:
  - type: regex
    regex:
      - 'aB3x[A-Za-z0-9]+'
`)
	fs2 := Findings(context.Background(), det, eng2, nil, model.Item{
		Text: `api_key = "` + genVal + `"`, Source: "code", Path: "app.py",
	}, nil, nil)
	if len(fs2) != 1 {
		t.Fatalf("expected 1 finding for generic+template, got %d: %+v", len(fs2), fs2)
	}
	if fs2[0].Type != "specific-token" || fs2[0].Stage != "rule" {
		t.Errorf("specific template should supersede a non-checksum generic builtin: got Type=%s Stage=%s",
			fs2[0].Type, fs2[0].Stage)
	}
}

// TestBothProducersBounded is the round-6 invariant test: the COMBINED finding count from BOTH
// producers — the det.Scan cascade AND the rule-template engine — is bounded by detect.MaxScanMatches
// for one file. A dense file that matches a permissive template thousands of times must NOT yield
// ~200k findings; it must be capped, and a results_truncated marker must surface the truncation in the
// machine output. Before the fix the engine (eng.Match) was uncapped and stacked onto the cascade.
func TestBothProducersBounded(t *testing.T) {
	defer detect.ApplyTuning(3.5, 4.2, 50000)
	const capN = 500
	detect.ApplyTuning(3.5, 4.2, capN)

	det := detector(t)
	// A permissive, anchor-less generic template: a regex matching any 40-char alnum token, so it fires
	// once per distinct token on a dense file (the worst-case engine fan-out).
	dir := t.TempDir()
	body := "id: generic-blob\ninfo:\n  name: generic blob\n  severity: high\nmatchers:\n  - type: regex\n    regex:\n      - '[A-Za-z0-9]{40}'\n"
	if err := os.WriteFile(filepath.Join(dir, "g.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := rules.Load(dir)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}

	var b strings.Builder
	for i := 0; b.Len() < 4*1024*1024; i++ {
		// distinct 40-char token per line so the template's per-value dedup can't collapse them
		fmt.Fprintf(&b, "secret_key_%039dZ\n", i)
	}
	fs := Findings(context.Background(), det, eng, nil, model.Item{Text: b.String(), Source: "code", Path: "dense.txt"}, nil, nil)

	// The combined output (real findings + the one truncation marker) must stay at/near the cap, never
	// the ~100k the uncapped engine produced.
	if len(fs) > capN+1 {
		t.Fatalf("combined producers NOT bounded: got %d findings, cap is %d (+1 marker)", len(fs), capN)
	}
	// Truncation must be surfaced in the machine output, not just a stderr Warn.
	sawMarker := false
	for _, f := range fs {
		if f.Type == ResultsTruncatedType {
			sawMarker = true
		}
	}
	if !sawMarker {
		t.Fatalf("dense input was truncated but no %q marker was emitted", ResultsTruncatedType)
	}
}

// TestNormalScanNoTruncationMarker proves no over-correction: an ordinary file with a handful of real
// findings under the cap carries NO truncation marker and reports its real secrets.
func TestNormalScanNoTruncationMarker(t *testing.T) {
	det := detector(t)
	fs := Run(context.Background(), feed(model.Item{
		Text:   "db_password = \"S3cr3tP4ssw0rd!\"\napi_key = \"AKIANAFGYOEYPXU1DSYP\"",
		Source: "code", Path: "a.py",
	}), det, nil, nil, 1, nil, nil)
	if len(fs) == 0 {
		t.Fatal("normal scan lost all findings")
	}
	sawAWS := false
	for _, f := range fs {
		if f.Type == ResultsTruncatedType {
			t.Fatalf("normal scan must NOT carry a truncation marker, got: %+v", f)
		}
		if f.Type == "aws_access_key_id" {
			sawAWS = true
		}
	}
	if !sawAWS {
		t.Errorf("normal scan lost the real AWS key: %+v", fs)
	}
}

// TestPragmaSuppressionAfterMemoization proves the hasPragma per-line memoization didn't change which
// lines are suppressed: a `# prowl:allow` line still drops its finding, and an identical line WITHOUT
// the pragma still reports — even when both are scanned through the same cached lineIndex.
func TestPragmaSuppressionAfterMemoization(t *testing.T) {
	det := detector(t)
	fs := Run(context.Background(), feed(model.Item{
		Text:   "a = \"AKIANAFGYOEYPXU1DSYP\"\nb = \"AKIAZZ11YY22XX33WW44\" # prowl:allow\nc = \"AKIA9988YY22XX33WW44\"",
		Source: "code", Path: "x.py",
	}), det, nil, nil, 1, nil, nil)
	// Lines a and c report; line b is pragma-suppressed. (All three are valid-shaped AWS-ID tokens.)
	for _, f := range fs {
		if f.Line == 2 {
			t.Fatalf("pragma line should be suppressed after memoization, but line 2 reported: %+v", f)
		}
	}
	if len(fs) < 2 {
		t.Fatalf("expected the two non-pragma AWS keys to report, got %d: %+v", len(fs), fs)
	}
}

func TestSeverityDemotion(t *testing.T) {
	det := detector(t)
	const ghTok = "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" // checksum-valid (digits-first base62)
	cases := []struct {
		name, text, path, wantSev string
	}{
		{"generic in test path", `password = "Welcome1!"`, "app/tests/conftest.py", "low"},
		{"structured in comment", `# AWS = "AKIANAFGYOEYPXU1DSYP"`, "src/app.py", "medium"},
		{"structured normal path", `AWS = "AKIANAFGYOEYPXU1DSYP"`, "src/app.py", "high"},
		{"checksum in test path stays", `t = "` + ghTok + `"`, "tests/fixtures.py", "high"},
	}
	for _, tc := range cases {
		fs := Run(context.Background(), feed(model.Item{Text: tc.text, Source: "code", Path: tc.path}), det, nil, nil, 1, nil, nil)
		if len(fs) != 1 {
			t.Errorf("%s: expected 1 finding, got %d", tc.name, len(fs))
			continue
		}
		if fs[0].Severity != tc.wantSev {
			t.Errorf("%s: severity = %q, want %q", tc.name, fs[0].Severity, tc.wantSev)
		}
	}
}
