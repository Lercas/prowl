package lsp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

// captureWarn buffers logx Warn output for the duration of fn and returns it, so tests can assert
// the in-repo kill-switch warning fires (or doesn't) without a real .prowl.yaml on disk.
func captureWarn(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	// Console format (color off) renders attrs as key=value, which the kill-switch assertions match.
	logx.Setup(logx.Options{Level: slog.LevelWarn, Format: "console", Color: false, Out: &buf})
	defer logx.Setup(logx.Options{Level: slog.LevelInfo, Format: "console", Color: false, Out: nil})
	fn()
	return buf.String()
}

// newWorkspaceCfg loads the given YAML from a temp file so LoadedFrom() is set as for an
// auto-discovered in-repo config — the trust signal warnInRepoSuppression keys off.
func newWorkspaceCfg(t *testing.T, yaml string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	p := dir + "/.prowl.yaml"
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.LoadedFrom() == "" {
		t.Fatal("setup: config must report a LoadedFrom (in-repo trust signal)")
	}
	return cfg
}

// newTestEngine builds an engine from the default taxonomy (no .prowl.yaml), the same way build()
// does minus rule templates, so tests can drive scanDiagnostics / the debouncer directly.
func newTestEngine(t *testing.T) *engine {
	t.Helper()
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	return &engine{det: detect.New(tax), maxBytes: defaultMaxScanBytes}
}

// restoreDetectDefaults resets detect's process-wide tuning to its built-in defaults so a test that
// mutated them via detect.ApplyTuning doesn't leak into others.
func restoreDetectDefaults() { detect.ApplyTuning(3.5, 4.2, 50000) }

// genericSecretLine holds a generic high-entropy value (~5.0) flagged at the default
// generic_entropy_min (3.5) and suppressed once the threshold is raised above its entropy.
const genericSecretLine = `token: "ghp_aB3dEf7Gh1Jk5Lm9Np2Qr6St0Uv4Wx8Yz1234"`

// drainPublishes reads every framed message from buf and returns the count of publishDiagnostics
// frames plus the params of the last one.
func drainPublishes(t *testing.T, buf *bytes.Buffer) (count int, last map[string]any) {
	t.Helper()
	r := bufio.NewReader(bytes.NewReader(buf.Bytes()))
	for {
		body, err := readMessage(r)
		if err != nil {
			break
		}
		var m struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if json.Unmarshal(body, &m) != nil {
			continue
		}
		if m.Method == "textDocument/publishDiagnostics" {
			count++
			last = m.Params
		}
	}
	return count, last
}

// hasDiag reports whether a publishDiagnostics params map carries at least one diagnostic.
func hasDiag(params map[string]any) bool {
	if params == nil {
		return false
	}
	d, ok := params["diagnostics"].([]any)
	return ok && len(d) > 0
}

func TestOffsetPos(t *testing.T) {
	text := "ab\ncde\nf"
	cases := []struct {
		off, line, char int
	}{
		{0, 0, 0},  // 'a'
		{2, 0, 2},  // newline at end of line 0
		{3, 1, 0},  // 'c'
		{4, 1, 1},  // 'd'
		{7, 2, 0},  // 'f'
		{99, 2, 1}, // clamp past end
	}
	for _, c := range cases {
		l, ch := offsetPos(text, c.off)
		if l != c.line || ch != c.char {
			t.Errorf("offsetPos(%d) = (%d,%d), want (%d,%d)", c.off, l, ch, c.line, c.char)
		}
	}
}

// TestOffsetPosUTF16Column verifies offsetPos reports columns in UTF-16 code units (not bytes) when
// multibyte UTF-8 precedes the offset, so the highlighted span is correct.
func TestOffsetPosUTF16Column(t *testing.T) {
	const line = `x = "Ключ AKIA1234"`
	off := strings.Index(line, "AKIA")
	if off < 0 {
		t.Fatal("setup: AKIA not found")
	}
	// `x = "` (5 ASCII = 5 units) + `Ключ` (4 runes = 4 units) + ` ` (1) = 10 UTF-16 units.
	const wantUTF16Col = 10
	if off == wantUTF16Col {
		t.Fatalf("setup: byte offset %d equals the UTF-16 column, test can't distinguish them", off)
	}
	l, ch := offsetPos(line, off)
	if l != 0 || ch != wantUTF16Col {
		t.Errorf("offsetPos(secret start) = (%d,%d), want (0,%d) UTF-16 units (byte offset was %d)", l, ch, wantUTF16Col, off)
	}

	// Astral-plane rune (emoji, > 0xFFFF) counts as 2 UTF-16 code units (a surrogate pair).
	const emojiLine = "a😀b" // 'a'(1) + '😀'(2 UTF-16 units) + 'b' -> 'b' is at col 3, byte off 5
	boff := strings.Index(emojiLine, "b")
	bl, bch := offsetPos(emojiLine, boff)
	if bl != 0 || bch != 3 {
		t.Errorf("offsetPos after emoji = (%d,%d), want (0,3) UTF-16 units (byte offset %d)", bl, bch, boff)
	}
}

// TestReadMessageRecoversAfterBadFrame asserts an oversized Content-Length doesn't swallow the
// following valid frame: readMessage rejects the bad frame, then resyncs and returns the next body.
func TestReadMessageRecoversAfterBadFrame(t *testing.T) {
	const good = `{"jsonrpc":"2.0","id":42,"method":"shutdown"}`
	stream := "Content-Length: 99999999\r\n\r\n{\"x\":1}" + // oversized lie + short body
		"Content-Length: " + strconv.Itoa(len(good)) + "\r\n\r\n" + good
	r := bufio.NewReader(strings.NewReader(stream))

	// First read: the malformed frame is rejected as errBadFrame (not a disconnect).
	if _, err := readMessage(r); !errors.Is(err, errBadFrame) {
		t.Fatalf("first readMessage err = %v, want errBadFrame", err)
	}
	// Second read: the stream has resynced — the valid shutdown frame comes through intact.
	body, err := readMessage(r)
	if err != nil {
		t.Fatalf("second readMessage err = %v, want the recovered shutdown frame", err)
	}
	if string(body) != good {
		t.Errorf("recovered body = %q, want %q", body, good)
	}
}

func TestLSPSeverity(t *testing.T) {
	if lspSeverity("pki", 0.99) != 1 { // Error
		t.Error("pki should be Error")
	}
	if lspSeverity("generic", 0.6) != 2 { // Warning
		t.Error("generic should be Warning")
	}
	if lspSeverity("cloud", 0.5) != 2 { // low-conf downgraded to Warning
		t.Error("low-confidence should downgrade to Warning")
	}
}

// TestConfigTuningHonoredInLSP proves the LSP honors a config's detection.generic_entropy_min like
// the CLI: a generic value is flagged at the default threshold and suppressed once it is raised
// above the value's entropy.
func TestConfigTuningHonoredInLSP(t *testing.T) {
	defer restoreDetectDefaults()
	e := newTestEngine(t)
	const uri = "file:///t.py"

	// Default tuning (generic_entropy_min 3.5): the high-entropy value is flagged.
	restoreDetectDefaults()
	base := scanDiagnostics(e, uri, genericSecretLine)
	if len(base) == 0 {
		t.Fatalf("setup: expected the generic high-entropy value to be flagged at the default threshold, got 0 diagnostics")
	}

	// Raise generic_entropy_min to 7.5 (as applyTuning would); the value's entropy (~5.0) is now below
	// the threshold, so it must be suppressed.
	detect.ApplyTuning(7.5, 0, 0)
	tuned := scanDiagnostics(e, uri, genericSecretLine)
	if len(tuned) != 0 {
		t.Errorf("with generic_entropy_min=7.5 the generic value must be suppressed in the LSP (CLI parity), got %d diagnostics: %v", len(tuned), tuned)
	}

	// And restoring the default un-suppresses it — proving the LSP tracks the threshold both ways.
	restoreDetectDefaults()
	again := scanDiagnostics(e, uri, genericSecretLine)
	if len(again) == 0 {
		t.Errorf("restoring generic_entropy_min default must re-flag the value, got 0 diagnostics")
	}
}

// TestDebounceCoalescesBurst asserts a burst of N didChange edits collapses to one scan of the final
// text: far fewer than N publishes, and the final diagnostics still surface the last edit's secret.
func TestDebounceCoalescesBurst(t *testing.T) {
	defer restoreDetectDefaults()
	restoreDetectDefaults()
	e := newTestEngine(t)
	var buf bytes.Buffer
	sw := newSafeWriter(bufio.NewWriter(&buf))
	d := newDebouncer(e, sw, 60*time.Millisecond)
	defer d.stop()

	const uri = "file:///burst.py"
	const burst = 30
	// Intermediate texts are clean; only the final one introduces a secret. A per-keystroke scanner
	// would run `burst` scans; the debouncer should run ~1.
	for i := 0; i < burst; i++ {
		d.schedule(uri, "x = "+strconv.Itoa(i)+"\n")
	}
	d.schedule(uri, genericSecretLine) // final state: a real secret

	// Wait for the window to settle (well past 60ms), then drain.
	time.Sleep(250 * time.Millisecond)
	d.stop() // flush any in-flight scan deterministically before reading the buffer

	count, last := drainPublishes(t, &buf)
	if count == 0 {
		t.Fatal("debouncer produced no publishDiagnostics for the burst")
	}
	if count >= burst {
		t.Errorf("burst of %d edits produced %d publishes — not coalesced (want a small number, ideally 1)", burst, count)
	}
	if !hasDiag(last) {
		t.Errorf("final debounced scan must surface the secret in the LAST edit, got empty diagnostics — debounce dropped a real finding")
	}
}

// TestLargeDocumentBounded asserts an over-cap document returns empty diagnostics promptly (the
// CLI's --max-size parity) while a document under the cap is still scanned and flags its secret.
func TestLargeDocumentBounded(t *testing.T) {
	defer restoreDetectDefaults()
	restoreDetectDefaults()
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	e := &engine{det: detect.New(tax), maxBytes: 1 << 10} // 1 KiB cap for the test

	// Over the cap: the document is skipped (no diagnostics, no full scan) even though it holds a secret.
	big := genericSecretLine + "\n" + strings.Repeat("filler filler filler\n", 300)
	if len(big) <= e.maxBytes {
		t.Fatalf("setup: doc (%d bytes) must exceed the cap (%d)", len(big), e.maxBytes)
	}
	done := make(chan []map[string]any, 1)
	go func() { done <- scanDiagnostics(e, "file:///big.py", big) }()
	select {
	case got := <-done:
		if len(got) != 0 {
			t.Errorf("over-cap document must be skipped (empty diagnostics), got %d", len(got))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("over-cap scan did not return promptly — size cap not bounding the work")
	}

	// Under the cap: the same secret line is still scanned and flagged.
	small := scanDiagnostics(e, "file:///small.py", genericSecretLine)
	if len(small) == 0 {
		t.Errorf("a small document under the cap must still produce diagnostics, got 0")
	}
}

// TestDebounceSingleEditDiagnoses asserts a single edit still produces exactly one publish after the
// window — debouncing must not swallow the only edit.
func TestDebounceSingleEditDiagnoses(t *testing.T) {
	defer restoreDetectDefaults()
	restoreDetectDefaults()
	e := newTestEngine(t)
	var buf bytes.Buffer
	sw := newSafeWriter(bufio.NewWriter(&buf))
	d := newDebouncer(e, sw, 40*time.Millisecond)

	d.schedule("file:///one.py", genericSecretLine)
	time.Sleep(150 * time.Millisecond)
	d.stop()

	count, last := drainPublishes(t, &buf)
	if count != 1 {
		t.Errorf("a single edit should produce exactly one publish, got %d", count)
	}
	if !hasDiag(last) {
		t.Errorf("a single edit introducing a secret must diagnose it, got empty diagnostics")
	}
}

// loadDefaultTax loads a fresh default taxonomy per test (applyConfig mutates tax.Types in place).
func loadDefaultTax(t *testing.T) *taxonomy.Taxonomy {
	t.Helper()
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	return tax
}

// TestRegexBombCustomRuleRejectedFast asserts applyConfig routes an in-workspace custom-rule regex
// through saferegex: a repetition-bomb rule is skipped (not added as a detector) and the call
// returns fast rather than OOMing on a bare regexp.Compile.
func TestRegexBombCustomRuleRejectedFast(t *testing.T) {
	defer restoreDetectDefaults()
	restoreDetectDefaults()

	cases := []struct {
		name, yaml string
	}{
		{
			// A single absurd bound, rejected at saferegex's bound cap.
			name: "single_absurd_bound",
			yaml: "detectors:\n  custom:\n    - id: bomb\n      regex: 'a{1000000000}'\n",
		},
		{
			// A packed total that Go's regexp.Compile accepts (each bound <=1000) but whose aggregate
			// blows up RSS; only saferegex's MaxRepetitionTotal cap catches it.
			name: "packed_total_bound",
			yaml: "detectors:\n  custom:\n    - id: bomb\n      regex: '" + strings.Repeat("a{1000}", 50) + "'\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := newWorkspaceCfg(t, c.yaml)
			if len(cfg.Detectors.Custom) != 1 {
				t.Fatalf("setup: expected 1 custom rule parsed, got %d", len(cfg.Detectors.Custom))
			}
			tax := loadDefaultTax(t)
			before := len(tax.Types)

			done := make(chan struct{})
			go func() {
				applyConfig(tax, cfg)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("applyConfig did not return fast on a regex-bomb custom rule — saferegex guard not engaged (would OOM the editor)")
			}

			// The bomb rule must NOT have been added as a detector.
			for _, ty := range tax.Types {
				if ty.ID == "bomb" {
					t.Fatalf("regex-bomb custom rule was added as a detector (%d -> %d types) — guard did not reject it", before, len(tax.Types))
				}
			}
		})
	}
}

// TestNormalCustomRuleStillCompiles asserts a normal provider-shaped custom regex still compiles,
// is added as a detector, and flags its secret — saferegex rejects only bombs.
func TestNormalCustomRuleStillCompiles(t *testing.T) {
	defer restoreDetectDefaults()
	restoreDetectDefaults()

	// A realistic custom provider token rule, well under every saferegex limit.
	const yaml = "detectors:\n  custom:\n    - id: acme_token\n      category: cloud\n      regex: 'acme_[0-9A-Za-z]{32}'\n"
	cfg := newWorkspaceCfg(t, yaml)
	tax := loadDefaultTax(t)
	applyConfig(tax, cfg)

	var found bool
	for _, ty := range tax.Types {
		if ty.ID == "acme_token" {
			found = true
			if ty.RE == nil {
				t.Fatal("normal custom rule compiled to a nil regexp — saferegex rejected a legitimate rule")
			}
		}
	}
	if !found {
		t.Fatal("normal custom rule was NOT added as a detector — saferegex over-corrected on a real rule")
	}

	// And it detects its secret end-to-end.
	e := &engine{det: detect.New(tax), maxBytes: defaultMaxScanBytes}
	diags := scanDiagnostics(e, "file:///x.txt", `key = "acme_aB3dEf7Gh1Jk5Lm9Np2Qr6St0Uv4Wx8Yz"`)
	if len(diags) == 0 {
		t.Error("a normal custom rule must still flag its secret in the LSP scan, got 0 diagnostics")
	}
}

// TestEnableKillSwitchWarns asserts an in-repo enable:[bogus] (which zeroes the taxonomy) triggers
// the suppression warning AND that the detector is in fact zeroed, so the warning isn't cosmetic.
func TestEnableKillSwitchWarns(t *testing.T) {
	defer restoreDetectDefaults()
	restoreDetectDefaults()

	const yaml = "detectors:\n  enable:\n    - nonexistent_type\n"
	cfg := newWorkspaceCfg(t, yaml)
	tax := loadDefaultTax(t)

	out := captureWarn(t, func() { warnInRepoSuppression(cfg, tax) })
	if !strings.Contains(out, "suppresses detection") {
		t.Errorf("an enable:[bogus] in-repo config must trigger the kill-switch warning, got log:\n%s", out)
	}
	if !strings.Contains(out, "enable_kills_all_detectors=true") {
		t.Errorf("the warning must flag the enable channel specifically, got log:\n%s", out)
	}

	// Confirm the enable list really disables all detectors. First check the secret is detectable
	// under the default taxonomy, so "0 diagnostics" below is the kill-switch, not an undetectable value.
	const secretLine = `gh = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"`
	baseTax := loadDefaultTax(t)
	if d := scanDiagnostics(&engine{det: detect.New(baseTax), maxBytes: defaultMaxScanBytes}, "file:///s.py", secretLine); len(d) == 0 {
		t.Fatal("setup: the GitHub PAT must be detectable under the default taxonomy")
	}
	applyConfig(tax, cfg)
	if len(tax.Types) != 0 {
		t.Fatalf("setup: enable:[bogus] should zero the taxonomy, got %d types", len(tax.Types))
	}
	e := &engine{det: detect.New(tax), maxBytes: defaultMaxScanBytes}
	diags := scanDiagnostics(e, "file:///s.py", secretLine)
	if len(diags) != 0 {
		t.Errorf("with all detectors disabled the LSP must show no diagnostics (proving the silent blindness the warning guards), got %d", len(diags))
	}
}

// TestNormalEnableNoWarning asserts a real enable list naming real detectors does not warn and its
// detectors still produce diagnostics.
func TestNormalEnableNoWarning(t *testing.T) {
	defer restoreDetectDefaults()
	restoreDetectDefaults()

	// A legitimate "run only these" config naming real detectors.
	const yaml = "detectors:\n  enable:\n    - github_pat_classic\n    - stripe_secret_key\n"
	cfg := newWorkspaceCfg(t, yaml)
	tax := loadDefaultTax(t)

	out := captureWarn(t, func() { warnInRepoSuppression(cfg, tax) })
	if strings.Contains(out, "suppresses detection") {
		t.Errorf("a normal enable list naming real detectors must NOT warn (false positive), got log:\n%s", out)
	}

	// And the enabled detectors still work: the kept taxonomy flags a GitHub PAT.
	applyConfig(tax, cfg)
	if len(tax.Types) == 0 {
		t.Fatal("a real enable list must keep the named detectors, got 0 types")
	}
	e := &engine{det: detect.New(tax), maxBytes: defaultMaxScanBytes}
	diags := scanDiagnostics(e, "file:///s.py", `gh = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"`)
	if len(diags) == 0 {
		t.Error("a normal enable list must keep its detectors producing diagnostics, got 0")
	}
}

// TestNormalConfigNoWarning asserts a benign in-repo config (only an exclude) produces no warning.
func TestNormalConfigNoWarning(t *testing.T) {
	defer restoreDetectDefaults()
	restoreDetectDefaults()

	const yaml = "exclude:\n  - vendor/\n  - testdata/\n"
	cfg := newWorkspaceCfg(t, yaml)
	tax := loadDefaultTax(t)

	out := captureWarn(t, func() { warnInRepoSuppression(cfg, tax) })
	if strings.Contains(out, "suppresses detection") {
		t.Errorf("a benign in-repo config (only exclude) must NOT warn, got log:\n%s", out)
	}
}

// TestDefaultsConfigNoWarning asserts a defaults-only config (empty LoadedFrom) is never flagged,
// even with a bogus enable list — warnInRepoSuppression fires only for an in-repo file.
func TestDefaultsConfigNoWarning(t *testing.T) {
	defer restoreDetectDefaults()
	restoreDetectDefaults()

	cfg := &config.Config{} // empty LoadedFrom — exactly what Discover returns with no config file
	cfg.Detectors.Enable = []string{"nonexistent_type"}
	tax := loadDefaultTax(t)

	out := captureWarn(t, func() { warnInRepoSuppression(cfg, tax) })
	if strings.Contains(out, "suppresses detection") {
		t.Errorf("a defaults-only config (empty LoadedFrom) must never warn, even with a bogus enable list, got log:\n%s", out)
	}
}
