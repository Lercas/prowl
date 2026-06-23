package detect

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// TestGlobalMatchCap proves maxScanMatches is GLOBAL to one Scan: contextualPassword (one match per
// cue line, previously uncapped) and unmaskBase64 honor the running budget, so a dense input can no
// longer push the result far past the cap. Before the fix a 4 MB block of password-cue lines yielded
// ~120k matches against a 50k cap; now the combined result is bounded by the cap.
func TestGlobalMatchCap(t *testing.T) {
	defer ApplyTuning(3.5, 4.2, 50000) // restore the default cap regardless of outcome
	const cap = 100
	ApplyTuning(3.5, 4.2, cap)

	d := newDetector(t)
	// Each line carries a credential cue + a likely password token -> one contextualPassword match
	// per line and nothing an adjacent-assignment rule would catch first.
	line := "user password is hunter2abc99 here\n"
	var b strings.Builder
	for b.Len() < 1<<20 { // 1 MB is plenty of cue lines to blow past a 100 cap pre-fix
		b.WriteString(line)
	}
	ms := d.Scan(b.String())
	if len(ms) > cap {
		t.Fatalf("global cap not enforced: got %d matches, cap is %d", len(ms), cap)
	}
	if len(ms) == 0 {
		t.Fatalf("expected the cue lines to still produce contextual-password matches, got 0")
	}
}

// TestNormalScanUnchangedUnderCap proves no over-correction: a NORMAL file with a handful of real
// findings is identical with the cap in force vs. removed. The cap only bites pathological dense
// inputs; an ordinary `password = "..."` still yields its generic_password finding.
func TestNormalScanUnchangedUnderCap(t *testing.T) {
	defer ApplyTuning(3.5, 4.2, 50000)
	d := newDetector(t)

	const src = `# config
db_password = "S3cr3tP4ssw0rd!"
api_key = "AKIANAFGYOEYPXU1DSYP"
note = "nothing secret on this line"
`
	ApplyTuning(3.5, 4.2, 50000) // default cap (effectively unbounded for this tiny input)
	base := d.Scan(src)

	ApplyTuning(3.5, 4.2, 100) // tight cap — must NOT change the handful of real findings
	withCap := d.Scan(src)

	if len(base) != len(withCap) {
		t.Fatalf("cap changed a normal scan: %d findings without cap, %d with cap", len(base), len(withCap))
	}
	for i := range base {
		if base[i].Type != withCap[i].Type || base[i].Start != withCap[i].Start ||
			base[i].End != withCap[i].End || base[i].Value != withCap[i].Value {
			t.Fatalf("cap altered finding %d: %+v vs %+v", i, base[i], withCap[i])
		}
	}
	// And the real password cue must still be present.
	if countType(base, "generic_password") == 0 {
		t.Fatalf("expected a generic_password finding for the real password cue, got none")
	}
}

// TestBase64SurvivesCapTruncation is the round-6 regression for the stage-ordering bug (introduced in
// 2f3d909): the cap filled with confidence-0.55 generic_high_entropy, then SKIPPED the confidence-0.94
// unmaskBase64 stage (`if budget > 0`), dropping a real base64-embedded structured secret. The fix runs
// unmaskBase64 on the bounded candidate set unconditionally, then truncates to the cap AFTER the
// confidence-first sort — so the 0.94 AWS key sorts ahead of the 0.55 noise and survives.
func TestBase64SurvivesCapTruncation(t *testing.T) {
	defer ApplyTuning(3.5, 4.2, 50000)
	d := newDetector(t)
	blob := base64.StdEncoding.EncodeToString([]byte("AWS_ACCESS_KEY_ID=AKIANAFGYOEYPXU1DSYP"))
	// The base64 blob is itself a high-entropy candidate (collected early). It is followed by far more
	// generic_high_entropy noise lines than the cap, so under the OLD ordering collect() filled the cap,
	// the remaining budget went to 0, and unmaskBase64 was skipped -> the AWS key was lost (exit 0).
	var b strings.Builder
	b.WriteString("secret = \"" + blob + "\"\n")
	for i := 0; i < 200; i++ {
		b.WriteString("secret_token_x = \"aB3xQ9zP7mK2wL5vN8tR4yC6dF1gH0jKpQ9zP7mK\"\n")
	}
	text := b.String()

	ApplyTuning(3.5, 4.2, 60) // cap small enough that generic noise would exhaust the budget after collect
	ms := d.Scan(text)
	found := false
	for _, m := range ms {
		if m.Type == "aws_access_key_id" {
			found = true
		}
	}
	if !found {
		t.Fatalf("base64-embedded AWS key STARVED by generic_high_entropy noise under the cap (got %d matches, none aws)", len(ms))
	}
	// And the result still honors the cap.
	if len(ms) > 60 {
		t.Fatalf("cap not enforced after base64 reorder: got %d matches, cap 60", len(ms))
	}
}

// TestSingleLongLineBoundedTime is the round-6 regression for the O(N^2) CPU DoS on a single long
// line: per-match work (hasPragma's whole-line ToLower in scan, the generic_password line-prefix
// lowercase in collect) used to be O(lineLen) PER match, making a 512KB single line ~20-45s even
// though the match COUNT is capped. With the per-line memoization + bounded pwd-cue lookback the
// per-match cost is O(1), so the scan completes in well under a second.
func TestSingleLongLineBoundedTime(t *testing.T) {
	d := newDetector(t)
	seg := "password=hunter2abc99 "
	var b strings.Builder
	for b.Len() < 512*1024 {
		b.WriteString(seg) // no newline -> ONE 512KB line, thousands of matches on it
	}
	text := b.String()
	start := time.Now()
	_ = d.Scan(text)
	// The memoized scan is O(N) (sub-second untraced); the bound is loose enough to tolerate the 5-10x
	// slowdown of `go test -race` on a slow CI runner while still catching the O(N^2) DoS (20-45s here).
	if dur := time.Since(start); dur > 15*time.Second {
		t.Fatalf("single 512KB line scan took %v (O(N^2) time DoS regression; expected O(N), well under 15s)", dur)
	}
}
