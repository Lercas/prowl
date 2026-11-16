package detect

import (
	"context"
	"strings"
	"testing"
)

const publicSubjectFixture = "sb_publishable_q7Mn9Jk3Qw5Er8Ty2Ui6Op4As1Df0Gh9Lz"

func TestPublicKeySubjectRequiresExplicitOption(t *testing.T) {
	d := newDetector(t)
	text := `const config={NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:"` + publicSubjectFixture + `"};`
	for _, m := range d.Scan(text) {
		if m.Type == "supabase-publishable-key" {
			t.Fatal("ordinary detection reported an audit subject")
		}
	}
	r := d.ScanWithStatus(t.Context(), text, ScanOptions{PublicKeys: true})
	if len(r.Matches) != 1 || r.Matches[0].Type != "supabase-publishable-key" || r.Matches[0].Value != publicSubjectFixture || text[r.Matches[0].Start:r.Matches[0].End] != publicSubjectFixture || r.CandidateLimited {
		t.Fatal("public subject identity/span changed")
	}
}

func TestPublicSubjectWholeBoundaryLimitsAndCancellation(t *testing.T) {
	for _, text := range []string{"x" + publicSubjectFixture, "sb_publishable_" + strings.Repeat("x", 129), "sb_publishable_" + strings.Repeat("x", 19), "sb_secret_" + strings.Repeat("x", 40)} {
		if got, limited := publicKeyCandidates(t.Context(), text); len(got) != 0 || limited {
			t.Fatal("invalid public key prefix accepted")
		}
	}
	got, limited := publicKeyCandidates(t.Context(), strings.Repeat(publicSubjectFixture+" ", MaxScanMatches()+1))
	if len(got) != MaxScanMatches() || !limited {
		t.Fatal("public candidate cap failed open")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, _ := publicKeyCandidates(ctx, publicSubjectFixture); len(got) != 0 {
		t.Fatal("canceled discovery continued")
	}
}

func FuzzPublicKeySubjectSpans(f *testing.F) {
	f.Add(publicSubjectFixture)
	f.Add("x" + publicSubjectFixture)
	f.Fuzz(func(t *testing.T, text string) {
		ms, _ := publicKeyCandidates(t.Context(), text)
		for _, m := range ms {
			if m.Start < 0 || m.End > len(text) || m.Start >= m.End || text[m.Start:m.End] != m.Value || !strings.HasPrefix(m.Value, "sb_publishable_") {
				t.Fatal("invalid source span")
			}
		}
	})
}
