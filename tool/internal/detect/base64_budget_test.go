package detect

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func denseBase64Fixture(count int) (*Detector, []Match) {
	d := New(&taxonomy.Taxonomy{Types: []taxonomy.SecretType{
		{ID: "owned_dense", Category: "cloud", RE: regexp.MustCompile(`OWNED_[A-Za-z0-9]{12}`)},
	}})
	blob := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("OWNED_G7hJ9kL2mN5p ", 160)))
	candidates := make([]Match, count)
	for i := range candidates {
		candidates[i] = Match{Value: blob, Start: i * (len(blob) + 1), End: i*(len(blob)+1) + len(blob)}
	}
	return d, candidates
}

func TestBase64IntermediateResultsBoundedByOuterCandidates(t *testing.T) {
	d, candidates := denseBase64Fixture(32)
	got, limited := d.unmaskBase64Candidates(context.Background(), candidates)
	if limited || len(got) != len(candidates) {
		t.Fatalf("decoded output must retain one winner per outer span: got %d, want %d, limited=%v", len(got), len(candidates), limited)
	}
	for i, m := range got {
		if m.Start != candidates[i].Start || m.End != candidates[i].End || m.Type != "owned_dense" || m.Value != "OWNED_G7hJ9kL2mN5p" || m.Stage != "L1-base64" {
			t.Fatalf("decoded finding lost its outer location or typed value at candidate %d", i)
		}
	}
}

func TestBase64KeepsHighestConfidenceAcrossDecodedMatches(t *testing.T) {
	d := newDetector(t)
	valid := validGithubToken()
	for _, text := range []string{
		"AWS_ACCESS_KEY_ID=AKIANAFGYOEYPXU1DSYP\nGH_TOKEN=" + valid,
		"GH_TOKEN=" + valid + "\nAWS_ACCESS_KEY_ID=AKIANAFGYOEYPXU1DSYP",
	} {
		blob := base64.StdEncoding.EncodeToString([]byte(text))
		got, limited := d.unmaskBase64Candidates(context.Background(), []Match{{Value: blob, Start: 7, End: 7 + len(blob)}})
		if limited || len(got) != 1 || got[0].Value != valid || !got[0].ChecksumValid || got[0].Confidence != 0.99*0.95 {
			t.Fatalf("higher-confidence decoded checksum match must win regardless of text order: matches=%d limited=%v", len(got), limited)
		}
	}
}

type base64ObservedContext struct {
	context.Context
	checks int
}

func (c *base64ObservedContext) Err() error {
	c.checks++
	return c.Context.Err()
}

func TestBase64CancellationStopsBeforeDecodingCandidates(t *testing.T) {
	d, candidates := denseBase64Fixture(32)
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	ctx := &base64ObservedContext{Context: parent}
	got, limited := d.unmaskBase64Candidates(ctx, candidates)
	if len(got) != 0 || limited || ctx.checks != 1 {
		t.Fatalf("cancelled scan walked decoded candidates: matches=%d limited=%v context checks=%d", len(got), limited, ctx.checks)
	}
}

func BenchmarkBase64IntermediateBuffer(b *testing.B) {
	d, candidates := denseBase64Fixture(100)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = d.unmaskBase64Candidates(context.Background(), candidates)
	}
}
