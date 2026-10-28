package scan

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestReconstructionFindsSplitCredentialAndEvidence(t *testing.T) {
	text := "const head='AKIA';\nconst key=head+'NAFGYOEYPXU1DSYP';"
	key := []byte(strings.Repeat("k", 32))
	ctx := WithOptions(context.Background(), Options{Reconstruct: true, IdentityKey: key})
	fs := Findings(ctx, detector(t), nil, nil, model.Item{Text: text, Source: "code", Path: "bundle.js"}, nil, nil)
	for _, f := range fs {
		if f.Type == "aws_access_key_id" {
			if !strings.HasPrefix(f.Stage, "reconstructed/") || len(f.Evidence) < 2 || f.SecretID == "" || f.OccurrenceID == "" {
				t.Fatalf("missing source evidence: %+v", f)
			}
			return
		}
	}
	t.Fatal("split credential was missed")
}

func TestReconstructionOccurrencesUseExpressionCoordinates(t *testing.T) {
	text := "const head='AKIA';\nconst first=head+'NAFGYOEYPXU1DSYP';\nconst second=head+'NAFGYOEYPXU1DSYP';"
	ctx := WithOptions(context.Background(), Options{Reconstruct: true, IdentityKey: []byte(strings.Repeat("k", 32))})
	fs := Findings(ctx, detector(t), nil, nil, model.Item{Text: text, Source: "code", Path: "bundle.js"}, nil, nil)
	seen := map[string]int{}
	for _, f := range fs {
		if f.Type == "aws_access_key_id" {
			seen[f.OccurrenceID] = f.Line
		}
	}
	if len(seen) != 2 {
		t.Fatal("distinct expressions collapsed into the same occurrence identity")
	}
	for _, line := range seen {
		if line != 2 && line != 3 {
			t.Fatal("occurrence points to the shared prefix instead of its expression")
		}
	}
}

func TestReconstructedPragmaSetsFiltered(t *testing.T) {
	cov := model.NewCoverage()
	ctx := WithOptions(model.WithCoverage(context.Background(), cov), Options{Reconstruct: true})
	text := "const head='AKIA';\nconst key=head+'NAFGYOEYPXU1DSYP'; // prowl:allow"
	fs := Findings(ctx, detector(t), nil, nil, model.Item{Text: text, Source: "code", Path: "bundle.js"}, nil, nil)
	for _, f := range fs {
		if f.Type == "aws_access_key_id" {
			t.Fatal("expression pragma did not suppress reconstruction")
		}
	}
	if !model.NewResult(fs, cov).Filtered {
		t.Fatal("suppression could be mistaken for remediation")
	}
}

func TestReconstructionEvidenceDoesNotRevealURLCredentials(t *testing.T) {
	ctx := WithOptions(context.Background(), Options{Reconstruct: true})
	for _, path := range []string{"https://user:private-password@example.invalid/bundle.js", "https://example.invalid/bundle.js?key=private-query"} {
		it := model.Item{Text: `const key='AKIA'+'NAFGYOEYPXU1DSYP';`, Source: "code", Path: path}
		fs := Findings(ctx, detector(t), nil, nil, it, nil, nil)
		found := false
		for _, f := range fs {
			found = found || f.Type == "aws_access_key_id"
		}
		if !found {
			t.Fatal("query-bearing bundle was not reconstructed")
		}
		data, err := json.Marshal(fs)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "private-password") || strings.Contains(string(data), "private-query") {
			t.Fatal("raw URL leaked into source evidence")
		}
	}
}
func TestCrossSourceIdentityIsScopedAndOccurrenceSpecific(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	ctx := WithOptions(context.Background(), Options{IdentityKey: key})
	raw := "AKIANAFGYOEYPXU1DSYP"
	a := Findings(ctx, detector(t), nil, nil, model.Item{Text: raw, Source: "code", Path: "a.go"}, nil, nil)[0]
	b := Findings(ctx, detector(t), nil, nil, model.Item{Text: raw, Source: "jira", Path: "SEC-42"}, nil, nil)[0]
	if a.SecretID != b.SecretID || a.OccurrenceID == b.OccurrenceID {
		t.Fatal("secret and occurrence identities conflated")
	}
	other := WithOptions(context.Background(), Options{IdentityKey: []byte(strings.Repeat("x", 32))})
	c := Findings(other, detector(t), nil, nil, model.Item{Text: raw, Path: "a.go"}, nil, nil)[0]
	if c.SecretID == a.SecretID || c.IdentityScope == a.IdentityScope {
		t.Fatal("identities cross organization boundary")
	}
}
