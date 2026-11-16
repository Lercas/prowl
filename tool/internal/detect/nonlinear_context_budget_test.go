package detect

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strings"
	"testing"
)

func TestNonLinearDecodedContextBudget(t *testing.T) {
	const key = "AKIANAFGYOEYPXU1DSYP"
	payload := "AWS_ACCESS_KEY_ID=" + key + "\n" + strings.Repeat("x", 256<<10-128)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	blob := base64.StdEncoding.EncodeToString(compressed.Bytes())
	candidates := make([]Match, 140)
	for i := range candidates {
		candidates[i] = Match{Value: blob, Start: i * len(blob), End: (i + 1) * len(blob)}
	}
	d := newDetector(t)
	results, limited := d.unmaskNonLinearContext(t.Context(), candidates, true)
	retained := 0
	for _, result := range results {
		text, start := result.VerificationContext()
		retained += len(text)
		end := start + len(result.Value)
		if start < 0 || end > len(text) || text[start:end] != key {
			t.Fatal("non-linear match lost its own decoded context")
		}
	}
	if !limited || len(results) == 0 || len(results) >= len(candidates) || retained > maxNonLinearContextBytes {
		t.Fatalf("retained context budget not enforced: results=%d bytes=%d limited=%v", len(results), retained, limited)
	}
	ordinary, limited := d.unmaskNonLinear(t.Context(), candidates)
	if limited || len(ordinary) != len(candidates) {
		t.Fatal("verification context budget changed ordinary detection")
	}
	for _, result := range ordinary {
		if text, _ := result.VerificationContext(); text != "" {
			t.Fatal("ordinary non-linear detection retained private verification context")
		}
	}
}
