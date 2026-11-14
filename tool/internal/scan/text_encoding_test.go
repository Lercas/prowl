package scan

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/secretindex"
)

func TestEncodedTextPreservesPlainIdentitySourcePositionAndDisclosure(t *testing.T) {
	const key = "AKIANAFGYOEYPXU1DSYP"
	id, err := secretindex.LoadIdentity(filepath.Join(t.TempDir(), "index"), true)
	if err != nil {
		t.Fatal(err)
	}
	p := New(Options{Detector: detector(t), ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location})
	percent, entities := "", ""
	for _, c := range key {
		percent += fmt.Sprintf("%%%02X", c)
		entities += fmt.Sprintf("&#%d;", c)
	}
	for _, value := range []string{percent, entities} {
		text := "header\napi_key = \"" + value + "\"\n"
		it := model.Item{Source: "code", Path: "prod/" + value + ".env", Text: text}
		fs := p.Findings(t.Context(), it)
		if len(fs) != 1 {
			t.Fatalf("unexpected encoded findings: %d", len(fs))
		}
		f := fs[0]
		start := strings.Index(text, value)
		if f.Type != "aws_access_key_id" || f.Line != 2 || f.Col != start-strings.LastIndex(text[:start], "\n") || f.ValueFingerprint != id.Fingerprint(key) || f.Fingerprint != model.ComputeFingerprint(f.Type, it.Path, key) {
			t.Fatal("source mapping or plaintext identity lost")
		}
		if strings.Contains(f.IndexPath, key) || strings.Contains(f.IndexPath, value) {
			t.Fatal("observed encoded spelling leaked into index metadata")
		}
		raw, err := json.Marshal(fs)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), key) || f.Context != nil {
			t.Fatal("normalized value disclosed without authorization")
		}
		shown := p.WithRevealSecrets(true).Findings(t.Context(), it)
		if len(shown) != 1 || shown[0].Redacted != key || shown[0].Context == nil || !strings.Contains(shown[0].Context.Line, value) {
			t.Fatal("explicit disclosure lost logical value or original context")
		}
	}
}
