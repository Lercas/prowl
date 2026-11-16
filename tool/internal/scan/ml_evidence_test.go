package scan

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
)

func TestReleasedMLEvidenceRequiresItsOwnBindingAndStage(t *testing.T) {
	hex := strings.Repeat("a9c2", 16)
	for _, c := range []struct {
		typ, stage, binding, value string
		keep                       bool
	}{
		{"generic_password", "L1-regex", "db_password", "required", true},
		{"generic_password", "normalized/yaml-scalar/L1-regex", "auth.password", "required", true},
		{"generic_password", "normalized/json-string/L1-regex", "auth.password", "required", true},
		{"generic_password", "normalized/toml-string/L1-regex", "auth.password", "required", true},
		{"generic_password", "L1-context-pw", "password", "required", false},
		{"generic_password", "semantic-candidate", "password", "required", false},
		{"generic_password", "base64/L1-regex", "password", "required", false},
		{"generic_password", "L1-regex", "password", "aB9!", false},
		{"generic_password", "L1-regex", "label", "required", false},
		{"generic_password", "L1-regex", "", "required", false},
		{"generic_api_key", "L1-context-key", "api_key", hex, true},
		{"generic_api_key", "L1-context-key", "checksum", hex, false},
		{"generic_api_key", "L1-context-key", "api_key", "a9c2", false},
		{"generic_api_key", "L1-context-key", "api_key", strings.Repeat("z9", 32), false},
		{"together-api-key", "rule", "together_api_key", hex, true},
		{"together-api-key", "rule", "together_checksum", hex, false},
		{"linode-api-token", "rule", "linode_id", hex, false},
		{"deepgram-api-key", "rule", "deepgram_api_key", hex, false},
		{"deepgram-api-key", "rule", "deepgram_api_key", strings.Repeat("q9", 20), true},
		{"deepgram-api-key", "rule", "deepgram_checksum", strings.Repeat("q9", 20), false},
		{"deepgram-api-key", "rule", "deepgram_api_key", strings.Repeat("!9", 20), false},
		{"twitch-client-secret", "rule", "twitch_client_secret", strings.Repeat("q9", 15), true},
		{"twitch-client-secret", "rule", "twitch_user_id", strings.Repeat("q9", 15), false},
		{"twitch-client-secret", "rule", "twitch_client_secret", strings.Repeat("q9", 14), false},
		{"netlify-access-token", "rule", "value", "nfp_too_short", false},
	} {
		r := mlscore.Record{Value: c.value, Context: mlscore.Context{Name: "password"}, DirectBinding: c.binding}
		if got := mlAnchoredEvidence(model.Finding{Type: c.typ, Stage: c.stage}, r); got != c.keep {
			t.Fatalf("wrong nomination guard for %s/%s/%s: %t", c.typ, c.stage, c.binding, got)
		}
	}
}

func TestReleasedMLEvidenceCannotBorrowAnotherAssignment(t *testing.T) {
	const value = "9ac2f1e4d5b603789ac2f1e4d5b60378"
	text := `const password="unrelated"; const checksum="` + value + `";`
	r := recordFor(value, model.Item{Text: text, Path: "app.js"}, strings.Index(text, value))
	if r.Context.Name != "password" || r.DirectBinding != "checksum" {
		t.Fatal("fixture did not distinguish trained context from direct evidence")
	}
	if mlAnchoredEvidence(model.Finding{Type: "generic_high_entropy", Stage: "L1-entropy"}, r) {
		t.Fatal("another assignment protected a hash candidate")
	}
	r.DirectBinding = "private-binding-marker"
	data, err := json.Marshal(r)
	if err != nil || strings.Contains(string(data), r.DirectBinding) || strings.Contains(string(data), "DirectBinding") {
		t.Fatal("local binding evidence leaked to a scoring request")
	}
}
