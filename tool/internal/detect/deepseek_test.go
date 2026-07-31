package detect

import (
	"testing"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func TestDeepSeekAPIKeyContextRule(t *testing.T) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	d := New(tax)
	text := `DEEPSEEK_API_KEY="sk-abcdefghijklmnopqrstuvwxyz0123456789"`
	got := d.Scan(text)
	for _, match := range got {
		if match.Type == "deepseek_api_key" {
			if match.Value != "sk-abcdefghijklmnopqrstuvwxyz0123456789" {
				t.Fatalf("deepseek value = %q", match.Value)
			}
			return
		}
	}
	t.Fatalf("deepseek_api_key was not detected: %#v", got)
}

func TestDeepSeekRuleDoesNotMatchUnlabeledSKToken(t *testing.T) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	d := New(tax)
	for _, match := range d.Scan(`token="sk-abcdefghijklmnopqrstuvwxyz0123456789"`) {
		if match.Type == "deepseek_api_key" {
			t.Fatalf("unlabeled sk token matched DeepSeek rule: %#v", match)
		}
	}
}
