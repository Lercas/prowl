package scan

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	bundledrules "github.com/Lercas/prowl/tool/rules"
)

func TestRepeatedCredentialKeepsEveryExactOccurrence(t *testing.T) {
	const value = "Kp9aZ2bYwcX4dWqeV8fUmgThS6iRnjQ7sL"
	text := `const first={azure_client_secret:"` + value + `"}; const second={azure_client_secret:"` + value + `"};` + "\n" + `const third={azure_client_secret:"` + value + `"};`
	eng, err := rules.LoadEmbedded(bundledrules.Files)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithOptions(context.Background(), Options{IdentityKey: []byte(strings.Repeat("k", 32))})
	fs := Findings(ctx, detector(t), eng, nil, model.Item{Path: "app.js", Text: text, Source: "code"}, nil, nil)
	if len(fs) != 3 {
		t.Fatalf("three source occurrences collapsed or duplicated: %d", len(fs))
	}
	spans, occurrences, secrets := map[int]bool{}, map[string]bool{}, map[string]bool{}
	for _, f := range fs {
		if f.Type != "azure-ad-client-secret" || f.ByteStart < 0 || f.ByteEnd > len(text) || f.ByteStart >= f.ByteEnd || text[f.ByteStart:f.ByteEnd] != value {
			t.Fatal("a repeated occurrence lost its provider type or exact source span")
		}
		spans[f.ByteStart] = true
		occurrences[f.OccurrenceID] = true
		secrets[f.SecretID] = true
		if f.OccurrenceID == "" || f.SecretID == "" {
			t.Fatal("identity evidence missing")
		}
	}
	if len(spans) != 3 || len(occurrences) != 3 || len(secrets) != 1 {
		t.Fatal("secret identity and distinct occurrences were conflated")
	}
	raw, err := json.Marshal(fs)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "ByteStart") || strings.Contains(string(raw), "ByteEnd") || strings.Contains(string(raw), value) {
		t.Fatal("internal offsets or raw value leaked to redacted JSON")
	}
}
