package scan

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
)

func TestProseLabelReachesMLWithOriginalValueAndPrivateIdentity(t *testing.T) {
	const value = "Q7mR3vK8pT2xN6cW4bY9sF5hL1aD0uGz"
	const text = "🔐 The api_key used for authentication is " + value + "."
	key := []byte(strings.Repeat("k", 32))
	calls := 0
	scorer := &compareTestScorer{action: func(records []mlscore.Record) ([]mlscore.Result, error) {
		calls++
		if len(records) != 1 || records[0].Value != value || records[0].Context.Name != "api_key" || !strings.Contains(records[0].Context.Line, value) {
			t.Fatal("ML lost the proven prose label or source value")
		}
		return []mlscore.Result{{Score: 1}}, nil
	}}
	p := New(Options{Detector: detector(t), ML: scorer, IdentityKey: key})
	fs := p.Findings(context.Background(), model.Item{Source: "file", Path: "production.md", Text: text})
	if calls != 1 || len(fs) != 1 || fs[0].Type != "generic_high_entropy" || fs[0].ByteStart != strings.Index(text, value) || text[fs[0].ByteStart:fs[0].ByteEnd] != value {
		t.Fatal("prose label changed entropy type or original span")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	if fs[0].SecretID != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatal("identity did not use the exact source value")
	}
	data, err := json.Marshal(fs)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), value) || fs[0].Context != nil {
		t.Fatal("private prose scoring context leaked")
	}
}
