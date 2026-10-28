package scan

import (
	"context"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	bundledrules "github.com/Lercas/prowl/tool/rules"
)

func TestLiteralUIRolesPreserveConfiguredWeakPasswords(t *testing.T) {
	ml, err := mlscore.NewEmbedded(.5, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []model.Item{
		{Path: "production.json", Text: `{"labels":{"password":"Password","пароль":"Пароль","token":"` + "\x73" + `k_live_Q5t7U9i2O4p6A8s0D3f5G7h9","real_password":"Ab1234567"},"auth":{"password":"Password"}}`},
		{Path: "production.yaml", Text: "labels:\n  password: Password\n  пароль: Пароль\n  token: \x73k_live_Q5t7U9i2O4p6A8s0D3f5G7h9\n  real_password: Ab1234567\nauth: {password: Password}\n"},
		{Path: "production.toml", Text: "[labels]\npassword='Password'\n'пароль'='Пароль'\ntoken='\x73k_live_Q5t7U9i2O4p6A8s0D3f5G7h9'\nreal_password='Ab1234567'\n[auth]\npassword='Password'"},
	} {
		item.Source = "code"
		for _, scorer := range []mlscore.Scorer{nil, ml} {
			fs := Findings(context.Background(), detector(t), nil, nil, item, nil, scorer)
			if len(fs) != 3 {
				t.Fatalf("UI role hid real values or retained labels: %s %+v", item.Path, fs)
			}
			for _, value := range []string{"Password", "Ab1234567", "\x73k_live_Q5t7U9i2O4p6A8s0D3f5G7h9"} {
				found := false
				for _, f := range fs {
					found = found || f.Fingerprint == model.ComputeFingerprint(f.Type, item.Path, value)
				}
				if !found {
					t.Fatalf("configured credential %q disappeared in %s", value, item.Path)
				}
			}
		}
	}
	for _, text := range []string{
		`{"username":"Username","password":"Password","login":"Sign in"}`,
		`{"labels":[{"password":"Confirm password"}]}`,
		`{"validation":{"password":"Password is required"}}`,
	} {
		if fs := Findings(context.Background(), detector(t), nil, nil, model.Item{Source: "code", Path: "en.json", Text: text}, nil, nil); len(fs) != 0 {
			t.Fatalf("UI text retained as credential: %+v", fs)
		}
	}
}

func TestStructuredProviderNamespacesKeepTypedIdentity(t *testing.T) {
	eng, err := rules.LoadEmbedded(bundledrules.Files)
	if err != nil {
		t.Fatal(err)
	}
	ml, err := mlscore.NewEmbedded(.5, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ provider, value, typ string }{
		{"assemblyai", "83ea947bc2567d10a5f390c2eb468d91", "assemblyai-api-key"},
		{"together", strings.Repeat("83ea947bc2567d10a5f390c2eb468d91", 2), "together-api-key"},
	} {
		for _, item := range []model.Item{
			{Path: "production.json", Text: `{"` + row.provider + `":{"api_key":"` + row.value + `"}}`},
			{Path: "production.yaml", Text: row.provider + ":\n  api_key: '" + row.value + "'"},
			{Path: "production.toml", Text: "[" + row.provider + "]\napi_key='" + row.value + "'"},
		} {
			item.Source = "code"
			for _, scorer := range []mlscore.Scorer{nil, ml} {
				fs := Findings(context.Background(), detector(t), eng, nil, item, nil, scorer)
				found := false
				for _, f := range fs {
					found = found || f.Type == row.typ && f.Fingerprint == model.ComputeFingerprint(row.typ, item.Path, row.value)
				}
				if !found {
					t.Fatalf("provider context lost: %s/%s %+v", row.provider, item.Path, fs)
				}
			}
		}
	}
}
