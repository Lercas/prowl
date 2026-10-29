package scan

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
)

func TestLongParserEstablishedCredentialBindings(t *testing.T) {
	ml, err := mlscore.NewEmbedded(.5, "")
	if err != nil {
		t.Fatal(err)
	}
	const value = "Winter42!Autumn"
	for _, name := range []string{strings.Repeat("service_", 40) + "password", strings.Repeat("сервис_", 40) + "пароль", strings.Repeat("a", 150) + strings.Repeat("1", 150) + "_password"} {
		encoded, _ := json.Marshal(map[string]string{name: value})
		for _, item := range []model.Item{
			{Path: "production.json", Text: string(encoded), Source: "code"},
			{Path: "production.yaml", Text: name + ": '" + value + "'", Source: "code"},
			{Path: "production.toml", Text: "\"" + name + "\"='" + value + "'", Source: "code"},
		} {
			for _, scorer := range []mlscore.Scorer{nil, ml} {
				cov := model.NewCoverage()
				fs := Findings(model.WithCoverage(context.Background(), cov), detector(t), nil, nil, item, nil, scorer)
				complete, _, ds := cov.Snapshot()
				if !complete || len(fs) != 1 || fs[0].Fingerprint != model.ComputeFingerprint("generic_password", item.Path, value) {
					t.Fatalf("long parser binding vanished: %s findings=%+v diagnostics=%+v", item.Path, fs, ds)
				}
			}
		}
	}
}

func TestExplicitMixedSequentialPasswordsAreNotPlaceholders(t *testing.T) {
	for _, value := range []string{"Ab1234567", "p0000000!", "Realdeadbeef!", "xxxxWinter42"} {
		for _, item := range []model.Item{
			{Path: "production.json", Source: "code", Text: `{"password":"` + value + `"}`},
			{Path: "production.env", Source: "code", Text: "PASSWORD='" + value + "'"},
		} {
			fs := Findings(context.Background(), detector(t), nil, nil, item, nil, nil)
			if len(fs) != 1 || fs[0].Fingerprint != model.ComputeFingerprint("generic_password", item.Path, value) {
				t.Fatalf("explicit weak password lost: %s %q", item.Path, value)
			}
		}
	}
}

func TestStructuredProseKeepsContextualPasswordEvidence(t *testing.T) {
	const value = "Winter42!Autumn"
	for _, item := range []model.Item{
		{Path: "production.json", Source: "code", Text: `{"message":"Your password is ` + value + `"}`},
		{Path: "production.yaml", Source: "code", Text: "message: 'Your password is " + value + "'"},
		{Path: "production.toml", Source: "code", Text: "message='Your password is " + value + "'"},
	} {
		fs := Findings(context.Background(), detector(t), nil, nil, item, nil, nil)
		if len(fs) != 1 || !strings.HasSuffix(fs[0].Stage, "L1-context-pw") || fs[0].Fingerprint != model.ComputeFingerprint("generic_password", item.Path, value) {
			t.Fatalf("contextual password in structured prose lost: %s %+v", item.Path, fs)
		}
	}
}

func TestJSONBOMAndCarriageReturnSourceCoordinates(t *testing.T) {
	const value = "Winter42!Autumn"
	for _, separator := range []string{"\n", "\r", "\r\n"} {
		text := "\uFEFF{" + separator + `"password":"` + value + `"}`
		item := model.Item{Path: "production.json", Source: "code", Text: text}
		cov := model.NewCoverage()
		fs := Findings(model.WithCoverage(context.Background(), cov), detector(t), nil, nil, item, nil, nil)
		complete, _, ds := cov.Snapshot()
		if !complete || len(fs) != 1 || fs[0].Line != 2 || fs[0].Col != 13 || fs[0].ByteStart != strings.Index(text, value) || text[fs[0].ByteStart:fs[0].ByteEnd] != value {
			t.Fatalf("BOM/newline altered canonical identity or source coordinates: %+v %+v", fs, ds)
		}
		// An allow comment on an earlier CR-only line must not suppress the following credential.
		env := model.Item{Path: "production.env", Source: "code", Text: "# prowl:allow" + separator + "PASSWORD='" + value + "'"}
		if got := Findings(context.Background(), detector(t), nil, nil, env, nil, nil); len(got) != 1 || got[0].Line != 2 {
			t.Fatal("previous-line pragma suppressed a credential across a newline")
		}
	}
}
