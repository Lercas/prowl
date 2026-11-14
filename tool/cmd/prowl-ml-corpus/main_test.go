package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlscore"
)

func TestCaptureUsesPipelineContextAndPythonCharacterSpans(t *testing.T) {
	for _, c := range []struct{ path, text, value, name, source string }{
		{"production.json", `{"password":"Quartz${19}Mango"}`, "Quartz${19}Mango", "password", "Quartz${19}Mango"},
		{"production.json", `{"password":"Quartz\u0034\u0032Mango"}`, "Quartz42Mango", "password", `Quartz\u0034\u0032Mango`},
		{"production.yaml", "пароль: \"ЖукЖук🦋\"\n", "ЖукЖук🦋", "пароль", "ЖукЖук🦋"},
		{"production.toml", "[auth]\n\"пароль\"=\"ЖукЖук🦋\"\n", "ЖукЖук🦋", "пароль", "ЖукЖук🦋"},
	} {
		a := annotation{Name: "synthetic", Path: c.path, Text: c.text, Value: c.value, LabelBinary: 1, LabelType: "generic_password"}
		input, _ := json.Marshal(a)
		var out bytes.Buffer
		if err := run(bytes.NewReader(input), &out); err != nil {
			t.Fatal(err)
		}
		var row struct {
			Value   string          `json:"value"`
			Context mlscore.Context `json:"context"`
			Span    [2]int          `json:"span"`
		}
		if err := json.Unmarshal(out.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		if row.Value != c.value || row.Context.Name != c.name || row.Context.Path != c.path || row.Context.Source != "code" {
			t.Fatal("captured features were reconstructed rather than obtained from pipeline")
		}
		text := []rune(c.text)
		if row.Span[0] < 0 || row.Span[1] > len(text) || string(text[row.Span[0]:row.Span[1]]) != c.source {
			t.Fatal("UTF-8 byte offsets were passed to a Python character-based splitter")
		}
	}
}

func TestCaptureRejectsUntrustedLabelsAndIncompleteSources(t *testing.T) {
	for _, a := range []annotation{
		{Path: "production.json", Text: `{"password":"Quartz42Mango"}`, Value: "different", LabelBinary: 1, LabelType: "generic_password"},
		{Path: "production.json", Text: `{"password":"Quartz42Mango"}`, Value: "Quartz42Mango", LabelBinary: 1, LabelType: "stripe_secret_key"},
		{Path: "production.json", Text: `{"password":"Quartz42Mango"}`, Value: "Quartz42Mango", LabelBinary: 0, LabelType: "generic_password"},
		{Path: "production.json", Text: `{"password":"Quartz42Mango"`, Value: "Quartz42Mango", LabelBinary: 1, LabelType: "generic_password"},
	} {
		input, _ := json.Marshal(a)
		var out bytes.Buffer
		err := run(bytes.NewReader(input), &out)
		if err == nil || out.Len() != 0 || strings.Contains(err.Error(), a.Value) {
			t.Fatal("invalid fixture exported data or leaked its value in an error")
		}
	}
}

func TestCaptureNegativeUICandidatesAndL1Suppressions(t *testing.T) {
	for _, c := range []struct {
		value    string
		exported bool
	}{{"Password must contain at least 12 characters.", true}, {"Password", false}} {
		a := annotation{Name: "synthetic-ui", Path: "messages.json", Text: `{"validation":{"password":"` + c.value + `"}}`, Value: c.value, LabelBinary: 0, LabelType: "neg_canonical_ui"}
		input, _ := json.Marshal(a)
		var out bytes.Buffer
		if err := run(bytes.NewReader(input), &out); err != nil {
			t.Fatal(err)
		}
		if (out.Len() > 0) != c.exported {
			t.Fatal("negative candidate inventory disagrees with L1")
		}
	}
}
