package scan

import (
	"context"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestStructuredProseCueCannotBorrowAnotherScalar(t *testing.T) {
	for _, text := range []string{
		`{"message":"Your password is","value":"Winter42!Autumn"}`,
		`{"password_hint":"Winter42!Autumn"}`,
		`{"message":"Your password is required"}`,
		`{"message":"password","value":"Winter42!Autumn"}`,
	} {
		fs := New(Options{Detector: detector(t)}).Findings(context.Background(), model.Item{Path: "production.json", Source: "code", Text: text})
		for _, f := range fs {
			if f.Type == "generic_password" {
				t.Fatal("prose borrowed a cue from another scalar or presentation name")
			}
		}
	}
}

func TestEscapedStructuredProseMapsOnlyThePasswordSpan(t *testing.T) {
	const value = "Winter42!Autumn"
	for _, it := range []model.Item{
		{Source: "code", Path: "production.json", Text: `{"message":"Your\u0020password\u0020is\u0020` + value + `"}`},
		{Source: "code", Path: "production.yaml", Text: "message: >\n  Your password is " + value + "\n"},
		{Source: "code", Path: "production.toml", Text: `message="Your\u0020password is ` + value + `"`},
	} {
		fs := New(Options{Detector: detector(t)}).Findings(t.Context(), it)
		if len(fs) != 1 || fs[0].ByteStart != strings.Index(it.Text, value) || it.Text[fs[0].ByteStart:fs[0].ByteEnd] != value || !strings.HasSuffix(fs[0].Stage, "L1-context-pw") {
			t.Fatal("prose password lost its exact source mapping", it.Path)
		}
	}
}
