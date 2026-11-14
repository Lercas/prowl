package scan

import (
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestTOMLPragmasRequireActualComments(t *testing.T) {
	const key = "AKIANAFGYOEYPXU1DSYP"
	for _, sep := range []string{"\n", "\r\n"} {
		for _, c := range []struct {
			text  string
			count int
		}{
			{`key="` + key + `" # prowl:allow` + sep, 0},
			{`key="` + key + ` # prowl:allow"` + sep, 1},
			{"key=\"\"\"" + key + " # prowl:allow\"\"\"" + sep, 1},
			{"# prowl:allow" + sep + `key="` + key + `"` + sep, 1},
			{`key="` + key + `" # prowl:allowance` + sep, 1},
			{`key="` + key + `" # xprowl:allow` + sep, 1},
		} {
			it := model.Item{Source: "code", Path: "production.toml", Text: c.text}
			fs := New(Options{Detector: detector(t)}).Findings(t.Context(), it)
			if len(fs) != c.count {
				t.Fatalf("comment/data role changed: %q, %+v", c.text, fs)
			}
			if strings.Contains(c.text, ` # prowl:allow`) {
				fs = New(Options{Detector: detector(t), IgnorePragmas: true}).Findings(t.Context(), it)
				if len(fs) != 1 || fs[0].Type != "aws_access_key_id" {
					t.Fatal("untrusted source could grant itself an exception")
				}
			}
		}
	}
}

func TestStructuredPhysicalCoordinatesAndHMACAtAliasUse(t *testing.T) {
	const key = "AKIANAFGYOEYPXU1DSYP"
	for _, c := range []struct{ path, text string }{
		{"production.yaml", "note: 🚀\r\ndefinition: &a " + key + "\r\ncopy: *a\r\n"},
		{"production.toml", "note='🚀'\r\nkey=\"\\u0041KIANAFGYOEYPXU1DSYP\"\r\n"},
	} {
		var locations [][2]int
		p := New(Options{Detector: detector(t), ValueFingerprint: func(v string) string {
			if v != key {
				t.Fatal("noncanonical value reached identity function")
			}
			return "owned-identity"
		}, LocationFingerprint: func(source, path string, line, col int) string {
			locations = append(locations, [2]int{line, col})
			return "owned-location"
		}})
		fs := p.Findings(t.Context(), model.Item{Source: "code", Path: c.path, Text: c.text})
		want := 1
		if strings.HasSuffix(c.path, "yaml") {
			want = 2
		}
		if len(fs) != want {
			t.Fatalf("physical occurrences lost: %+v", fs)
		}
		li := newLineIndex(c.text)
		for _, f := range fs {
			line, col := li.cols(f.ByteStart)
			if f.Line != line || f.Col != col || f.UTF16Col != li.utf16Col(f.ByteStart) || f.ValueFingerprint != "owned-identity" || f.IndexLocationID != "owned-location" {
				t.Fatal("canonical finding retained synthetic coordinates")
			}
			found := false
			for _, location := range locations {
				found = found || location == [2]int{line, col}
			}
			if !found {
				t.Fatal("HMAC locator was never given physical source coordinates")
			}
		}
	}
}
