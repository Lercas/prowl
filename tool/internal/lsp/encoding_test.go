package lsp

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestEncodedCredentialsUseOriginalEditorRanges(t *testing.T) {
	e := newTestEngine(t)
	const value = "AKIANAFGYOEYPXU1DSYP"
	blob := base64.StdEncoding.EncodeToString([]byte("first=" + value + "\nsecond=AKIAZ7M4Q9N2W8K5R3VX"))
	for _, c := range []struct {
		path, text, source string
		count              int
	}{
		{"payload.env", "# 🔐\npayload=\"" + base64.StdEncoding.EncodeToString([]byte(value)) + "\"", base64.StdEncoding.EncodeToString([]byte(value)), 1},
		{"config.yaml", `{пароль: "Winter\u0034\u0032!Autumn"}`, `Winter\u0034\u0032!Autumn`, 1},
		{"config.json", `{"пароль":"Winter\u0034\u0032!Autumn"}`, `Winter\u0034\u0032!Autumn`, 1},
		{"typed.json", `{"note":"🔐","key":"\u0041\u004b\u0049\u0041NAFGYOEYPXU1DSYP"}`, `\u0041\u004b\u0049\u0041NAFGYOEYPXU1DSYP`, 1},
		{"config.toml", "\ufeffpassword='Winter42!Autumn'", "Winter42!Autumn", 1},
		{"multiline.toml", "password=\"\"\"\nWinter\\\n  42!Autumn\"\"\"", "Winter\\\n  42!Autumn", 1},
		{"typed.toml", `note="🔐"` + "\n" + `key="\u0041\u004b\u0049\u0041NAFGYOEYPXU1DSYP"`, `\u0041\u004b\u0049\u0041NAFGYOEYPXU1DSYP`, 1},
		{"multiline.yaml", "note: 🔐\npassword: |-\n  Winter42!Autumn\n  Spring53\n", "Winter42!Autumn\n  Spring53", 1},
		{"alias.yaml", "definition: &a Winter42!Autumn\npassword: *a\n", "*a", 1},
		{"binary.yaml", "token: !!binary '" + base64.StdEncoding.EncodeToString([]byte(value)) + "'\n", base64.StdEncoding.EncodeToString([]byte(value)), 1},
	} {
		ds := scanDiagnostics(e, "file:///workspace/"+c.path, c.text)
		if len(ds) != c.count {
			t.Fatalf("encoded editor finding count: got %d, expected %d", len(ds), c.count)
		}
		start := strings.Index(c.text, c.source)
		sl, sc := offsetPos(c.text, start)
		el, ec := offsetPos(c.text, start+len(c.source))
		for _, d := range ds {
			r := d["range"].(map[string]any)
			a, b := r["start"].(map[string]any), r["end"].(map[string]any)
			if a["line"] != sl || a["character"] != sc || b["line"] != el || b["character"] != ec {
				t.Fatal("decoded editor range refers to a reconstructed value rather than source")
			}
			if strings.Contains(d["message"].(string), value) || strings.Contains(d["message"].(string), blob) {
				t.Fatal("encoded editor diagnostic disclosed credential data")
			}
		}
	}
}

func TestDecodedRepeatedCredentialsHaveDifferentEditorRanges(t *testing.T) {
	e := newTestEngine(t)
	const raw = "AKIANAFGYOEYPXU1DSYP"
	decoded := "first=" + raw + "\nsecond=" + raw
	blob := base64.StdEncoding.EncodeToString([]byte(decoded))
	text := "# 🔐\npayload='" + blob + "'"
	ds := scanDiagnostics(e, "file:///workspace/production.env", text)
	if len(ds) != 2 {
		t.Fatal("editor lost an inner encoded occurrence")
	}
	ranges := map[string]bool{}
	for _, d := range ds {
		b, _ := json.Marshal(d["range"])
		ranges[string(b)] = true
	}
	if len(ranges) != 2 {
		t.Fatal("different decoded occurrences share one whole-blob editor range")
	}
}
