package scan

import (
	"strings"
	"testing"
)

func TestCodeLiteralRegionsRespectLanguageSyntax(t *testing.T) {
	const value = "Kp9aZ2bYwcX4dWqeV8fUmgThS6iRnjQ7sL"
	for _, c := range []struct {
		path, text string
		literal    bool
	}{
		{"app.rs", "fn f<'a>(x: &'a str) { let api_key=" + value + "; }", false},
		{"app.rs", "let doc = r##\"some \"quotes\" api_key=" + value + "\"##;", true},
		{"app.rs", "/* first /* nested */ api_key=" + value + " */", true},
		{"app.go", "const doc = `api_key=" + value + "`;", true},
		{"app.py", "doc = \"\"\"some \"quotes\" api_key=" + value + "\"\"\"", true},
		{"app.java", "String doc = \"\"\"\nsome \"quotes\" api_key=" + value + "\n\"\"\";", true},
		{"app.cs", "var doc = @\"some \"\"quotes\"\" api_key=" + value + "\";", true},
		{"app.py", "doc = '\nunclosed string\napi_key=" + value, false},
		{"app.js", "const doc = \"https://internal.invalid\"; api_key=" + value, false},
		{"app.js", "const doc = `${api_key=" + value + "}`;", false},
		{"app.js", "const doc = `${fn({x:1}) && (api_key=" + value + ")}`;", false},
		{"app.js", "const doc = `${api_key=\"" + value + "\"}`;", true},
		{"app.js", "const doc = `api_key=" + value + " ${fn({x:1})}`;", true},
		{"app.js", "const doc = `${`nested ${api_key=" + value + "}`}`;", false},
	} {
		filter := NewCodeValueFilter(c.path, c.text)
		start := strings.Index(c.text, value)
		if got := filter.NonLiteral(start, start+len(value)); got == c.literal {
			t.Fatalf("unexpected literal classification for %s: literal=%v", c.path, !got)
		}
	}
}
