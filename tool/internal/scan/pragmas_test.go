package scan

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestAllowPragmasRequireOperatorComments(t *testing.T) {
	const key = "\x41KIANAFGYOEYPXU1DSYP"
	for _, c := range []struct {
		path, text string
		suppressed bool
	}{
		{"config.py", `key="` + key + `"; note="prowl:allow"`, false},
		{"config.js", `key="` + key + `"; note="// prowl:allow"`, false},
		{"config.py", "note='''\n# prowl:allow " + key + "\n'''", false},
		{"config.js", "note=`\n// gitleaks:allow " + key + "\n`", false},
		{"config.json", `{"key":"` + key + `","note":"# prowl:allow"}`, false},
		{"config.json", `{"key":"\u0041KIANAFGYOEYPXU1DSYP","note":"# prowl:allow"}`, false},
		{"config.toml", `key='` + key + `' # prowl:allow`, true},
		{"config.toml", `password='Winter42\' # prowl:allow`, true},
		{"config.toml", `auth={key='` + key + `', note='# prowl:allow'}`, false},
		{"config.toml", "note='''\n# prowl:allow " + key + "\n'''", false},
		{"config.env", "key=" + key + " # prowl:allowed", false},
		{"config.env", "key=" + key + " # xprowl:allow", false},
		{"config.env", "key=" + key + " # prowl:allow", true},
		{"config.env", "key=" + key + " // prowl:allow", false},
		{"config.env", "key=" + key + " /* prowl:allow */", false},
		{".env.production", "key=" + key + " // prowl:allow", false},
		{"config.js", "key='" + key + "'; /* gitleaks:allow */", true},
		{"config.html", key + " <!-- pragma: allowlist secret -->", true},
		{"config.sql", "key='" + key + "' -- noqa: secret", true},
		{"config.ini", "; prowl:allow key=" + key, true},
	} {
		cov := model.NewCoverage()
		fs := Findings(model.WithCoverage(context.Background(), cov), detector(t), nil, nil, model.Item{Path: c.path, Text: c.text, Source: "code"}, nil, nil)
		if (len(fs) == 0) != c.suppressed || model.NewResult(nil, cov).Filtered != c.suppressed {
			t.Fatalf("allow pragma comment boundary violated: %s %q", c.path, c.text)
		}
	}
}

func TestAllowPragmaInventoryHasLinearCost(t *testing.T) {
	text := "x; " + strings.Repeat("x; ", 100000) + "\"# prowl:allow\""
	started := time.Now()
	if newLineIndex(text).hasPragma(0) {
		t.Fatal("quoted pragma marker suppressed a dense line")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("pragma comments repeatedly scanned semicolon prefixes")
	}
}
