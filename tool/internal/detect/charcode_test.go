package detect

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"
)

func charCodeFixture(value, shape string) string {
	units := utf16.Encode([]rune(value))
	args := make([]string, len(units))
	for i, u := range units {
		args[i] = fmt.Sprint(u)
	}
	list := strings.Join(args, ",")
	switch shape {
	case "hex":
		for i, u := range units {
			args[i] = fmt.Sprintf("0x%x", u)
		}
		return "String.fromCharCode(" + strings.Join(args, ",") + ")"
	case "spread":
		return "String.fromCharCode(...[" + list + "])"
	case "apply":
		return "String.fromCharCode.apply(null,[" + list + "])"
	case "wrap":
		for i, u := range units {
			args[i] = fmt.Sprint(int(u) - 65536)
		}
		return "String.fromCharCode(" + strings.Join(args, ",") + ")"
	case "multiline":
		return "String \n . fromCharCode(\n" + strings.Join(args, ",\n") + ",\n)"
	default:
		return "String.fromCharCode(" + list + ")"
	}
}

func TestCharCodeNumericSemantics(t *testing.T) {
	for _, c := range []struct {
		literal string
		unit    uint16
	}{
		{"65", 65}, {"65.9", 65}, {"+65", 65}, {"-65471", 65}, {"6_5", 65}, {".65e2", 65}, {"65e+0", 65},
		{"0x4_1", 65}, {"0b1000001", 65}, {"0o101", 65}, {"65536.9", 0}, {"-65535.9", 1},
		{"0x20000000000041", 64}, {"0x10000000000000041", 0}, {"1e309", 0}, {"1e-9999", 0},
	} {
		unit, ok := charCodeUnit(c.literal)
		if !ok || unit != c.unit {
			t.Errorf("%s: got %d,%v want %d", c.literal, unit, ok, c.unit)
		}
	}
	for _, s := range []string{"065", "00", "0x_41", "65_", "6__5", "1e_2", "1_", "1n", "NaN", "Infinity", "true", "'65'", "a()", "65+1"} {
		if _, ok := charCodeUnit(s); ok {
			t.Errorf("non-numeric/ambiguous literal accepted: %s", s)
		}
	}
}

func TestCharCodeTypedValuesAndSourceSpans(t *testing.T) {
	d := newDetector(t)
	for _, shape := range []string{"decimal", "hex", "spread", "apply", "wrap", "multiline"} {
		expr := charCodeFixture(depthAWSKey, shape)
		text := "heading\nconst blob = " + expr + ";\n"
		matches, limited := d.ScanCtxWithStatus(t.Context(), text)
		m := findType(matches, "aws_access_key_id")
		if limited || m == nil || m.Value != depthAWSKey || text[m.Start:m.End] != expr {
			t.Errorf("%s: typed value/span lost, found=%v limited=%v", shape, m != nil, limited)
		}
	}
	// A token beyond the ordinary cue lookback still belongs to the same call.
	expr := charCodeFixture(strings.Repeat(" ", 300)+depthAWSKey, "decimal")
	if m := findType(d.Scan("blob="+expr), "aws_access_key_id"); m == nil || m.Value != depthAWSKey {
		t.Fatal("typed token beyond view cue lookback lost")
	}
	// Context-sensitive provider detection keeps its original assignment context.
	const secret = "wJalrXUtnFEMIK7MDENGbPxRfiCYzK8vQ2mN4pLs"
	if m := findType(d.Scan("aws_secret_access_key="+charCodeFixture(secret, "decimal")), "aws_secret_access_key"); m == nil || m.Value != secret {
		t.Fatal("typed provider context lost")
	}
}

func TestCharCodeGenericCredentialsAndLogicalData(t *testing.T) {
	d := newDetector(t)
	for _, c := range []struct{ name, value string }{
		{"password", "Kx7;mP,q2'vL"}, {"db_password", `"Kx7#mPq2"`}, {"password", "Kx7😀mPq2"},
		{"refresh_token", namedToken}, {"key", namedHex64},
		{"пароль", "Kx7;mPq2"}, {"passwort", "Kx7;mPq2"},
	} {
		for _, text := range []string{
			"const " + c.name + "=" + charCodeFixture(c.value, "decimal"),
			"cfg['" + c.name + "'] == " + charCodeFixture(c.value, "spread"),
			charCodeFixture(c.value, "apply") + " != cfg['" + c.name + "']",
		} {
			matches, limited := d.ScanCtxWithStatus(t.Context(), text)
			typ := "generic_password"
			if c.name == "key" || c.name == "refresh_token" {
				typ = "generic_api_key"
			}
			m := namedMatch(matches, typ, c.value)
			if limited || m == nil || m.ContextName != c.name {
				t.Errorf("generic value/name lost for %s, found=%v limited=%v", c.name, m != nil, limited)
			}
		}
	}
}

func TestCharCodeRejectsDynamicAndUnrelatedForms(t *testing.T) {
	d := newDetector(t)
	expr := charCodeFixture("Kx7;mPq2", "decimal")
	for _, text := range []string{
		"blob=" + expr, "password_hash=" + expr, "password_type=" + expr,
		"password=" + expr + "+suffix", "password=" + expr + ".toLowerCase()", "prefix+password==" + expr,
		"'password'==" + expr, "'db_password'==" + expr,
		"password=OtherString.fromCharCode(75,120,55,59,109,80,113,50)",
		"password=obj.String.fromCharCode(75,120,55,59,109,80,113,50)",
		"password=éString.fromCharCode(75,120,55,59,109,80,113,50)",
		"password=String.fromCharCode(variable)", "password=String.fromCharCode(65+1)",
		"password=String.fromCharCode.apply(callback(),[65,75])",
		"password=String.fromCharCode(...variable)",
		"password=" + charCodeFixture("${VAULT_PASSWORD}", "decimal"),
		"password=" + charCodeFixture("changeme", "decimal"),
	} {
		ms, limited := d.charCodeSecrets(t.Context(), text, maxViewBytes, maxViewConstructs)
		if len(ms) != 0 || limited {
			t.Errorf("unrelated/dynamic input promoted: %q matches=%d limited=%v", text, len(ms), limited)
		}
	}
	d.genericPwd, d.genericKey = false, false
	if ms, _ := d.charCodeSecrets(t.Context(), "password="+expr, maxViewBytes, maxViewConstructs); len(ms) != 0 {
		t.Fatal("disabled generic taxonomy produced charcode finding")
	}
}

func TestCharCodeLimitsAndBrokenUTF16(t *testing.T) {
	d := newDetector(t)
	for _, text := range []string{
		strings.Repeat("String.fromCharCode(variable);\n", maxViewConstructs+1),
		"String.fromCharCode(" + strings.Repeat("65,", maxCharCodeUnits+1) + "65)",
		"String.fromCharCode(" + strings.Repeat(" ", maxCharCodeSource) + "65)",
		"String.fromCharCode(" + strings.Repeat("1", maxCharCodeNumber+1) + ")",
	} {
		if _, limited := d.charCodeSecrets(t.Context(), text, maxViewBytes, maxViewConstructs); !limited {
			t.Errorf("charcode limit hidden for %d bytes", len(text))
		}
	}
	text := "api_key=" + charCodeFixture(depthAWSKey, "decimal")
	if _, cap := d.charCodeSecrets(t.Context(), text, 10, maxViewConstructs); !cap {
		t.Fatal("decoded output limit hidden")
	}
	text = strings.Repeat(`"\u0041" `, maxViewConstructs) + "\n" + text
	if _, cap := d.scanViewsStatus(t.Context(), text); !cap {
		t.Fatal("normalization discovery budgets not shared")
	}
	// Broken UTF-16 must not hide an adjacent, independently valid typed value.
	expr := strings.Replace(charCodeFixture(depthAWSKey, "decimal"), "(", "(55296,", 1)
	matches, limited := d.ScanCtxWithStatus(t.Context(), "password="+expr)
	if !limited || findType(matches, "aws_access_key_id") == nil {
		t.Fatal("broken UTF-16 hid typed suffix or uncertainty")
	}
	for _, m := range matches {
		if m.Stage == stageCharCode {
			t.Fatal("lossy UTF-16 became a generic credential")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if ms, _ := d.charCodeSecrets(ctx, "api_key="+expr, maxViewBytes, maxViewConstructs); len(ms) != 0 {
		t.Fatal("cancelled conversion emitted findings")
	}
}

func FuzzCharCodeSourceBounds(f *testing.F) {
	for _, text := range []string{charCodeFixture(depthAWSKey, "decimal"), "String.fromCharCode(0x41,1e309)", "String.fromCharCode.apply(null,[65,])"} {
		f.Add(text)
	}
	d := newDetector(f)
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 32<<10 {
			return
		}
		ms, _ := d.charCodeSecrets(t.Context(), text, 4096, 32)
		for _, m := range ms {
			if m.Start < 0 || m.End > len(text) || m.Start >= m.End {
				t.Fatal("charcode source span outside input")
			}
		}
	})
}

func TestCharCodeBrokenUTF16DoesNotInventCredentialValue(t *testing.T) {
	expr := strings.Replace(charCodeFixture("postgresql://svc:Kx7$mPq2@prod.internal/db", "decimal"), ",75,", ",55296,75,", 1)
	ms, limited := newDetector(t).charCodeSecrets(t.Context(), "blob="+expr, maxViewBytes, maxViewConstructs)
	if !limited {
		t.Fatal("broken credential encoding presented as complete")
	}
	for _, m := range ms {
		if strings.ContainsRune(m.Value, '\ufffd') {
			t.Fatal("lossy replacement became a credential value")
		}
	}
	valid := "postgresql://svc:Kx7\ufffdmPq2@prod.internal"
	ms, limited = newDetector(t).charCodeSecrets(t.Context(), "blob="+charCodeFixture(valid, "decimal"), maxViewBytes, maxViewConstructs)
	if limited || namedMatch(ms, "db_connection_string", valid) == nil {
		t.Fatal("literal U+FFFD was confused with lossy UTF-16 recovery")
	}
}

func TestCharCodePreservesPlainTypedWinnerBeforeSourceMapping(t *testing.T) {
	const uri = "postgresql://svc:Kx7$mPq2@prod.internal"
	d := newDetector(t)
	plain := findType(d.Scan(uri), "db_connection_string")
	encoded := findType(d.Scan("blob="+charCodeFixture(uri, "decimal")), "db_connection_string")
	if plain == nil || encoded == nil || plain.Value != encoded.Value {
		t.Fatal("outer source mapping changed overlapping typed winner or logical identity")
	}
}

func TestQuotedConnectionURIExcludesLiteralDelimiters(t *testing.T) {
	const uri = "postgresql://svc:Kx7$mPq2@prod.internal:5432"
	d := newDetector(t)
	for _, quote := range []string{"\"", "'", "`"} {
		text := "connection=" + quote + uri + quote + ";"
		m := findType(d.Scan(text), "db_connection_string")
		if m == nil || m.Value != uri || text[m.Start:m.End] != uri {
			t.Fatalf("quoted connection URI retained its source delimiter: quote=%q match=%+v", quote, m)
		}
	}
	expr := charCodeFixture(uri, "decimal")
	m := findType(d.Scan("connection="+expr+";"), "db_connection_string")
	if m == nil || m.Value != uri {
		t.Fatal("converted URI absorbed surrounding statement syntax")
	}
}
