package detect

import (
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func TestProseCredentialValuesAndSourceSpans(t *testing.T) {
	d := newDetector(t)
	const long = "Q7mR3vK8pT2xN6cW4bY9sF5hL1aD0uGz"
	const letters = "qMnRpTvKxNcWbYsFhLaDzGuE"
	const shortKey = "Q7mR3vK8pT2xN6cW4bY9"
	for _, c := range []struct{ text, value, typ, name string }{
		{"K The password is " + long + ".", long, "generic_password", ""},
		{"Your password is " + letters + ".", letters, "generic_password", ""},
		{long + " is the password", long, "generic_password", ""},
		{"Le passwd actuel est Cedar286.", "Cedar286", "generic_password", ""},
		{"Passwort - Cedar286 und weitere Angaben.", "Cedar286", "generic_password", ""},
		{"他的密码是Cedar286。", "Cedar286", "generic_password", ""},
		{"密碼：Cedar286。", "Cedar286", "generic_password", ""},
		{"パスワードはCedar286です。", "Cedar286", "generic_password", ""},
		{"The api_key used for authentication is " + long + ".", long, "generic_high_entropy", "api_key"},
		{"**API Key**: " + long, long, "generic_high_entropy", "api key"},
		{"The api_key is " + shortKey + ".", shortKey, "generic_api_key", "api_key"},
		{"Rotate deploy_token (" + shortKey + ") today.", shortKey, "generic_api_key", "deploy_token"},
	} {
		t.Run(c.text[:min(len(c.text), 20)], func(t *testing.T) {
			m := namedMatch(d.Scan(c.text), c.typ, c.value)
			if m == nil {
				t.Fatalf("missing prose candidate for type %s", c.typ)
			}
			if m.Start != strings.Index(c.text, c.value) || c.text[m.Start:m.End] != c.value || m.ContextName != c.name {
				t.Fatalf("prose evidence/label changed: %+v", m)
			}
		})
	}
}

func TestProseCredentialCannotBorrowAnUnrelatedLabel(t *testing.T) {
	d := newDetector(t)
	const value = "Q7mR3vK8pT2xN6cW4bY9"
	for _, text := range []string{
		"The api_key was rotated yesterday and the build is now " + value,
		"The api_key. An unrelated checksum is " + value,
		"The public_key is " + value,
		"The tokenId is " + value,
		"The sort_key is " + value,
		"The token_ttl is " + value,
		"The api_key used for authentication. The build is " + value,
		"Password reset complete. Build releaseV2026 succeeded.",
		"密码学讨论 Cedar286", "密码长度 Cedar286", "パスワードの長さ Cedar286",
		"Your password is ThisIsAnOrdinaryPropertyName.",
		"The password is " + strings.Repeat("a", 65) + ".",
		strings.Repeat("Q7mR3vK8", 9) + " is the password",
	} {
		if ms := d.Scan(text); len(ms) != 0 {
			t.Fatalf("unrelated context reported: %q -> %s", text, ms[0].Type)
		}
	}
}

func TestProseKeyDoesNotRequireEntropyDetectorInCustomTaxonomy(t *testing.T) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range tax.Types {
		if st.ID != "generic_api_key" {
			continue
		}
		d := New(&taxonomy.Taxonomy{Types: []taxonomy.SecretType{st}})
		const value = "Q7mR3vK8pT2xN6cW4bY9sF5hL1aD0uGz"
		m := namedMatch(d.Scan("The api_key is "+value), "generic_api_key", value)
		if m == nil || m.ContextName != "api_key" {
			t.Fatal("prose path required an unrelated taxonomy type")
		}
		if ms := d.Scan("The api_key is " + strings.Repeat("Q7mR3vK8", 26)); len(ms) != 0 {
			t.Fatal("prose key ceiling minted a partial value")
		}
		return
	}
	t.Fatal("missing fixture taxonomy type")
}

func TestProseLabelDoesNotChangeExistingAssignmentMLRecords(t *testing.T) {
	d := newDetector(t)
	const value = "Q7mR3vK8pT2xN6cW4bY9sF5hL1aD0uGz"
	for _, text := range []string{`"SessionToken": "` + value + `"`, `secret="` + value + `"`} {
		for _, m := range d.Scan(text) {
			if m.ContextName != "" {
				t.Fatal("prose path replaced existing assignment features")
			}
		}
	}
}
