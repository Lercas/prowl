package detect

import (
	"strings"
	"testing"
)

func TestLiteralCredentialComparisons(t *testing.T) {
	d := newDetector(t)
	for _, c := range []struct{ text, value, name string }{
		{`if password == "Kx7#mPq2":`, "Kx7#mPq2", "password"},
		{`if cfg['password'] != 'Kx7;mP,q2':`, "Kx7;mP,q2", "password"},
		{`if (config.db_password === "Kx7;mPq2")`, "Kx7;mPq2", "db_password"},
		{"if (pwd !== `Kx7#mPq2`)", "Kx7#mPq2", "pwd"},
		{`if "Kx7;mPq2" == config.password:`, "Kx7;mPq2", "password"},
		{`if 'Kx7;mPq2' != cfg['password']:`, "Kx7;mPq2", "password"},
		{`if ("Kx7;mPq2" !== config.Password)`, "Kx7;mPq2", "password"},
		{`if password == "Kx7\"mPq2":`, `Kx7"mPq2`, "password"},
		{`if password == "Kx7\x23mPq2":`, "Kx7#mPq2", "password"},
		{`if password == "Kx7\\mPq2":`, `Kx7\mPq2`, "password"},
		{`if "Kx7\u0023mPq2" == cfg.password:`, "Kx7#mPq2", "password"},
		{`if api_key == "` + namedToken + `":`, namedToken, "api_key"},
		{`if "` + namedToken + `" == cfg['refresh_token']:`, namedToken, "refresh_token"},
		{`if key == "` + namedHex64 + `":`, namedHex64, "key"},
		{`if password == "longpassword":`, "longpassword", "password"},
		{`if db_pw == "Kx7;mPq2":`, "Kx7;mPq2", "db_pw"},
		{`if "Kx7;mPq2" == db_pw:`, "Kx7;mPq2", "db_pw"},
	} {
		ms, _ := d.namedSecrets(t.Context(), c.text, strings.ToLower(c.text), 100)
		var got *Match
		for i := range ms {
			if ms[i].Stage == stageComparison && ms[i].Value == c.value {
				got = &ms[i]
				break
			}
		}
		if got == nil || got.ContextName != c.name {
			t.Errorf("comparison value/name lost for %q: %+v", c.text, ms)
			continue
		}
		if got.Start < 0 || got.End > len(c.text) || got.End <= got.Start {
			t.Fatal("invalid source span")
		}
		if namedMatch(d.Scan(c.text), got.Type, c.value) == nil {
			t.Errorf("comparison lost in cascade for %q", c.text)
		}
	}
}

func TestLiteralComparisonExcludesMetadataAndExpressions(t *testing.T) {
	d := newDetector(t)
	for _, text := range []string{
		`if password_hash == "` + namedHex64 + `":`,
		`if password_type == "bcrypt":`, `if password_status == "active":`,
		`if password_policy == "required":`, `if password_ref == "vault01":`,
		`if compass == "Kx7;mPq2":`, `if bypass == "Kx7;mPq2":`,
		`if 'password' == 'Kx7;mPq2':`, `if ['password'] == 'Kx7;mPq2':`,
		`if public_key == "` + namedToken + `":`, `if token_id == "` + namedToken + `":`,
		`if api_key == "REPLACE_WITH_YOUR_TOKEN_12345":`,
		`if password == "${VAULT_PASSWORD}":`, `if password == "changeme":`,
		`if password == "12345678":`, `if password == true:`,
		`if password == other_password:`, `if password == get_password():`,
		`if password == f"Kx7;mPq2":`, `if r"Kx7;mPq2" == password:`,
		`if password == "Kx7;mPq2" + suffix:`, `if prefix + "Kx7;mPq2" == password:`,
		`if "Kx7;mPq2" == password_value.get():`,
		`if password ==== "Kx7;mPq2":`,
		`if password == "Kx7\nmPq2":`, `if password == "Kx7\qmPq2":`,
		`if password == "Kx7#mPq2\"trailing-without-close`,
		`if password == "Kx7;mPq2${suffix}":`,
		`if password == "Kx7;mPq2\nsecondary":`,
	} {
		ms, _ := d.namedSecrets(t.Context(), text, strings.ToLower(text), 100)
		for _, m := range ms {
			if m.Stage == stageComparison {
				t.Errorf("unexpected comparison match for %q: %+v", text, m)
			}
		}
	}
	d.genericPwd, d.genericKey = false, false
	ms, _ := d.namedSecrets(t.Context(), `password == "Kx7;mPq2"`, "", 100)
	for _, m := range ms {
		if m.Stage == stageComparison {
			t.Fatal("disabled generic taxonomy emitted comparison")
		}
	}
}

func TestComparisonRejectedCandidateLimit(t *testing.T) {
	d := newDetector(t)
	text := strings.Repeat(`password_type == "bcrypt"`+"\n", 4) + `password == "Kx7;mPq2"`
	ms, cap := d.namedSecrets(t.Context(), text, strings.ToLower(text), 3)
	if !cap || len(ms) != 0 {
		t.Fatal("rejected comparison candidates lost incomplete status")
	}
	ms, cap = d.namedSecrets(t.Context(), text, strings.ToLower(text), 10)
	if cap || len(ms) != 1 {
		t.Fatal("complete comparison walk lost credential")
	}
}

func FuzzComparisonSourceBounds(f *testing.F) {
	for _, s := range []string{`password == "Kx7#mPq2"`, `"Kx7#mPq2" != cfg['password']`, `password == "Kx7\"mPq2"`} {
		f.Add(s)
	}
	d := newDetector(f)
	f.Fuzz(func(t *testing.T, text string) {
		ms, _ := d.namedSecrets(t.Context(), text, strings.ToLower(text), 100)
		for _, m := range ms {
			if m.Start < 0 || m.End > len(text) || m.Start >= m.End {
				t.Fatal("invalid comparison span")
			}
		}
	})
}
