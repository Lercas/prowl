package detect

import (
	"context"
	"strings"
	"testing"
)

func TestTableSecrets(t *testing.T) {
	d := newDetector(t)
	for _, c := range []struct{ text, value, name string }{
		{"| Password | Kx7#mP |", "Kx7#mP", "password"},
		{"| **Пароль** | `Kx7;mP,q2'vL` |", "Kx7;mP,q2'vL", "пароль"},
		{"| db_password | {{Kx7#mPq2}} |", "Kx7#mPq2", "db_password"},
		{"| Password | 'Kx7;mP,q2' |", "Kx7;mP,q2", "password"},
		{`| Password | Kx7\|mPq2 |`, "Kx7|mPq2", "password"},
		{"| User | Password |\n| :--- | ---: |\n| service | Kx7#mP |", "Kx7#mP", "password"},
		{"User | DB Password\n--- | ---\nservice | Kx7#mPq2", "Kx7#mPq2", "db_password"},
		{"||User||Password||\n|service|Kx7#mPq2|", "Kx7#mPq2", "password"},
		{"| API key | " + namedToken + " |", namedToken, "api_key"},
		{"| Key | " + namedHex64 + " |", namedHex64, "key"},
		{"| refresh_token | host |\n| --- | --- |\n| " + namedToken + " | prod |", namedToken, "refresh_token"},
	} {
		ms, capped := d.tableSecrets(t.Context(), c.text, 100)
		if capped || len(ms) != 1 || ms[0].Value != c.value || ms[0].ContextName != c.name {
			t.Errorf("%q: unexpected table matches %+v capped=%v", c.text, ms, capped)
			continue
		}
		m := ms[0]
		if m.Start < 0 || m.End > len(c.text) || m.Start >= m.End || strings.ContainsAny(c.text[m.Start:m.End], "\n\r") {
			t.Errorf("bad source span: %+v", m)
		}
		if namedMatch(d.Scan(c.text), m.Type, c.value) == nil {
			t.Errorf("%q: whole table value lost by cascade", c.text)
		}
	}
}

func TestTableRejectsHeadersMetadataAndExpressions(t *testing.T) {
	d := newDetector(t)
	for _, text := range []string{
		"| Password | Description |\n| --- | --- |",
		"||Password||Description||",
		"| password_hash | " + namedHex64 + " |",
		"| password_policy | required |",
		"| compass | Kx7#mPq2 |", "| bypass | Kx7#mPq2 |",
		"| пароль_хеш | " + namedHex64 + " |",
		"| password | ${VAULT_PASSWORD} |",
		"| password | changeme |", "| password | 12345678 |",
		"| API key | REPLACE_WITH_YOUR_TOKEN_12345 |",
		"| public_key | " + namedToken + " |",
		"| key | " + namedToken + " |",
		"| token_id | " + namedToken + " |",
		"password | Kx7#mPq2", "flags = password | value | other",
		"| label | value |\n| --- | --- |\n| service | Kx7#mPq2 |",
	} {
		ms, cap := d.tableSecrets(t.Context(), text, 100)
		if len(ms) != 0 || cap {
			t.Errorf("%q: false table match %+v cap=%v", text, ms, cap)
		}
	}
	d.genericPwd, d.genericKey = false, false
	if ms, cap := d.tableSecrets(t.Context(), "| password | Kx7#mPq2 |", 100); len(ms) != 0 || cap {
		t.Fatal("disabled taxonomy emitted table candidates")
	}
}

func TestTableLimitsAndCancellation(t *testing.T) {
	d := newDetector(t)
	for _, text := range []string{
		strings.Repeat("| password | Kx7#mPq2 |\n", maxTableRows+1),
		"| User | Password |\n| --- | --- |\n| service | " + strings.Repeat("x", maxTableLine) + " |",
		"| password | " + strings.Repeat("x", maxTableLine) + " |",
		"| password |" + strings.Repeat(" value |", maxTableColumns+1),
		"| password | Kx7#mPq2 |\n| password | Jz8#mPq2 |",
	} {
		_, cap := d.tableSecrets(t.Context(), text, 1)
		if !cap {
			t.Errorf("table limit not surfaced for %d bytes", len(text))
		}
	}
	// Reaching the retained count is not itself evidence of an omitted candidate.
	exact := "| Password | Notes |\n| --- | --- |\n| Kx7#mPq2 | svc |\n| ${VAULT_PASSWORD} | svc |"
	if ms, capped := d.tableSecrets(t.Context(), exact, 1); capped || len(ms) != 1 {
		t.Fatal("exact candidate budget falsely marked incomplete")
	}
	// Exhaust the byte budget without hitting the row or candidate limit.
	text := "| Password | Notes |\n| --- | --- |\n" + strings.Repeat("| ${VAULT_PASSWORD} | "+strings.Repeat("x", 4000)+" |\n", 300)
	if _, cap := d.tableSecrets(t.Context(), text, 10000); !cap {
		t.Fatal("byte budget not surfaced")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, cap := d.tableSecrets(ctx, "| password | Kx7#mPq2 |", 10); !cap {
		t.Fatal("cancellation not surfaced")
	}
}

func FuzzTableSourceBounds(f *testing.F) {
	for _, s := range []string{"| password | Kx7#mPq2 |", "||Password||User||\n| Kx7#mPq2 | svc |", `| password | Kx7\|mPq2 |`} {
		f.Add(s)
	}
	d := newDetector(f)
	f.Fuzz(func(t *testing.T, text string) {
		ms, _ := d.tableSecrets(t.Context(), text, 100)
		for _, m := range ms {
			if m.Start < 0 || m.End > len(text) || m.Start >= m.End {
				t.Fatalf("invalid span: %+v", m)
			}
		}
	})
}
