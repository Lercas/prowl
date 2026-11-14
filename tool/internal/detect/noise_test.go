package detect

import (
	"strings"
	"testing"
)

func TestAdjacentBindingDoesNotBorrowUnrelatedContext(t *testing.T) {
	const value = "Kp9aZ2bYwcX4dWqeV8fUmgThS6iRnjQ7sL"
	for _, text := range []string{
		`{"auth":true,"class":"` + value + `"}`,
		`const secret=null; const checksum="` + value + `";`,
		`{"public_key":"` + value + `"}`,
		`{"private_key_id":"` + value + `"}`,
	} {
		if HasSecretNameContext(text, strings.Index(text, value)) {
			t.Fatal("unrelated name supplied credential context")
		}
	}
	for _, text := range []string{
		`secret_key="` + value + `"`, `PUBLIC_API_KEY="` + value + `"`, `token_value="` + value + `"`,
		`The secret is ` + value, `Authorization: Bearer ` + value,
	} {
		if !HasSecretNameContext(text, strings.Index(text, value)) {
			t.Fatal("adjacent credential context lost")
		}
	}
}

func TestHashFilterRequiresWholeKDFEncoding(t *testing.T) {
	hash := "$2b$12$" + strings.Repeat("a", 53)
	if !IsEncodedPasswordHash(hash) {
		t.Fatal("valid bcrypt shape rejected")
	}
	for _, value := range []string{"$2b$12$short", "$argon2id$MyP4ss", "pbkdf2_sha256$MyP4ss", hash + "extra"} {
		if IsEncodedPasswordHash(value) {
			t.Fatal("hash prefix or invalid shape treated as a hash")
		}
		text := `password="` + value + `"`
		if countType(newDetector(t).Scan(text), "generic_password") == 0 {
			t.Fatal("hash-looking plaintext password suppressed")
		}
	}
}

func TestMultilingualCueUsesOriginalByteOffsets(t *testing.T) {
	for _, prefix := range []string{"Ваш ПАРОЛЬ для доступа: ", "Contraseña es ", "Sua senha é ", "Votre mot de passe est "} {
		text := prefix + "R4nd0mT3mp!"
		found := false
		for _, m := range newDetector(t).Scan(text) {
			if m.Type == "generic_password" && m.Value == "R4nd0mT3mp!" {
				if text[m.Start:m.End] != m.Value || m.Start != len(prefix) {
					t.Fatal("multilingual cue shifted the source span")
				}
				found = true
			}
		}
		if !found {
			t.Fatalf("credential prose missed for prefix %q", prefix)
		}
	}
}

func TestContextualCueCannotCrossWordsOrSentences(t *testing.T) {
	for _, text := range []string{
		"bypass routesV2", "passenger passenger2024", "passwordInput2 = field2Value",
		"Build releaseV2026 succeeded. Reset your password on the site.",
		"Password reset complete. Build releaseV2026 succeeded.",
		"password = config.credentialsV2", "password = get_password_v2()",
	} {
		if countType(newDetector(t).Scan(text), "generic_password") > 0 {
			t.Fatalf("unrelated token treated as password in %q", text)
		}
	}
}
