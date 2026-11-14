package detect

import (
	"strings"
	"testing"
)

const testBcrypt = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

func TestBcryptHashRecognition(t *testing.T) {
	for _, version := range []string{"2a", "2b", "2y"} {
		for _, cost := range []string{"04", "10", "31"} {
			value := "$" + version + "$" + cost + "$" + testBcrypt[7:]
			if !isBcryptHash(value) {
				t.Errorf("valid encoded bcrypt rejected: version=%s cost=%s", version, cost)
			}
		}
	}
	for _, value := range []string{
		"", testBcrypt[:59], testBcrypt + "x", "x" + testBcrypt,
		strings.Replace(testBcrypt, "$10$", "$00$", 1),
		strings.Replace(testBcrypt, "$10$", "$32$", 1),
		strings.Replace(testBcrypt, "$10$", "$1x$", 1),
		strings.Replace(testBcrypt, "$10$", "$-4$", 1),
		strings.Replace(testBcrypt, "$2a$", "$3a$", 1),
		strings.Replace(testBcrypt, "$2a$", "$2x$", 1),
		testBcrypt[:59] + "_", testBcrypt[:59] + "=", testBcrypt[:59] + "\xff",
		"Pr0d$Pass99",
	} {
		if isBcryptHash(value) {
			t.Error("non-bcrypt value classified as a password hash")
		}
	}
}

func TestGenericPasswordDoesNotReclassifyBcrypt(t *testing.T) {
	d := newDetector(t)
	for _, value := range []string{testBcrypt, strings.Replace(testBcrypt, "$2a$", "$2b$", 1), strings.Replace(testBcrypt, "$2a$", "$2y$", 1)} {
		for _, name := range []string{"password", "hashed_password", "password_hash"} {
			text := name + ` = "` + value + `"`
			if matches := d.Scan(text); len(matches) != 0 {
				t.Fatalf("encoded password hash yielded %d plaintext credential matches", len(matches))
			}
		}
	}
	// A bcrypt field on the same line must not suppress a different plaintext
	// password or a typed credential, including the weaker contextual path.
	for _, suffix := range []string{
		`; password="Pr0d$Pass99"`,
		`; password="` + validGithubToken() + `"`,
		`; пароль для доступа Z7mQ8rVp9tKs`,
	} {
		text := `hashed_password="` + testBcrypt + `"` + suffix
		matches := d.Scan(text)
		if len(matches) == 0 {
			t.Fatal("neighboring credential suppressed by bcrypt field")
		}
		for _, m := range matches {
			if m.Value == testBcrypt {
				t.Fatal("password hash survived beside a real credential")
			}
		}
	}
	// An arbitrary password that only resembles part of the format remains a
	// candidate. The filter requires the complete value and valid cost/alphabet.
	for _, value := range []string{testBcrypt + "x", "Pr0d$Pass99", "$2a$10$NotAHash9", strings.Replace(testBcrypt, "$10$", "$32$", 1)} {
		matches := d.Scan(`password="` + value + `"`)
		found := false
		for _, m := range matches {
			found = found || m.Type == "generic_password" && m.Value == value
		}
		if !found {
			t.Fatal("non-hash password was lost")
		}
	}
}
