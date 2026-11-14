package detect

import (
	"strings"
	"testing"
)

// Prose that names a credential by its identifier is evidence for the high-entropy value after it.
func TestProseNamedSecretContext(t *testing.T) {
	d := newDetector(t)
	const value = "3NR4HvB2819W1TgfJHPAahiHUcziqUHVyJ6zICli"
	for _, text := range []string{
		"The staging awsSecretKey is " + value + " (do not use in production).",
		"Reminder to rotate the AWS_SECRET_ACCESS_KEY (" + value + ") before Friday's release.",
		"Der aktuelle encryption_key lautet " + value + " — bitte prüfen.",
		"Le app_secret actuel est " + value + ", quelqu'un peut vérifier ?",
		"Напоминание: сменить API_KEY (" + value + ") до релиза в пятницу.",
		"Set the environment variable `api_key` to `" + value + "` and restart the service.",
		"提醒：在周五发布之前轮换 secret_key（" + value + "）。",
		"3. Enter the API key " + value + ". 4. Attempt to connect.",
	} {
		found := false
		for _, m := range d.Scan(text) {
			found = found || strings.Contains(m.Value, value) || strings.Contains(value, m.Value) && len(m.Value) >= 30
		}
		if !found {
			t.Errorf("prose-named secret not reported: %s", text)
		}
	}
}

// The name must be separated from the value and must end the clause; ids, hashes and names that
// merely contain a credential word are not evidence. These are false positives seen on real code.
func TestProseNamedSecretContextRejects(t *testing.T) {
	for before, want := range map[string]bool{
		"the staging awssecretkey is ":                          true,
		"rotate the aws_secret_access_key (":                    true,
		"datadog_api_key: !secret ":                             true,
		"secrets.gpg_key_":                                      false, // the hex run continues the name
		"// https://github.com/docker/docker-credential-":       false, // a dash inside a name
		"the commit hash of the token_hash is ":                 false,
		"the client_id next to the secret_id is ":               false,
		"password_file is ":                                     false,
		"the token was rotated yesterday and the build is now ": false, // the name does not end the clause
		"{\"apikey\":\"x\",\"version\":\"1\",\"etag\":\"":       false, // an earlier property on a dense line
	} {
		if got := proseNamesSecret(before); got != want {
			t.Errorf("proseNamesSecret(%q) = %v, want %v", before, got, want)
		}
	}
	d := newDetector(t)
	for _, text := range []string{
		"\t\t\t// https://github.com/docker/docker-credential-helpers/blob/f78081d1f7fef6ad74ad6b79368de6348386e591/credentials/error.go#L4-L6",
		"uses: secrets.GPG_KEY_161DFBE342889F01DDAC4E61CBB3D576F2A0946F",
	} {
		if ms := d.Scan(text); len(ms) != 0 {
			t.Errorf("non-secret reported as %s: %s", ms[0].Type, text)
		}
	}
}

func TestProsePasswordForms(t *testing.T) {
	d := newDetector(t)
	for text, want := range map[string]string{
		"The staging db_password is Cedar286 (do not use in production).":      "Cedar286",
		"Bitte rotiere den PASSWORD (bronze$9901) vor dem Release am Freitag.": "bronze$9901",
		"Внимание: пароль сервиса — Thunder71, храните его в хранилище.":       "Thunder71",
		"リマインダー：金曜のリリース前に password（Bronze#8776）をローテーションしてください":                 "Bronze#8776",
		"The password for accessing the project is k9m$L4p2R@Z7n5. Thanks":     "k9m$L4p2R@Z7n5",
		"Ihr neues Passwort für das Konto lautet Be4QTXoTlML5.":                "Be4QTXoTlML5",
	} {
		m := findType(d.Scan(text), "generic_password")
		if m == nil || m.Value != want {
			t.Errorf("prose password: got %+v, want %q in %s", m, want, text)
		}
	}
	for _, text := range []string{
		`def login(password: str, mode: str = "oauth2flow") -> None: pass`,                     // a comma ends the clause
		"\t\tPassword: mask(\"secret123\"),",                                                   // a call, not a value
		"\t// TODO: Password should be converted to Latin-1.",                                  // sentence-final word
		"ENV EXES=\"paste patch pgrep printf ps pwd rev rm rmdir rpm rpm2cpio run-parts sed\"", // a weak word far from the cue
		"the password reset flow was moved to version2 of the api yesterday",                   // weak value, cue too far
	} {
		if m := findType(d.Scan(text), "generic_password"); m != nil {
			t.Errorf("non-password %q reported in: %s", m.Value, text)
		}
	}
}
