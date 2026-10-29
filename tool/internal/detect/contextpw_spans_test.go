package detect

import (
	"reflect"
	"strings"
	"testing"
)

func TestContextPasswordRequiresACueOutsideItsOwnToken(t *testing.T) {
	d := newDetector(t)
	for _, text := range []string{"hunter2passmenu", "entry = 'hunter2passy'", "credentials_b64", "password7Gx2", "lösenord7gh"} {
		for _, m := range d.Scan(text) {
			if m.Type == "generic_password" {
				t.Errorf("token supplied its own credential cue: text=%q match=%+v", text, m)
			}
		}
	}
}

func TestExactMatchesWinContextualOverlapIndependentOfInputOrder(t *testing.T) {
	context := Match{Type: "generic_password", Stage: "L1-context-pw", Confidence: 0.6, Start: 0, End: 24}
	regex := Match{Type: "generic_password", Stage: "L1-regex", Confidence: 0.6, Start: 12, End: 24}
	other := Match{Type: "generic_api_key", Stage: "L1-regex", Confidence: 0.6, Start: 4, End: 8}
	want := []Match{other, regex}
	for _, input := range [][]Match{{context, regex, other}, {context, other, regex}, {regex, context, other}, {regex, other, context}, {other, context, regex}, {other, regex, context}} {
		got, truncated := dedupeOverlapsCap(input, -1)
		if truncated || !reflect.DeepEqual(got, want) {
			t.Fatalf("contextual token replaced exact evidence: got=%+v truncated=%v", got, truncated)
		}
	}
}

func TestPasswordAssignmentKeepsTheExactValueAndSpan(t *testing.T) {
	d := newDetector(t)
	const value = "G7hJ9kL2"
	for _, prefix := range []string{"password=", "db_password=", "PWD=", "Password = ", "pwd : "} {
		for _, suffix := range []string{"", " // another password is required"} {
			text := prefix + value + suffix
			var passwords []Match
			for _, m := range d.Scan(text) {
				if m.Type == "generic_password" {
					passwords = append(passwords, m)
				}
			}
			start := strings.Index(text, value)
			if len(passwords) != 1 || passwords[0].Value != value || passwords[0].Start != start || passwords[0].End != start+len(value) || passwords[0].Stage != "L1-regex" {
				t.Errorf("assignment context replaced the actual password: text=%q matches=%+v", text, passwords)
			}
		}
	}
}

func TestSeparatePasswordCueStillDetectsExactProseToken(t *testing.T) {
	d := newDetector(t)
	const value = "G7hJ9kL2"
	for _, text := range []string{"Your password is " + value, "ПАРОЛЬ: " + value, "K Votre mot de passe est " + value, "CREDENTİALS " + value, value + " is the password", "password token is hunter2passmenu"} {
		want := value
		if strings.Contains(text, "hunter2passmenu") {
			want = "hunter2passmenu"
		}
		found := false
		for _, m := range d.Scan(text) {
			if m.Type == "generic_password" && m.Value == want && text[m.Start:m.End] == want {
				found = true
			}
		}
		if !found {
			t.Errorf("separate credential cue no longer detects password: %q", text)
		}
	}
}

func TestContextPasswordAssignmentsKeepValuesOutsideRegexNames(t *testing.T) {
	d := newDetector(t)
	for _, name := range []string{"credential", "passwords", "service_password_token", "lösenord", "CREDENTİALS"} {
		for _, value := range []string{"G7hJ9kL2", "G7hJ=9kL2mN5p", "hunter2passmenu"} {
			text := name + "=" + value
			found := false
			for _, m := range d.Scan(text) {
				if m.Type == "generic_password" && m.Value == value && m.Start == len(name)+1 && m.End == len(text) {
					found = true
				}
			}
			if !found {
				t.Errorf("contextual assignment lost the actual value: %q", text)
			}
		}
	}
}

func FuzzContextPasswordByteSpans(f *testing.F) {
	for _, seed := range [][]byte{{}, {0}, {1, 2, 3}, {4, 5, 0, 2}, {255, 128, 64}} {
		f.Add(seed)
	}
	d := newDetector(f)
	f.Fuzz(func(t *testing.T, seed []byte) {
		if len(seed) > 256 {
			return
		}
		var prefix strings.Builder
		for _, b := range seed {
			prefix.WriteString([]string{"K", "İ", "Ⱥ", "ǰ", "😀", "\xff"}[int(b)%6])
		}
		const value = "G7hJ9kL2"
		for _, name := range []string{"credential", "lösenord", "CREDENTİALS"} {
			text := prefix.String() + " " + name + "=" + value
			start := len(text) - len(value)
			found := false
			for _, m := range d.Scan(text) {
				if m.Type == "generic_password" && m.Value == value && m.Start == start && m.End == len(text) {
					found = true
				}
			}
			if !found {
				t.Fatalf("Unicode context changed the actual credential span: name=%s prefix-bytes=%d", name, prefix.Len())
			}
		}
	})
}
