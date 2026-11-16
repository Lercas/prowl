package detect

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func TestShortPasswordLiteralBindings(t *testing.T) {
	d := newDetector(t)
	for _, value := range []string{"r", "47", "jsfg", "aB9!", "白", "q🙂"} {
		for _, text := range []string{`password="` + value + `"`, `POSTGRES_PASSWORD='` + value + `'`, `cfg.password == "` + value + `"`, `"` + value + `" != cfg.password`, "| password | " + value + " |", "password = " + charCodeFixture(value, "spread")} {
			t.Run(fmt.Sprintf("%d/%d", len(value), len(text)), func(t *testing.T) {
				r := d.ScanWithStatus(t.Context(), text, ScanOptions{})
				found := false
				for _, m := range r.Matches {
					if m.Type == "generic_password" && m.Value == value {
						found = true
						if m.Start < 0 || m.Start >= m.End || m.End > len(text) {
							t.Fatal("short value lost source bounds")
						}
					}
				}
				if !found || r.CandidateLimited || r.Base64Limited {
					t.Fatal("short literal password lost or incomplete", text)
				}
			})
		}
		text := "POSTGRES_PASSWORD=" + value
		r := d.ScanWithStatus(t.Context(), text, ScanOptions{BarePasswordLiterals: true})
		found := false
		for _, m := range r.Matches {
			found = found || m.Type == "generic_password" && m.Value == value
		}
		if !found {
			t.Fatal("explicit bare scalar password lost")
		}
	}
}

func TestShortPasswordCanonicalScalarsPreserveValues(t *testing.T) {
	d := newDetector(t)
	for _, value := range []string{"r", "47", "白", "q🙂", "r\n", ";", "'", "\"", "\\"} {
		text := value
		r := d.ScanWithStatus(t.Context(), text, ScanOptions{PasswordScalars: map[int]PasswordScalar{0: {Name: "password", Value: value, End: len(value)}}})
		found := false
		for _, m := range r.Matches {
			if m.Type == "generic_password" && m.Value == value {
				found = true
				if m.Start != 0 || m.End != len(value) || m.ContextName != "password" {
					t.Fatal("scalar identity changed")
				}
			}
		}
		if !found {
			t.Fatal("short canonical scalar lost")
		}
		payload, _ := json.Marshal(map[string]string{"password": value})
		// Logical escaped claims are scanned as data, independently of JWT output.
		for _, m := range d.Scan(jwtFixture(string(payload))) {
			if m.Type == "generic_password" && m.Value == value && !m.JWTPayload {
				t.Fatal("short claims child lost binding isolation")
			}
		}
	}
}

func TestShortPasswordDoesNotPromoteMetadataPrimitivesOrExpressions(t *testing.T) {
	d := newDetector(t)
	for _, value := range []string{"", "abc", "ABCD", "cba", "123", "54321", "true", "TRUE", "false", "null", "None", "nil", "test", "yes", "no", "on", "off", "x", "xxx", "***", "•••", " ", "${P}", "$PW", "<pw>"} {
		for _, text := range []string{`password="` + value + `"`, `password='` + value + `'`, `password == "` + value + `"`, "| password | " + value + " |"} {
			for _, m := range d.Scan(text) {
				if m.Type == "generic_password" {
					t.Fatal("short control became a password", value)
				}
			}
		}
		r := d.ScanWithStatus(t.Context(), value, ScanOptions{PasswordScalars: map[int]PasswordScalar{0: {Name: "password", Value: value, End: len(value)}}})
		for _, m := range r.Matches {
			if m.Type == "generic_password" {
				t.Fatal("canonical short control became a password", value)
			}
		}
	}
	for _, text := range []string{`password_status="ok"`, `password_length="47"`, `password_hint="jsfg"`, `password_hash="abcd"`, `password = env()`, `password == value`, `the password is jsfg`, `api_key="jsfg"`, `token="jsfg"`} {
		for _, m := range d.Scan(text) {
			if m.Type == "generic_password" || m.Type == "generic_api_key" {
				t.Fatal("metadata, expression, prose or short key entered password path", text)
			}
		}
	}
}

func TestShortPasswordHonorsCustomMinimumAndDisabledType(t *testing.T) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	var types []taxonomy.SecretType
	for _, st := range tax.Types {
		if st.ID == "generic_password" {
			st.Detection.Regex = strings.Replace(st.Detection.Regex, "{1,64}", "{6,64}", 1)
			st.RE = regexp.MustCompile(st.Detection.Regex)
			types = append(types, st)
		}
	}
	for _, d := range []*Detector{New(&taxonomy.Taxonomy{Types: types}), New(&taxonomy.Taxonomy{})} {
		for _, text := range []string{`password="jsfg"`, `password == "jsfg"`, "| password | jsfg |"} {
			for _, m := range d.Scan(text) {
				if m.Type == "generic_password" {
					t.Fatal("custom/disabled taxonomy admitted short password")
				}
			}
		}
		r := d.ScanWithStatus(t.Context(), "jsfg", ScanOptions{PasswordScalars: map[int]PasswordScalar{0: {Name: "password", Value: "jsfg", End: 4}}})
		for _, m := range r.Matches {
			if m.Type == "generic_password" {
				t.Fatal("scalar bypassed taxonomy minimum")
			}
		}
	}
}

func FuzzShortPasswordSourceIdentity(f *testing.F) {
	for i, value := range []string{"jsfg", "47", "白", "r\n", "\"", "${P}"} {
		f.Add(value, uint8(i))
	}
	d := newDetector(f)
	f.Fuzz(func(t *testing.T, value string, mode uint8) {
		if !utf8.ValidString(value) || utf8.RuneCountInString(value) < 1 || utf8.RuneCountInString(value) > 5 {
			return
		}
		var text string
		var result ScanResult
		if mode%2 == 0 {
			text = value
			result = d.ScanWithStatus(t.Context(), text, ScanOptions{PasswordScalars: map[int]PasswordScalar{0: {Name: "password", Value: value, End: len(value)}}})
		} else {
			payload, _ := json.Marshal(map[string]string{"password": value})
			text = jwtFixture(string(payload))
			result = d.ScanWithStatus(t.Context(), text, ScanOptions{})
		}
		count := 0
		for _, m := range result.Matches {
			if m.Start < 0 || m.Start >= m.End || m.End > len(text) {
				t.Fatal("source interval escaped original input")
			}
			if m.Type == "generic_password" {
				count++
				if m.Value != value {
					t.Fatal("short password identity became a prefix or spelling")
				}
			}
			for _, step := range m.ProofSteps() {
				if step.Start < 0 || step.Start >= step.End || step.End > len(text) {
					t.Fatal("decode proof escaped original input")
				}
			}
		}
		if count > 1 {
			t.Fatal("one scalar produced duplicate password candidates")
		}
	})
}

func TestUnpairedEmphasisStarsStayInPasswordValues(t *testing.T) {
	d := newDetector(t)
	for _, value := range []string{":**0", "a:**0", "0`:", "x**:", "``:", "`a`:", " `a`:", "**a**"} {
		payload, _ := json.Marshal(map[string]string{"password": value})
		for _, text := range []string{string(payload), jwtFixture(string(payload))} {
			for _, m := range d.Scan(text) {
				if m.Type == "generic_password" && m.Value != value {
					t.Fatalf("emphasis normalization changed %q into %q", value, m.Value)
				}
			}
		}
	}
	for _, text := range []string{"**Password:** Tr0ub4dor&3xKq9\n", "**Password**: Tr0ub4dor&3xKq9\n", "`password`: Tr0ub4dor&3xKq9\n"} {
		if namedMatch(d.Scan(text), "generic_password", "Tr0ub4dor&3xKq9") == nil {
			t.Fatal("paired Markdown emphasis no longer normalized", text)
		}
	}
}
