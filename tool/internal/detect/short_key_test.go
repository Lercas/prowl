package detect

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

const shortKeyFixture = "q7Vx9mK2rP5nC8aH4zL"

func TestShortKeyExplicitBindings(t *testing.T) {
	d := newDetector(t)
	for n := 12; n < 20; n++ {
		value := shortKeyFixture[:n]
		for _, text := range []string{
			`api_key="` + value + `"`, "DEPLOY_TOKEN=" + value,
			`os.environ["API_KEY"] = "` + value + `"`,
			`cfg = {'client_secret' => '` + value + `'}`,
			`cfg.api_key == "` + value + `"`, `"` + value + `" != cfg.api_key`,
			"| api_key | " + value + " |",
			"api_key = " + charCodeFixture(value, "spread"),
		} {
			t.Run(fmt.Sprintf("%d/%d", n, len(text)), func(t *testing.T) {
				r := d.ScanWithStatus(t.Context(), text, ScanOptions{})
				m := namedMatch(r.Matches, "generic_api_key", value)
				if m == nil || m.Start < 0 || m.Start >= m.End || m.End > len(text) || r.CandidateLimited || r.Base64Limited {
					t.Fatal("explicit short key lost source identity", text)
				}
			})
		}
		body, _ := json.Marshal(map[string]string{"api_key": value})
		jwt := jwtFixture(string(body))
		found := false
		for _, m := range d.Scan(jwt) {
			if m.Type == "generic_api_key" && m.Value == value {
				found = true
				if !m.JWTPayload || m.Start < 0 || m.End > len(jwt) {
					t.Fatal("claims child lost binding isolation")
				}
			}
		}
		if !found {
			t.Fatal("short key in JWT claims lost")
		}
	}
}

func TestShortKeyPreservesNegativeBoundaries(t *testing.T) {
	d := newDetector(t)
	for _, text := range []string{
		`api_key="` + shortKeyFixture[:11] + `"`,
		`api_key="node_inventory_67"`, `api_key="aaaaaaaaaaaaaaaa"`,
		`api_key="0123456789abcdef"`, `api_key="v1.27.41123456"`,
		`key="` + shortKeyFixture[:16] + `"`,
		`public_key="` + shortKeyFixture[:16] + `"`,
		`token_hash="` + shortKeyFixture[:16] + `"`,
		`csrf_token="` + shortKeyFixture[:16] + `"`,
		`api_key_id="` + shortKeyFixture[:16] + `"`,
		`cache_key="` + shortKeyFixture[:16] + `"`,
		`api_key = tls13.NewEarlySecret`,
		`api_key = ` + shortKeyFixture[:16] + `()`,
		`api_key="${API_TOKEN_REF}"`,
		`api_key="` + shortKeyFixture[:16] + `\"suffix"`,
		`api_key="` + shortKeyFixture[:16] + `\ntrailer"`,
		`api_key="` + shortKeyFixture[:16] + `白"`,
		`the api_key is ` + shortKeyFixture[:16],
		`api_key: ` + shortKeyFixture[:16] + `/path`,
	} {
		for _, m := range d.Scan(text) {
			if m.Type == "generic_api_key" && len(m.Value) < minNamedSecret {
				t.Fatal("short noncredential/prefix nominated", text)
			}
		}
	}
}

func TestShortKeyHonorsCustomTaxonomyMinimum(t *testing.T) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	var types []taxonomy.SecretType
	for _, st := range tax.Types {
		if st.ID == "generic_api_key" {
			st.Detection.Regex = strings.Replace(st.Detection.Regex, "{12,64}", "{20,64}", 1)
			st.RE = regexp.MustCompile(st.Detection.Regex)
			types = append(types, st)
		}
	}
	for _, d := range []*Detector{New(&taxonomy.Taxonomy{Types: types}), New(&taxonomy.Taxonomy{})} {
		for _, text := range []string{`api_key="` + shortKeyFixture[:16] + `"`, `cfg.api_key == "` + shortKeyFixture[:16] + `"`, "| api_key | " + shortKeyFixture[:16] + " |"} {
			if namedMatch(d.Scan(text), "generic_api_key", shortKeyFixture[:16]) != nil {
				t.Fatal("custom minimum bypassed")
			}
		}
	}
}

func FuzzShortKeySourceIdentity(f *testing.F) {
	f.Add(shortKeyFixture[:16], uint8(0))
	f.Add(shortKeyFixture[:13], uint8(1))
	f.Add("node_inventory_67", uint8(0))
	d := newDetector(f)
	f.Fuzz(func(t *testing.T, value string, mode uint8) {
		if len(value) < 12 || len(value) >= 20 || strings.ContainsAny(value, "\"\\\r\n") {
			return
		}
		text := `api_key="` + value + `"`
		if mode%2 != 0 {
			body, _ := json.Marshal(map[string]string{"api_key": value})
			text = jwtFixture(string(body))
		}
		for _, m := range d.Scan(text) {
			if m.Start < 0 || m.Start >= m.End || m.End > len(text) {
				t.Fatal("source bounds lost")
			}
			if m.Type == "generic_api_key" && m.Value != value {
				t.Fatal("prefix identity minted")
			}
		}
	})
}
