package detect

import (
	"bytes"
	"encoding/base64"
	"math/rand"
	"strings"
	"testing"
)

const (
	namedHex64 = "3ec85be3ad56e8b3701f709d6d4829a992c264344fca1907bb6ee93063b51012"
	namedToken = "uYPIcjDG4DmisHIv80lPq7Zx"
)

func namedMatch(ms []Match, typ, value string) *Match {
	for i := range ms {
		if ms[i].Type == typ && ms[i].Value == value {
			return &ms[i]
		}
	}
	return nil
}

func TestNamedKeyForms(t *testing.T) {
	d := newDetector(t)
	for _, text := range []string{
		"SECRET_KEY=" + namedHex64 + "\n",
		`encryption_key: "` + namedHex64 + `"` + "\n",
		"Key = " + namedHex64 + "\n",
		"PRIVATE_KEY=0x" + namedHex64 + "\n",
		`os.environ["API_KEY"] = "` + namedToken + `"` + "\n",
		`process.env['DEPLOY_TOKEN'] = '` + namedToken + `';` + "\n",
		`return ['api_key' => '` + namedToken + `'];` + "\n",
		`config = { :client_secret => "` + namedToken + `" }` + "\n",
		"export DEPLOY_TOKEN=" + namedToken + "\n",
		"Use the API key: " + namedToken + " for requests.\n",
		`{"service_credential": "` + namedToken + `"}` + "\n",
		`{"refresh_token": "` + namedToken + `"}` + "\n",
		"ENVIRONMENT_SECRET=" + namedToken + "\n",
		"challenge_token: " + namedToken + "\n",
		"token := `" + namedToken + "`\n",
	} {
		want := namedToken
		switch {
		case strings.Contains(text, "0x"+namedHex64):
			want = "0x" + namedHex64
		case strings.Contains(text, namedHex64):
			want = namedHex64
		}
		m := namedMatch(d.Scan(text), "generic_api_key", want)
		if m == nil {
			t.Errorf("%q: named secret not reported", text)
			continue
		}
		if text[m.Start:m.End] != want {
			t.Errorf("%q: span %q is not the value", text, text[m.Start:m.End])
		}
	}
}

func TestNamedKeyRejectsNonSecrets(t *testing.T) {
	d := newDetector(t)
	for _, text := range []string{
		// the name describes a secret instead of holding one
		"token_hash=" + namedHex64 + "\n",
		"sha256 = " + namedHex64 + "\nchecksum: " + namedHex64 + "\n",
		`"private_key_id": "b16c4419bb8c911868a9b55c26a50ea1"` + "\n",
		"public_key: " + namedToken + "\n",
		"secretName: " + namedToken + "\n",
		"secretRef: " + namedToken + "\n",
		"secret_ref: " + namedToken + "\n",
		"tokenId: " + namedToken + "\n",
		"api_key_id: " + namedToken + "\n",
		"token_ttl: " + namedToken + "\n",
		"csrf_token=" + namedToken + "\n",
		"next_page_token: " + namedToken + "\n",
		// a key that is not a credential
		`cache_key = "3DDGpTjDV9QPhqGHKf7qXmL9iyvaK6mx"` + "\n",
		"sort_key: " + namedToken + "\n",
		// a bare `key` vouches only for hex key material
		"key: " + namedToken + "\n",
		// values that are not generated material
		"Key = FBFBFBFBFBFBFBFBFBFBFBFBFBFBFBFBFBFBFBFBFBFBFBFBFBFBFBFBFBFBFBFB\n",
		"api_secret: node_inventory_prod_67_east\n",
		"PeerKey=BOB_cf_wap-wsg-idm-ecid-wtls11_PUB\n",
		"deploy_token: 03d71787-6df8-4c33-bde6-9e2bf9f21e51\n",
		"api_token = REPLACE_WITH_YOUR_TOKEN_12345\n",
		"auth_token: ${DEPLOY_TOKEN_FROM_VAULT_01}\n",
		"token_endpoint_secret = https://login.example.com/oauth2/v2/token\n",
		// expressions, not literals
		"earlySecret = tls13.NewEarlySecret(cipherSuite.hash.New, session.secret)\n",
		"privKey.PrivateKey = MarshalPKCS1PrivateKey(k)\n",
		"testClientRSA2048Key = testClientRSA2048Cert.PrivateKey.(*rsa.PrivateKey)\n",
		"privateKey = jwtTestEC256PrivateKey\n",
		"apiSecret := defaultClientSecret2024Value\n",
	} {
		for _, m := range d.Scan(text) {
			if m.Stage == stageContextKey {
				t.Errorf("%q: reported %s %q", text, m.Type, m.Value)
			}
		}
	}
}

func TestBasicSchemeInCode(t *testing.T) {
	d := newDetector(t)
	pair := base64.StdEncoding.EncodeToString([]byte("svc:Kx7#mPq2vL"))
	for _, text := range []string{
		`headers: { Authorization: "Basic ` + pair + `" }` + "\n",
		`'Authorization' => 'Basic ` + pair + `',` + "\n",
		`req.Header.Set("Authorization", "Basic ` + pair + `")` + "\n",
		"curl -H 'Authorization: Basic " + pair + "' https://api.example.com\n",
	} {
		m := namedMatch(d.Scan(text), "basic_auth_header", pair)
		if m == nil || m.Confidence < 0.9 {
			t.Errorf("%q: decoded Basic credentials not reported at full confidence", text)
		}
	}
	for _, text := range []string{
		"Basic " + base64.StdEncoding.EncodeToString([]byte("just some words here")) + "\n", // no user:password
		"Basic " + base64.StdEncoding.EncodeToString([]byte("user:changeme")) + "\n",        // placeholder
		"a basic introduction to cryptography\n",
	} {
		for _, m := range d.Scan(text) {
			if m.Type == "basic_auth_header" && m.Stage == "L1-base64" {
				t.Errorf("%q: reported as Basic credentials", text)
			}
		}
	}
}

func TestQuotedPasswordWithSeparators(t *testing.T) {
	d := newDetector(t)
	for _, c := range []struct{ text, value string }{
		{`password = "Kx7;mP,q2'vL"` + "\n", `Kx7;mP,q2'vL`},
		{`DB_PASSWORD: 'p4ss;w0rd,"x"'` + "\n", `p4ss;w0rd,"x"`},
		{`$cfg['passwd'] = "a1;b2,c3;d4";` + "\n", "a1;b2,c3;d4"},
	} {
		if namedMatch(d.Scan(c.text), "generic_password", c.value) == nil {
			t.Errorf("%q: the whole quoted password was not reported", c.text)
		}
	}
	for _, text := range []string{
		`password = "func(a, b);"` + "\n",
		`password_rules = "min:8,max:64;required"` + "\n",
		`password: "<enter;your,password1>"` + "\n",
	} {
		for _, m := range d.Scan(text) {
			if m.Type == "generic_password" && strings.ContainsAny(m.Value, ",;") {
				t.Errorf("%q: reported %q", text, m.Value)
			}
		}
	}
}

func TestClassSwitchRateSeparatesIdentifiers(t *testing.T) {
	for _, id := range []string{"testRSAPrivateKey", "encapsulationKey1024", "defaultSigningSecret", "handshakeTrafficSecret"} {
		if r := classSwitchRate(id); r >= minClassSwitchRate {
			t.Errorf("identifier %s has switch rate %.2f, not below %.2f", id, r, minClassSwitchRate)
		}
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	r := rand.New(rand.NewSource(1))
	low := 0
	for i := 0; i < 2000; i++ {
		b := make([]byte, 24)
		for j := range b {
			b[j] = alphabet[r.Intn(len(alphabet))]
		}
		if classSwitchRate(string(b)) < minClassSwitchRate {
			low++
		}
	}
	if low > 20 { // 1%
		t.Errorf("%d of 2000 random base62 tokens fall below the identifier threshold", low)
	}
}

// Chance headers must not manufacture decoded secrets. A nonempty damaged
// prefix may still be ambiguous, so this test does not require a complete scan.
func TestChanceCompressionHeadersDoNotCreateDecodedSecrets(t *testing.T) {
	d := newDetector(t)
	r := rand.New(rand.NewSource(7))
	var text bytes.Buffer
	for i := 0; i < 4000; i++ {
		raw := make([]byte, 57)
		_, _ = r.Read(raw)
		raw[0], raw[1] = 0x78, 0x9c // zlib header followed by noise
		text.WriteString(base64.StdEncoding.EncodeToString(raw))
		text.WriteByte('\n')
	}
	ms, _ := d.ScanCtxWithStatus(t.Context(), text.String())
	for _, m := range ms {
		if m.Stage == "L1-base64" {
			t.Fatalf("noise behind a chance compression header became a decoded finding: %s", m.Type)
		}
	}
}
