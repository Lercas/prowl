package rules

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	bundledrules "github.com/Lercas/prowl/tool/rules"
)

func TestGCPKeyIDIsMetadataAndPrivateMaterialIsExtracted(t *testing.T) {
	eng, err := LoadEmbedded(bundledrules.Files)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		`{"type":"service_account","private_key_id":"83ea947bc2567d10a5f390c2eb468d917a3160be"}`,
		`{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----"}`,
	} {
		if len(eng.Match(text)) != 0 {
			t.Fatal("metadata/header reported as private-key credentials")
		}
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	private := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	raw, err := json.Marshal(map[string]string{"type": "service_account", "private_key_id": "83ea947bc2567d10a5f390c2eb468d917a3160be", "private_key": private})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, hit := range eng.Match(string(raw)) {
		if hit.RuleID == "gcp-service-account-private-key-id" {
			if !strings.HasPrefix(hit.Value, "-----BEGIN PRIVATE KEY-----") || !strings.HasSuffix(hit.Value, "-----END PRIVATE KEY-----") || string(raw)[hit.Start:hit.End] != hit.Value {
				t.Fatal("rule did not extract the private material with a literal source span")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("actual generated service-account private material was missed")
	}
}

func TestPublicSentryDSNAndSpotifyClientIDAreNotCredentials(t *testing.T) {
	eng, err := LoadEmbedded(bundledrules.Files)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		`SENTRY_DSN="https://83ea947bc2567d10a5f390c2eb468d91@o123.ingest.sentry.io/456"`,
		`SPOTIFY_CLIENT_ID="Kp9aZ2bYwcX4dWqeV8fUmgThS6iRnjQ7"`,
	} {
		if len(eng.Match(text)) > 0 {
			t.Fatal("public metadata reported as credentials")
		}
	}
	const private = "https://83ea947bc2567d10a5f390c2eb468d91:957db36fe0184ca76829ed034bc5af12@o123.ingest.sentry.io/456"
	for _, hit := range eng.Match(`SENTRY_DSN="` + private + `"`) {
		if hit.RuleID == "sentry-dsn" && hit.Value == private {
			return
		}
	}
	t.Fatal("legacy DSN's actual secret key was missed")
}
