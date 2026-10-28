package detect

import (
	"encoding/base64"
	"testing"
)

func TestJWTStructureRequiresJOSEHeaderAndClaimsObject(t *testing.T) {
	for _, c := range []struct {
		header, claims, signature string
		valid                     bool
	}{
		{`{"alg":"HS256"}`, `{"sub":"local-synthetic-account"}`, "c2lnbmF0dXJl", true},
		{`{"alg":"none"}`, `{"sub":"local-synthetic-account"}`, "", true},
		{`{"nested":{"alg":"HS256"}}`, `{"sub":"local-synthetic-account"}`, "c2lnbmF0dXJl", false},
		{`{"alg":true}`, `{"sub":"local-synthetic-account"}`, "c2lnbmF0dXJl", false},
		{`{"alg":""}`, `{"sub":"local-synthetic-account"}`, "c2lnbmF0dXJl", false},
		{`{"alg":`, `{"sub":"local-synthetic-account"}`, "c2lnbmF0dXJl", false},
		{`{"alg":"HS256"}`, `{"not valid JSON`, "c2lnbmF0dXJl", false},
		{`{"alg":"HS256"}`, `[]`, "c2lnbmF0dXJl", false},
		{`{"alg":"HS256"}`, `null`, "c2lnbmF0dXJl", false},
		{`{"alg":"HS256"}`, `{"sub":"local-synthetic-account"}`, "s", false},
		{`{"alg":"HS256"}`, `{"sub":"local-synthetic-account"}`, "dozjgNryP4Jq3mNHl9wYZ", false},
		{`{"alg":"HS256"}`, `{"sub":"local-synthetic-account"}`, "", false},
		{`{"alg":"none"}`, `{"sub":"local-synthetic-account"}`, "c2lnbmF0dXJl", false},
	} {
		token := base64.RawURLEncoding.EncodeToString([]byte(c.header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(c.claims)) + "." + c.signature
		if JWTStructuralOK(token) != c.valid {
			t.Fatalf("JWT structural boundary changed: header=%s claims=%s", c.header, c.claims)
		}
		if checked, valid := checksumValid("jwt", token); checked || valid {
			t.Fatal("JWT structure was presented as checksum proof")
		}
	}
}

func TestJWTCandidateCarriesStructureRatherThanChecksumStage(t *testing.T) {
	const token = "\x65yJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmNkZWZnIn0.dozjgNryP4Jq3mNHl9wYZQ"
	ms := newDetector(t).Scan(token)
	if len(ms) != 1 || ms[0].Type != "jwt" || ms[0].Stage != "L1-structure" || ms[0].ChecksumValid || ms[0].Confidence >= .99 {
		t.Fatal("JWT candidate overstated its structural evidence")
	}
}
