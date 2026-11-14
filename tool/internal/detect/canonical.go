package detect

import (
	"regexp"
	"strings"
)

// IsCanonicalPasswordPlaceholder filters known examples and whole-value placeholders without
// interpreting punctuation or mixed template-looking text as an executable substitution.
func IsCanonicalPasswordPlaceholder(v string) bool {
	low := strings.ToLower(v)
	if exampleValues[low] || IsTemplatePlaceholder(v) || reSeqRun.ReplaceAllString(low, "") == "" {
		return true
	}
	for _, word := range []string{"changeme", "change_me", "change_this", "change-this", "changethis", "placeholder", "dummy", "redacted", "example", "sample", "fake", "secret_here", "test_password", "your_password", "your_password_here", "password_here"} {
		if low == word {
			return true
		}
	}
	// Mixed ramps/filler can be an actual weak password. Only a whole filler value establishes a
	// placeholder for an explicit literal binding; generic entropy keeps its stricter heuristic.
	return low != "" && reFillerRun.ReplaceAllString(low, "") == ""
}

var encodedPasswordHash = regexp.MustCompile(`^(?:` +
	`\$2[aby]\$(?:0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}` +
	`|\$argon2(?:i|d|id)\$(?:v=[0-9]+\$)?m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]{8,128}={0,2}\$[A-Za-z0-9+/]{16,128}={0,2}` +
	`|pbkdf2_sha(?:256|512)\$[0-9]+\$[A-Za-z0-9]{8,128}\$[A-Za-z0-9+/]{16,128}={0,2}` +
	`|\$scrypt\$ln=[0-9]+,r=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]{8,128}={0,2}\$[A-Za-z0-9+/]{16,128}={0,2}` + `)$`)

// IsEncodedPasswordHash distinguishes self-describing KDF hashes from plaintext passwords. A
// hex-only configured password remains a candidate: its shape alone cannot prove it is a digest.
func IsEncodedPasswordHash(v string) bool { return encodedPasswordHash.MatchString(v) }
