package detect

import (
	"strings"
	"testing"
)

func oldBlobContext(text string, start int) bool {
	before := lineBefore(text, start)
	if q := strings.LastIndexAny(before, "\"'`"); q >= 0 {
		before = before[q+1:]
	} else if sep := strings.LastIndexAny(before, ";,{}"); sep >= 0 {
		before = before[sep+1:]
	}
	for _, marker := range nonSecretBlobMarkers {
		if strings.Contains(before, marker) {
			return true
		}
	}
	return false
}

func oldAuthContext(text string, start int) bool {
	before := strings.TrimRight(lineBefore(text, start), "\"' \t")
	if !strings.HasSuffix(before, ":") && !strings.HasSuffix(before, "=") {
		return false
	}
	before = strings.TrimRight(before[:len(before)-1], "\"' \t")
	if !strings.HasSuffix(before, "auth") {
		return false
	}
	rest := strings.TrimSuffix(before[:len(before)-4], "_")
	if rest == "" {
		return true
	}
	c := rest[len(rest)-1]
	return !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.')
}

func FuzzContextPredicatesPreserveOriginalLowercaseSemantics(f *testing.F) {
	for _, text := range []string{"AUTH: \"", "Kauth = '", "İNTEGRITY=", "SSH-RSA ", "data:other;token='", "\xff\xfeAUTH:", "ordinaryCodeIdentifier"} {
		f.Add(text, len(text))
	}
	f.Fuzz(func(t *testing.T, text string, start int) {
		if len(text) > 8192 {
			return
		}
		start = max(0, min(start, len(text)))
		if IsKnownNonSecretBlob(text, start) != oldBlobContext(text, start) || authKeyBefore(text, start) != oldAuthContext(text, start) {
			t.Fatal("context gate changed Unicode/boundary semantics")
		}
	})
}

func FuzzProseGateCannotRejectOriginalMatch(f *testing.F) {
	for _, text := range []string{"secret is ", "api key equals '", "the AWS_SECRET_ACCESS_KEY is ", "password lautet ", "credential: ", "ordinary prose", "token は ", "key: ", "pwd is "} {
		f.Add(text)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 8192 {
			return
		}
		if (reProseSecretContext.MatchString(text) || reProseNamedSecret.MatchString(text)) && !proseContextMatcher.Contains(text) {
			t.Fatal("literal prefilter rejected an original prose match")
		}
	})
}
