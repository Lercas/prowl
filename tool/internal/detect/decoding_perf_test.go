package detect

import (
	"bytes"
	"encoding/base64"
	"math"
	"strings"
	"testing"
)

func fourDecoderReference(s string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if data, err := enc.Strict().DecodeString(s); err == nil {
			return data, true
		}
	}
	return nil, false
}

func FuzzSelectedBase64MatchesFourDecoders(f *testing.F) {
	for _, s := range []string{"", "Zg==", "Zg", "Zm8=", "AA+_", "Zg=\r\n=", "\r\n", "Zg=", "//8=", "__8", "AB==", "A\tA=="} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 8192 {
			return
		}
		want, ok := fourDecoderReference(s)
		got, gotOK := tryB64Decode(s)
		if gotOK != ok || !bytes.Equal(got, want) {
			t.Fatal("selected decoder changed strict alphabet/padding/CRLF semantics")
		}
	})
}

func FuzzASCIIEntropyMatchesRuneReference(f *testing.F) {
	for _, s := range []string{"", "abcd", "aaabbc", "密码пароль", "\xff\xfe", strings.Repeat("a", 64), "Q7mR3vK8pT2xN6cW4bY9sF5hL1aD0uGz"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 8192 {
			return
		}
		if math.Abs(ShannonEntropy(s)-runeEntropy(s)) > 1e-12 {
			t.Fatal("entropy changed rune frequencies")
		}
	})
}

func TestDecodedContextSurvivesScratchPoolReuse(t *testing.T) {
	d := newDetector(t)
	value := "AKIANAFGYOEYPXU1DSYP"
	blob := base64.RawURLEncoding.EncodeToString([]byte("access_key=" + value))
	ms, limited := d.base64Occurrences(t.Context(), blob)
	if limited || len(ms) != 1 {
		t.Fatal("fixture failed")
	}
	context := strings.Clone(ms[0].DecodedText)
	for i := 0; i < 20; i++ {
		d.Scan(strings.Repeat("ordinaryIdentifier ", 1000))
	}
	if ms[0].DecodedText != context || !strings.Contains(ms[0].DecodedText, value) {
		t.Fatal("retained decoded context aliases reusable scratch memory")
	}
}
