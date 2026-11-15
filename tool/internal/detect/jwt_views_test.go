package detect

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func FuzzJWTPayloadObserverSourceMapping(f *testing.F) {
	for _, value := range []string{"ordinary", "quotes\"\\", "\n\t", "😀Kſ密码", "\xff"} {
		f.Add(value)
	}
	d := newDetector(f)
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 512 {
			return
		}
		payload, _ := json.Marshal(map[string]string{"note": value, "owned": jwtFixture(`{"password":"R7v!K9pX2mQ"}`)})
		// Force a JSON escape inside the nested token itself, not only adjacent data.
		payload = []byte(strings.Replace(string(payload), `"owned":"e`, `"owned":"\u0065`, 1))
		text := "note 🚀\nTOKEN=" + jwtFixture(string(payload))
		count := 0
		d.ScanWithStatus(t.Context(), text, ScanOptions{ObserveJWTPayload: func(view JWTPayloadView) {
			count++
			left, right := view.SourceSpan(0, len(view.Text))
			if left < 0 || left >= right || right > len(text) {
				t.Fatal("observer projected outside original text")
			}
			spans := view.EncodedSpans()
			if len(spans) == 0 || len(spans) > maxJWTPayloadDepth {
				t.Fatal("unbounded/missing observer proof")
			}
			for _, span := range spans {
				if span.Start < 0 || span.Start >= span.End || span.End > len(text) {
					t.Fatal("encoded proof escaped source")
				}
			}
			outer, err := base64.RawURLEncoding.Strict().DecodeString(text[spans[0].Start:spans[0].End])
			if err != nil || string(outer) != string(payload) {
				t.Fatal("outer proof does not decode to the observed source")
			}
		}})
		if count < 2 {
			t.Fatal("nested escaped observer missing")
		}
	})
}
