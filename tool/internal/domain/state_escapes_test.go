package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStateEscapesDecodeOneLayer(t *testing.T) {
	for _, tc := range []struct{ name, source, want string }{
		{"literal-unicode-escape", `\\u0051`, `\u0051`},
		{"escaped-backslash-before-unicode", `\\\u0051`, `\Q`},
		{"decoded-backslash-not-reparsed", `\u005cu0051`, `\u0051`},
		{"literal-slash-escape", `\\/`, `\/`},
		{"hex", `\x51A`, "QA"},
		{"braced-unicode", `\u{51}A`, "QA"},
		{"leading-zeroes", `\u{000000000051}A`, "QA"},
		{"surrogate-pair", `\uD83D\uDD10`, "🔐"},
		{"braced-surrogate-pair", `\u{D83D}\u{DD10}`, "🔐"},
		{"mixed-surrogate-pair", `\uD83D\u{DD10}`, "🔐"},
		{"code-point", `\u{1F510}`, "🔐"},
		{"max-code-point", `\u{10FFFF}`, "\U0010ffff"},
		{"controls", `\b\f\n\r\t\v\0`, "\b\f\n\r\t\v\x00"},
		{"quotes", `\'\"\\`, "'\"\\"},
		{"LF-continuation", "QA\\\n_STATE", "QA_STATE"},
		{"CRLF-continuation", "QA\\\r\n_STATE", "QA_STATE"},
		{"CR-continuation", "QA\\\r_STATE", "QA_STATE"},
		{"LS-continuation", "QA\\\u2028_STATE", "QA_STATE"},
		{"PS-continuation", "QA\\\u2029_STATE", "QA_STATE"},
		{"HTML-entities", `a&amp;b&#x2f;c`, "a&b/c"},
		{"HTML-entity-escape", `&#92;u0051`, "Q"},
		{"unpaired-high", `\uD83Dx`, `\uD83Dx`},
		{"unpaired-low", `\uDD10`, `\uDD10`},
		{"braced-surrogate", `\u{D800}`, `\u{D800}`},
		{"wrong-pair", `\uD800\u0041`, `\uD800A`},
		{"empty-code-point", `\u{}`, `\u{}`},
		{"too-large-code-point", `\u{110000}`, `\u{110000}`},
		{"overflow-code-point", `\u{FFFFFFFFFFFFFFFFFF}`, `\u{FFFFFFFFFFFFFFFFFF}`},
		{"invalid-hex", `\xQ1`, `\xQ1`},
		{"short-hex", `\x1`, `\x1`},
		{"invalid-unicode", `\u00Q1`, `\u00Q1`},
		{"unterminated-code-point", `\u{0051`, `\u{0051`},
		{"unsupported-escape", `\z`, `\z`},
		{"unsupported-octal", `\012`, `\012`},
		{"trailing-backslash", `trailing\`, `trailing\`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decodeEscapes(tc.source); got != tc.want {
				t.Fatalf("escape decoding changed the value: got=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestStateEscapesMatchJSONValues(t *testing.T) {
	values := []string{"plain value", "quotes: \"'", "literal: \\u0051", "literal: \\/", "🔐", "\x00\b\t\n\f\r", "slash /", "line\u2028separator\u2029"}
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if got := decodeEscapes(string(encoded[1 : len(encoded)-1])); got != value {
			t.Fatalf("JSON string changed: input=%s got=%q want=%q", encoded, got, value)
		}
	}
	// Exercise escape parity independently of the decoder's implementation.
	for n := 0; n < 65; n++ {
		for _, suffix := range []string{"u0051", "uD83D\\uDD10", "/", "\"", "n", "x51"} {
			value := strings.Repeat("\\", n) + suffix
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			var want string
			if err := json.Unmarshal(encoded, &want); err != nil {
				t.Fatal(err)
			}
			if got := decodeEscapes(string(encoded[1 : len(encoded)-1])); got != want {
				t.Fatalf("JSON escape parity changed: input=%s got=%q want=%q", encoded, got, want)
			}
		}
	}
}

func TestStateEscapesMalformedBracesPreserveTheRemainingSource(t *testing.T) {
	for _, source := range []string{
		strings.Repeat(`\u{`, 8192),
		`\u{` + strings.Repeat("0", 8192),
		strings.Repeat(`\u{not-hex}`, 8192),
	} {
		if got := decodeEscapes(source); got != source {
			t.Fatal("malformed code points changed the remaining source")
		}
	}
}

func BenchmarkStateEscapesMalformedBraces(b *testing.B) {
	source := strings.Repeat(`\u{`, maxBodyBytes/3)
	b.ReportAllocs()
	b.SetBytes(int64(len(source)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := decodeEscapes(source); got != source {
			b.Fatal("malformed code points changed the source")
		}
	}
}

func FuzzStateEscapesJSONRoundTrip(f *testing.F) {
	for _, seed := range []string{"plain", "literal \\u0051", "literal \\/", "🔐", "\x00\b\t\n\f\r", "&amp;", "\"'\\", "\u2028\u2029", string([]byte{0xff, 0xfe})} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 64*1024 {
			t.Skip()
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var want string
		if err := json.Unmarshal(encoded, &want); err != nil {
			t.Fatal(err)
		}
		if got := decodeEscapes(string(encoded[1 : len(encoded)-1])); got != want {
			t.Fatalf("JSON string changed: input=%s got=%q want=%q", encoded, got, want)
		}
	})
}
