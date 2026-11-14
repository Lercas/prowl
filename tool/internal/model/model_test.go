package model

import (
	"testing"
	"unicode/utf8"
)

func TestRedactUnicode(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"", ""},
		{"abc", "***"},
		{"abcdefgh", "********"},
		{"abcdefghi", "abcd*fghi"},
		{"秘密鍵", "***"},
		{"🔑🔒🗝", "***"},
		{"пароль12", "********"},
		{"абвгдежзий", "абвг**жзий"},
		{"abcd🔑efgh", "abcd*efgh"},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			got := Redact(tc.raw)
			if got != tc.want || !utf8.ValidString(got) {
				t.Errorf("Redact(%q) = %q, want %q with valid UTF-8", tc.raw, got, tc.want)
			}
		})
	}
}
