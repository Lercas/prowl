package model

import (
	"strings"
	"testing"
)

func TestSafeLocatorCaseInsensitiveScheme(t *testing.T) {
	for _, raw := range []string{"HTTP://user:password@example.invalid/src.js?token=secret#frag", "//user:password@example.invalid/src.js?token=secret#frag"} {
		want := "http://example.invalid/src.js"
		if raw[:2] == "//" {
			want = "//example.invalid/src.js"
		}
		if got := SafeLocator(raw); got != want {
			t.Fatalf("URL was not sanitized: %s", got)
		}
	}
}

func TestSafeLocatorDoesNotResurrectQueryOrFragment(t *testing.T) {
	for _, suffix := range []string{"?token=hidden!/secret-value", "#hidden!/secret-value", "!/member.js?token=hidden#fragment"} {
		got := SafeLocator("https://example.invalid/bundle.js" + suffix)
		if strings.Contains(got, "hidden") || strings.Contains(got, "secret-value") || strings.Contains(got, "fragment") {
			t.Fatal("URL suffix escaped sanitization")
		}
		if SafeLocator(got) != got {
			t.Fatal("sanitization is not idempotent")
		}
	}
}
