package domain

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestParseTargetRootsAndIdentity(t *testing.T) {
	for raw, want := range map[string][]string{
		"acme.com":                      {"https://acme.com", "https://www.acme.com"},
		"WWW.Acme.com:8080":             {"https://www.acme.com:8080"},
		"http://acme.com:8080/path?q=1": {"http://acme.com:8080"},
		"https://www.acme.com/":         {"https://www.acme.com"},
		"[::1]:8080":                    {"https://[::1]:8080"},
		"::1":                           {"https://[::1]"},
		"https://[2001:db8::1]:8443":    {"https://[2001:db8::1]:8443"},
		"https://bücher.example/":       {"https://xn--bcher-kva.example"},
		"localhost:8080":                {"https://localhost:8080"},
	} {
		got, err := ParseTarget(raw)
		if err != nil || !reflect.DeepEqual(got.roots, want) {
			t.Fatalf("%q: roots=%v error=%v", raw, got.roots, err)
		}
		again, err := ParseTarget(got.Canonical)
		if err != nil || !reflect.DeepEqual(got.roots, again.roots) || got.fallback != again.fallback {
			t.Fatalf("identity changed selection: %+v %+v error=%v", got, again, err)
		}
	}
}

func TestParseTargetRejectsAmbiguousInputsWithoutEchoingThem(t *testing.T) {
	for _, raw := range []string{"", "ftp://owned.example", "https://user:owned-password@owned.example/", "owned.example:", "owned.example:0", "owned.example:65536", "owned.example:abc", "[::1", "[owned.example]", "fe80::1%en0", "https://[fe80::1%25en0]/", "https://owned.example\noutside.example", "owned.example\\outside", "a..example", "bad\xff.example", "//outside.example"} {
		if got, err := ParseTarget(raw); err == nil || got.Canonical != "" || strings.Contains(err.Error(), "owned-password") {
			t.Fatalf("invalid input accepted or echoed: target=%+v error=%v", got, err)
		}
	}
}

func TestDiscoveryInvalidTargetMakesNoRequest(t *testing.T) {
	for _, raw := range []string{"ftp://owned.example", "https://user:owned-password@owned.example/", "owned.example:0"} {
		calls := 0
		client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			return ownedResponse(r, 200, "ordinary root"), nil
		})}
		ch, _ := Discover(context.Background(), raw, Options{Authorized: true, HTTPClient: client})
		diagnostics := 0
		for item := range ch {
			if item.Error != nil {
				diagnostics++
			}
			if strings.Contains(item.Path, "owned-password") {
				t.Fatal("invalid target credentials were serialized")
			}
		}
		if calls != 0 || diagnostics != 1 {
			t.Fatalf("calls=%d diagnostics=%d", calls, diagnostics)
		}
	}
}

func TestDiscoveryUsesExactURLAuthority(t *testing.T) {
	var calls []string
	client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.URL.String())
		return ownedResponse(r, 200, "ordinary root"), nil
	})}
	ch, reached := Discover(context.Background(), "http://[::1]:8080/path?owned-query=1", Options{Authorized: true, HTTPClient: client})
	for item := range ch {
		if item.Error != nil {
			t.Fatal(item.Error)
		}
	}
	if !reached.Load() || !reflect.DeepEqual(calls, []string{"http://[::1]:8080"}) {
		t.Fatalf("URL reinterpreted: calls=%v reached=%v", calls, reached.Load())
	}
}
