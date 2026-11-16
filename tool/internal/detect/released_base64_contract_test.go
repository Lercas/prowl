package detect

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

func TestBase64NoiseAndLimits(t *testing.T) {
	d := newDetector(t)
	for _, raw := range []string{
		"The release documentation describes a normal service deployment.",
		"password=Winter42!Autumn\napi_key=\x4bp9aZ2bYwcX4dWqeV8fUmgThS6iRnjQ7sL",
		"AKIAIOSFODNN7EXAMPLE",
		string([]byte{0, 0, 0, 255}) + "AKIANAFGYOEYPXU1DSYP",
	} {
		if ms := d.Scan(`payload="` + base64.StdEncoding.EncodeToString([]byte(raw)) + `"`); len(ms) != 0 {
			t.Fatalf("encoded negative control yielded %d findings", len(ms))
		}
	}
	result := d.ScanWithStatus(context.Background(), strings.Repeat("A", maxBase64Blob+1), ScanOptions{})
	if !result.Base64Limited || len(result.Matches) != 0 {
		t.Fatal("oversized blob silently truncated or decoded")
	}
	_, limited := d.base64Occurrences(context.Background(), strings.Repeat(strings.Repeat("A", 1024)+"\n", maxBase64Work/1024+1))
	if !limited {
		t.Fatal("aggregate decoding budget was not surfaced")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ms, _ := d.base64Occurrences(ctx, strings.Repeat("A", maxBase64Work)); len(ms) != 0 {
		t.Fatal("cancelled decoding continued")
	}
	// Both malformed padding and nonzero unused pad bits must be rejected.
	for _, malformed := range []string{"QUtJQU5BRkdZT0VZUFhVMURTWVA===", "QUtJQU5BRkdZT0VZUFhVMURTWVB="} {
		if _, ok := tryB64Decode(malformed); ok {
			t.Fatal("malformed/noncanonical Base64 accepted")
		}
	}
}

func TestNestedBase64DepthAndRepeatedValues(t *testing.T) {
	d := newDetector(t)
	const value = "AKIANAFGYOEYPXU1DSYP"
	for depth := 1; depth <= 4; depth++ {
		blob := value
		for i := 0; i < depth; i++ {
			blob = base64.StdEncoding.EncodeToString([]byte(blob))
		}
		text := "payload='" + blob + "'"
		result := d.ScanWithStatus(context.Background(), text, ScanOptions{})
		if result.Base64Limited || len(result.Matches) != 1 || result.Matches[0].Value != value {
			t.Fatalf("nested Base64 depth %d lost a typed value", depth)
		}
	}
	inner := base64.StdEncoding.EncodeToString([]byte("key=" + value))
	for _, decoded := range []string{"first=" + value + "\nsecond=" + value, "first='" + inner + "'\nsecond='" + inner + "'"} {
		blob := base64.StdEncoding.EncodeToString([]byte(decoded))
		ms := d.Scan("payload='" + blob + "'")
		if len(ms) != 2 || ms[0].Value != value || ms[1].Value != value || ms[0].Start == ms[1].Start {
			t.Fatal("distinct inner Base64 occurrences collapsed onto their outer blob")
		}
	}
	blob := value
	for i := 0; i < 5; i++ {
		blob = base64.StdEncoding.EncodeToString([]byte(blob))
	}
	result := d.ScanWithStatus(context.Background(), blob, ScanOptions{})
	if !result.Base64Limited || len(result.Matches) != 0 {
		t.Fatal("fifth Base64 layer could certify complete absence")
	}
}
