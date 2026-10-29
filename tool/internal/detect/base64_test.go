package detect

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

func TestIndependentBase64TypedDetectionAndSharedSpans(t *testing.T) {
	d := newDetector(t)
	values := []string{"AKIANAFGYOEYPXU1DSYP", "AKIAZ7M4Q9N2W8K5R3VX", validGithubToken()}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		for _, decoded := range []string{values[0], "first=" + values[0] + "\nsecond=" + values[1] + "\ntoken=" + values[2]} {
			blob := enc.EncodeToString([]byte(decoded))
			text := `payload="` + blob + `"`
			seen := map[string]bool{}
			for _, m := range d.Scan(text) {
				if !strings.HasPrefix(m.Stage, "L1-base64") {
					t.Fatal("neutral encoded payload produced a raw generic finding")
				}
				part, valid := tryB64Decode(text[m.Start:m.End])
				if !valid || !strings.Contains(string(part), m.Value) || len(m.DecodeSpans) != 1 || text[m.DecodeSpans[0].Start:m.DecodeSpans[0].End] != blob || m.DecodedText != decoded || decoded[m.DecodedStart:m.DecodedStart+len(m.Value)] != m.Value {
					t.Fatal("decoded finding lost the full original span or inner context")
				}
				if seen[m.Value] {
					t.Fatal("decoded value duplicated within its original source occurrence")
				}
				seen[m.Value] = true
				if m.Value == values[2] && m.Stage != "L1-base64-checksum" {
					t.Fatal("decoded checksum evidence was lost")
				}
			}
			want := 1
			if decoded != values[0] {
				want = 3
			}
			if len(seen) != want {
				t.Fatalf("expected %d distinct typed credentials in encoded payload, got %d", want, len(seen))
			}
		}
	}
}

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
	_, limited := d.unmaskBase64(context.Background(), strings.Repeat(strings.Repeat("A", 1024)+"\n", maxBase64Work/1024+1))
	if !limited {
		t.Fatal("aggregate decoding budget was not surfaced")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ms, _ := d.unmaskBase64(ctx, strings.Repeat("A", maxBase64Work)); len(ms) != 0 {
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

func FuzzBoundedBase64SourceMapping(f *testing.F) {
	d := newDetector(f)
	for _, text := range []string{"QUtJQU5BRkdZT0VZUFhVMURTWVA=", "UVV0SlFVNUJSa2RaVDBWWlVGaFZNVVSVFdWQT0=", "payload='not a credential'"} {
		f.Add(text)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 8192 {
			return
		}
		ms, _ := d.unmaskBase64(context.Background(), text)
		for _, m := range ms {
			if m.Start < 0 || m.Start >= m.End || m.End > len(text) || len(m.DecodeSpans) < 1 || len(m.DecodeSpans) > maxBase64Depth {
				t.Fatal("decoded occurrence escaped its source or depth bound")
			}
			if m.DecodedStart < 0 || m.DecodedStart+len(m.Value) > len(m.DecodedText) || m.DecodedText[m.DecodedStart:m.DecodedStart+len(m.Value)] != m.Value {
				t.Fatal("decoded identity/context do not contain the literal candidate")
			}
			for i, span := range m.DecodeSpans {
				if span.Start < 0 || span.End > len(text) || span.Start >= span.End || m.Start < span.Start || m.End > span.End {
					t.Fatal("encoding proof refers to a synthetic span")
				}
				if i > 0 && (span.Start < m.DecodeSpans[i-1].Start || span.End > m.DecodeSpans[i-1].End) {
					t.Fatal("encoding proof escaped its parent")
				}
			}
		}
	})
}
