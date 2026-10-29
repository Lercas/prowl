package detect

import (
	"context"
	"encoding/base64"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

const base64URLTestKey = "\x519xwR7tP2kN4sV6yL8mA3cE5gH1jF0dBzU2oC7vS"

func TestBase64URLFullCandidate(t *testing.T) {
	d := newDetector(t)
	for _, punctuation := range []string{"??", ">>"} {
		payload := "aws_secret" + punctuation + "=" + base64URLTestKey
		for _, encoding := range []struct {
			name string
			enc  *base64.Encoding
		}{
			{"std", base64.StdEncoding}, {"raw-std", base64.RawStdEncoding},
			{"url", base64.URLEncoding}, {"raw-url", base64.RawURLEncoding},
		} {
			for _, prefix := range []string{"secret = \"", "password is ", "😀 auth: \""} {
				t.Run(punctuation+"/"+encoding.name+"/"+prefix, func(t *testing.T) {
					blob := encoding.enc.EncodeToString([]byte(payload))
					if strings.Contains(encoding.name, "url") && !strings.ContainsAny(blob, "-_") {
						t.Fatal("fixture must exercise the URL-specific alphabet")
					}
					matches, limited := d.ScanCtxWithStatus(context.Background(), prefix+blob+"\"\n")
					var found *Match
					for i := range matches {
						if matches[i].Type == "aws_secret_access_key" && matches[i].Stage == "L1-base64" {
							found = &matches[i]
						}
					}
					if limited || found == nil {
						t.Fatalf("encoded typed secret lost: found=%v limited=%v", found != nil, limited)
					}
					if found.Value != base64URLTestKey || len(found.DecodeSpans) != 1 || found.DecodeSpans[0].Start != len(prefix) || strings.TrimRight((prefix + blob)[found.DecodeSpans[0].Start:found.DecodeSpans[0].End], "=") != strings.TrimRight(blob, "=") {
						t.Fatal("decoded key or complete outer range was truncated")
					}
				})
			}
		}
	}
}

func TestBase64URLSurvivesGenericCandidateCap(t *testing.T) {
	defer ApplyTuning(3.5, 4.2, 50000)
	ApplyTuning(3.5, 4.2, 2)
	d := newDetector(t)
	blob := base64.RawURLEncoding.EncodeToString([]byte("aws_secret??=" + base64URLTestKey))
	text := strings.Repeat("secret = \"aB3xQ9zP7mK2wL5vN8tR4yC6dF1gH0jKpQ9zP7mK\"\n", 20) + "password is " + blob
	matches, limited := d.ScanCtxWithStatus(context.Background(), text)
	if !limited || len(matches) > 2 {
		t.Fatal("global cap or incomplete status was lost")
	}
	for _, m := range matches {
		if m.Type == "aws_secret_access_key" && m.Stage == "L1-base64" && m.Value == base64URLTestKey {
			return
		}
	}
	t.Fatal("generic candidate cap starved a full Base64URL secret")
}

func TestBase64URLRetainsContextAndNonSecretFilters(t *testing.T) {
	d := newDetector(t)
	blob := base64.RawURLEncoding.EncodeToString([]byte("aws_secret??=" + base64URLTestKey))
	for _, prefix := range []string{"blob = \"", "secret = \"data:application/octet-stream;base64,", "auth ssh-rsa "} {
		for _, m := range d.Scan(prefix + blob + "\"") {
			if m.Stage == "L1-base64" {
				t.Fatalf("URL candidate bypassed a non-secret context filter: %s", prefix)
			}
		}
	}
}

func TestBase64URLProducerLimitAndCancellation(t *testing.T) {
	defer ApplyTuning(3.5, 4.2, 50000)
	ApplyTuning(3.5, 4.2, 2)
	blob := base64.RawURLEncoding.EncodeToString([]byte("aws_secret??=" + base64URLTestKey))
	for _, count := range []int{2, 3} {
		text := strings.Repeat("password is "+blob+"\n", count)
		candidates, limited := base64Candidates(context.Background(), text, scanStructure(text, 32).b64urlruns)
		if len(candidates) != 2 || limited != (count > 2) {
			t.Fatalf("URL producer did not bound eligible candidates: count=%d retained=%d limited=%v", count, len(candidates), limited)
		}
		parent, cancel := context.WithCancel(context.Background())
		cancel()
		ctx := &base64ObservedContext{Context: parent}
		candidates, limited = base64Candidates(ctx, text, scanStructure(text, 32).b64urlruns)
		if len(candidates) != 0 || limited || ctx.checks != 1 {
			t.Fatal("cancelled URL producer continued walking candidates")
		}
	}
}

func TestBase64URLOpaqueNoiseDoesNotExpandGenericSpans(t *testing.T) {
	d := newDetector(t)
	blob := "q7V5n3M1x9K2_-" + strings.Repeat("R4tN8pC6jF2bL9sV5mQ3hE7yA1dK0wZ", 3)
	text := "password is " + blob
	for _, m := range d.Scan(text) {
		if m.Stage == "L1-base64" || m.End-m.Start == len(blob) {
			t.Fatal("opaque URL noise became a decoded or new whole-blob generic finding")
		}
	}
}

func FuzzBase64URLStructure(f *testing.F) {
	for _, s := range []string{
		"", strings.Repeat("a", 31) + "_", strings.Repeat("Z", 32) + "- ",
		"prefix: " + strings.Repeat("A_", 40), "😀" + strings.Repeat("Q-", 40) + "\xff",
		strings.Repeat("a", 40) + "+" + strings.Repeat("b_", 40) + "/" + strings.Repeat("c", 40),
		"password is " + base64.RawURLEncoding.EncodeToString([]byte("aws_secret??="+base64URLTestKey)),
	} {
		f.Add(s)
	}
	d := fuzzDetector(f)
	urlRE := regexp.MustCompile(`[A-Za-z0-9_-]{32,}`)
	f.Fuzz(func(t *testing.T, text string) {
		want := scanStructure(text, 32)
		var scratch []byte
		got := d.acAndStructure(lowerScratch(&scratch, text), make([]bool, len(d.allKW)))
		if !reflect.DeepEqual(got, want) {
			t.Fatal("fused and standalone structural scans disagree")
		}
		var expected [][2]int
		for _, r := range urlRE.FindAllStringIndex(text, -1) {
			if strings.ContainsAny(text[r[0]:r[1]], "-_") {
				expected = append(expected, [2]int{r[0], r[1]})
			}
		}
		if !reflect.DeepEqual(want.b64urlruns, expected) {
			t.Fatal("URL candidates disagree with maximal alphabet runs")
		}
	})
}
