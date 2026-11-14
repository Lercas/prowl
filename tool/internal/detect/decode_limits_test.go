package detect

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/base64"
	"io"
	"strings"
	"testing"
)

func compressedFixture(t testing.TB, payload string, gzipFormat bool) []byte {
	t.Helper()
	var b bytes.Buffer
	var w io.WriteCloser
	if gzipFormat {
		w = gzip.NewWriter(&b)
	} else {
		w = zlib.NewWriter(&b)
	}
	if _, err := io.WriteString(w, payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestCompressedDecodeReportsMissingTail(t *testing.T) {
	d := newDetector(t)
	if out, _, limited := inflateStatus([]byte{0x78, 0x9c, 0xff, 0xff, 0xff, 0xff, 0xff}); len(out) != 0 || limited {
		t.Fatal("invalid data with no inflated payload must not masquerade as a truncated document")
	}
	for _, gzipFormat := range []bool{true, false} {
		for _, size := range []int{maxInflateBytes - 1, maxInflateBytes, maxInflateBytes + 1} {
			compressed := compressedFixture(t, strings.Repeat(" ", size), gzipFormat)
			out, ok, limited := inflateStatus(compressed)
			if !ok || limited != (size > maxInflateBytes) || len(out) != min(size, maxInflateBytes) {
				t.Fatalf("incorrect decompression boundary: size=%d gzip=%v got=%d ok=%v limited=%v", size, gzipFormat, len(out), ok, limited)
			}
			if size > maxInflateBytes {
				text := "blob: " + base64.StdEncoding.EncodeToString(compressed)
				_, limited := d.ScanCtxWithStatus(t.Context(), text)
				if !limited {
					t.Fatal("oversized compressed input looked complete without any findings")
				}
			}
		}
		payload := "token=" + validGithubToken() + "\n"
		good := compressedFixture(t, payload, gzipFormat)
		badCRC := bytes.Clone(good)
		badCRC[len(badCRC)-1] ^= 0x80
		for _, damaged := range [][]byte{good[:len(good)-3], badCRC} {
			text := "blob: " + base64.StdEncoding.EncodeToString(damaged)
			matches, limited := d.ScanCtxWithStatus(t.Context(), text)
			if !limited || findType(matches, "github_pat_classic") == nil {
				t.Fatal("damaged stream must retain readable findings and report uncertainty")
			}
		}
	}
}

func TestNestedDecodeFanoutReportsIncomplete(t *testing.T) {
	d := newDetector(t)
	inner := b64("ordinary unstructured printable data")
	text := "blob: " + b64(strings.Repeat(inner+" ", maxNestedBlobs)+b64(validGithubToken()))
	matches, limited := d.ScanCtxWithStatus(t.Context(), text)
	if !limited || findType(matches, "github_pat_classic") != nil {
		t.Fatal("exhausted nested budget must be visible instead of claiming a complete scan")
	}
	// The budget is shared by the recursive tree, not reset for every child.
	remaining := 1
	_, _, limited = d.bestDecodedBudget(t.Context(), b64(inner)+" "+inner, 1, &remaining)
	if !limited || remaining != 0 {
		t.Fatal("recursive decode did not share its attempt budget")
	}
}

func TestEncodedAuthReportsItsOwnCap(t *testing.T) {
	d := newDetector(t)
	text := "auth: " + b64("deploy:Tr0ub4dor&3xKq9") + "\nauth: " + b64("release:Q8rV9mP2zK5s")
	runs := scanStructure(text, 32).b64decodeRuns
	matches, limited := d.encodedBasicAuth(t.Context(), text, runs, 1)
	if len(matches) != 1 || !limited {
		t.Fatal("auth candidate cap was not reported")
	}
}

func TestViewBudgetsAndCancellation(t *testing.T) {
	d := newDetector(t)
	for _, text := range []string{
		strings.Repeat(`\"`, maxViewConstructs+1),
		strings.Repeat(strings.Repeat("a", 400)+`\x62`+strings.Repeat("c", 400), maxViewConstructs),
	} {
		v, limited := buildViewStatus(t.Context(), text)
		if v == nil || !limited || len(v.text) > maxViewBytes || len(v.start) != len(v.text) || len(v.end) != len(v.text) {
			t.Fatal("view budgets were exceeded or not reported")
		}
		_, limited = d.ScanCtxWithStatus(t.Context(), text)
		if !limited {
			t.Fatal("public scan lost the view's incomplete status")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, _ := buildViewStatus(ctx, strings.Repeat(`\"`, maxViewConstructs)); v != nil {
		t.Fatal("cancelled normalization built a view")
	}
}

func TestViewCollectCapSurvivesFiltering(t *testing.T) {
	old := maxScanMatches
	maxScanMatches = 1
	t.Cleanup(func() { maxScanMatches = old })
	text := strings.Repeat(`{\"api_key\":\"your_api_key_here_your_key\"}`+"\n", 4)
	_, limited := newDetector(t).scanViewsStatus(t.Context(), text)
	if !limited {
		t.Fatal("filtered view candidates erased collect's cap status")
	}
}

func FuzzViewBudgetBounds(f *testing.F) {
	f.Add(`{\"password\":\"Tr0ub4dor&3xKq9\"}`)
	f.Add("k: >-\n  v\n")
	f.Fuzz(func(t *testing.T, text string) {
		v, _ := buildViewStatus(t.Context(), text)
		if v == nil {
			return
		}
		if len(v.text) > maxViewBytes || len(v.start) != len(v.text) || len(v.end) != len(v.text) {
			t.Fatal("view exceeded resource or mapping bounds")
		}
		for i := range v.text {
			if v.start[i] < 0 || v.end[i] < v.start[i] || int(v.end[i]) > len(text) {
				t.Fatal("view mapping escaped source bounds")
			}
		}
	})
}

func FuzzCompressedDecodeLimits(f *testing.F) {
	f.Add(compressedFixture(f, "ordinary printable payload", true))
	f.Add(compressedFixture(f, "ordinary printable payload", false))
	f.Add([]byte{0x1f, 0x8b, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		out, _, _ := inflateStatus(data)
		if len(out) > maxInflateBytes {
			t.Fatal("decompression exceeded its output budget")
		}
	})
}
