package mlfeatures

import (
	"bytes"
	"strings"
	"testing"

	"github.com/klauspost/compress/flate"
)

func TestCompressionPoolResetsStreams(t *testing.T) {
	for _, value := range []string{"", "a", strings.Repeat("abcd", 4096), "Пароль123", "different-stream"} {
		t.Run(value[:min(len(value), 20)], func(t *testing.T) {
			t.Parallel()
			var expected bytes.Buffer
			w, err := flate.NewWriter(&expected, 6)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte(value)); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			for range 100 {
				if got := flateCompressedLen([]byte(value)); got != expected.Len() {
					t.Fatalf("pooled stream length %d; independent stream %d", got, expected.Len())
				}
			}
		})
	}
}

func TestFeatureExtractionDeterministic(t *testing.T) {
	value := "Aa0+/Дб123_AbCdEfGhIjKlMnOpQrStUvWxYz"
	want := Extract(value, Context{Source: "code"})
	for range 100 {
		got := Extract(value, Context{Source: "code"})
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("feature %s is not deterministic", FeatureNames[i])
			}
		}
	}
}
