package detect

import (
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func fuzzDetector(tb testing.TB) *Detector {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		tb.Fatal(err)
	}
	return New(tax)
}

// FuzzScan asserts the L1 detector never panics on arbitrary input and returns valid spans.
func FuzzScan(f *testing.F) {
	for _, s := range []string{
		"", "AKIA", "password=", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"\x00\xff\xfe", strings.Repeat("a", 5000), "://:@", "ey" + strings.Repeat("J", 400),
		"-----BEGIN RSA PRIVATE KEY-----", "пароль = тест", "123456789:abc",
	} {
		f.Add(s)
	}
	d := fuzzDetector(f)
	f.Fuzz(func(t *testing.T, s string) {
		_ = d.Scan(s) // must not panic; spans are validated below
		for _, m := range d.Scan(s) {
			if m.Start < 0 || m.End > len(s) || m.Start > m.End {
				t.Fatalf("invalid span [%d,%d) for len %d", m.Start, m.End, len(s))
			}
		}
	})
}

// FuzzLowerScratch proves lowerScratch is length-preserving and ASCII-lowercases every input,
// including invalid UTF-8 (which must not be expanded).
func FuzzLowerScratch(f *testing.F) {
	for _, s := range []string{"", "A", "Hello WORLD", "ПАРОЛЬ", "\xa2\x00\xff", "\x00[Z`a"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		var buf []byte
		got := lowerScratch(&buf, s)
		if len(got) != len(s) {
			t.Fatalf("length changed %d->%d for %q", len(s), len(got), s)
		}
		for i := 0; i < len(s); i++ {
			want := s[i]
			if want >= 'A' && want <= 'Z' {
				want += 32
			}
			if got[i] != want {
				t.Fatalf("byte %d: got %#x want %#x", i, got[i], want)
			}
		}
	})
}

// FuzzScanStructure asserts the combined structural scan never panics and returns valid b64 spans.
func FuzzScanStructure(f *testing.F) {
	for _, s := range []string{"", "abc:123", strings.Repeat("a.b", 40), strings.Repeat("X", 100) + "/+"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		sig := scanStructure(s, 32)
		for _, r := range sig.b64runs {
			if r[0] < 0 || r[1] > len(s) || r[0] >= r[1] || r[1]-r[0] < 32 {
				t.Fatalf("invalid b64 run %v for len %d", r, len(s))
			}
		}
	})
}
