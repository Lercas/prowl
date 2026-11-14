package scan

import (
	"strings"
	"testing"
	"unicode/utf16"
)

func referenceUTF16Col(text string, off int) int {
	if off < 0 {
		off = 0
	} else if off > len(text) {
		off = len(text)
	}
	start := strings.LastIndexByte(text[:off], '\n') + 1
	column := 1
	for i, r := range text[start:] {
		if i+start >= off {
			break
		}
		column++
		if r > 0xFFFF {
			column++
		}
	}
	return column
}

func TestUTF16ColumnsMatchReference(t *testing.T) {
	for _, text := range []string{"", "ascii\nsecond", "Ключ😀\r\n🙂 e\u0301", "\xff\xfe😀\x80\nЖ", strings.Repeat("Я😀x\n", 300), strings.Repeat("界🙂", 500)} {
		index := newLineIndex(text)
		for off := -2; off <= len(text)+2; off++ {
			if got, want := index.utf16Col(off), referenceUTF16Col(text, off); got != want {
				t.Fatalf("offset %d: column=%d, reference=%d", off, got, want)
			}
		}
	}
}

func TestUTF16DenseSingleLine(t *testing.T) {
	const segment = "Ключ 😀 OWNED_G7hJ9kL2mN5p "
	const count = 5000
	text := strings.Repeat(segment, count)
	index := newLineIndex(text)
	width := len(utf16.Encode([]rune(segment)))
	start := strings.Index(segment, "OWNED_")
	prefixWidth := len(utf16.Encode([]rune(segment[:start])))
	for i := count - 1; i >= 0; i-- {
		if got, want := index.utf16Col(i*len(segment)+start), i*width+prefixWidth+1; got != want {
			t.Fatalf("match %d: column=%d, want=%d", i, got, want)
		}
	}
}

func FuzzUTF16Columns(f *testing.F) {
	f.Add("Ключ😀\r\n🙂 e\u0301", 5)
	f.Add(strings.Repeat("界🙂x", 100), 258)
	f.Add("\xff\xfe😀\x80", 4)
	f.Fuzz(func(t *testing.T, text string, off int) {
		if len(text) > 64<<10 {
			t.Skip()
		}
		index := newLineIndex(text)
		for _, pos := range []int{off, len(text), len(text) / 2, 0, -1} {
			if got, want := index.utf16Col(pos), referenceUTF16Col(text, pos); got != want {
				t.Fatalf("offset %d: column=%d, reference=%d", pos, got, want)
			}
		}
	})
}
