package server

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
	"unicode/utf8"
)

type chunkedJSON struct {
	io.Reader
	size int
}

func FuzzLosslessJSONUTF8(f *testing.F) {
	for _, data := range [][]byte{nil, []byte("Пароль🚀"), {0xff}, {0xed, 0xa0, 0x80}, {0xf4, 0x90, 0x80, 0x80}} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		// Escape JSON punctuation/control bytes without normalizing raw UTF-8 like json.Marshal.
		var body strings.Builder
		body.WriteString(`{"content":"`)
		const hex = "0123456789abcdef"
		for _, b := range data {
			switch {
			case b < 0x20:
				body.WriteString(`\u00`)
				body.WriteByte(hex[b>>4])
				body.WriteByte(hex[b&15])
			case b == '\\' || b == '"':
				body.WriteByte('\\')
				body.WriteByte(b)
			default:
				body.WriteByte(b)
			}
		}
		body.WriteString(`"}`)
		encoded := body.String()
		r := &losslessJSONReader{reader: chunkedJSON{Reader: strings.NewReader(encoded), size: 1 + len(data)%23}}
		raw, err := io.ReadAll(r)
		if utf8.Valid(data) != (err == nil) || err == nil && string(raw) != encoded {
			t.Fatalf("raw transport UTF-8 validation/identity differs: %x err=%v", data, err)
		}
	})
}

func (r chunkedJSON) Read(p []byte) (int, error) {
	if len(p) > r.size {
		p = p[:r.size]
	}
	return r.Reader.Read(p)
}

func TestLosslessJSONUnicodeAcrossEveryChunkSize(t *testing.T) {
	for _, row := range []struct {
		body string
		ok   bool
	}{
		{`{"content":"Пароль🚀�"}`, true},
		{`{"content":"\ud83d\ude80"}`, true},
		{`{"content":"\uD83D\uDE80\u0000\u0041"}`, true},
		{`{"content":"\\ud800 literal \"quoted\""}`, true},
		{`{"content":"\ud800"}`, false},
		{`{"content":"\udc00"}`, false},
		{`{"content":"\ud800\u0041"}`, false},
		{`{"content":"\ud800\ud800\udc00"}`, false},
		{`{"content":"\ud800\\udc00"}`, false},
		{`{"content":"\ud800🚀"}`, false},
		{`{"content":"\ud83d\ude80\udfff"}`, false},
		{`{"content":"\ud83d\ude80\ud800"}`, false},
		{"{\"content\":\"\xff\"}", false},
		{"{\"content\":\"\xc0\xaf\"}", false},
		{"{\"content\":\"\xed\xa0\x80\"}", false},
		{"{\"content\":\"\xf4\x90\x80\x80\"}", false},
		{"{\"content\":\"\xf0\x9f", false},
	} {
		for size := 1; size <= len(row.body)+1; size++ {
			r := &losslessJSONReader{reader: chunkedJSON{Reader: strings.NewReader(row.body), size: size}}
			raw, err := io.ReadAll(r)
			if row.ok != (err == nil) || row.ok && string(raw) != row.body {
				t.Fatalf("Unicode validation/literal identity differs at chunk=%d: %q err=%v", size, row.body, err)
			}
			if row.ok && !json.Valid(raw) {
				t.Fatal("positive control is not valid JSON")
			}
		}
	}
}
