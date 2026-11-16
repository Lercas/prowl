package scan

import (
	"context"
	"encoding/json"
	"testing"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/model"
)

func FuzzJSONLiteralInventory(f *testing.F) {
	for _, seed := range []string{`{}`, `{"password":"Winter42!Autumn"}`, `{"key":"\u0041KIA","key":"\ud83d\ude80"}`, `{"password":"quote\"and\nnewline"}`, `["x",{"x":[]}]`, `{"bad":"\ud800"}`} {
		f.Add(seed)
	}
	for _, seed := range []string{`{"password":"Winter\u0034\u0032"}`, `"\uD83D\uDE80"`, `{"password":"\uD800"}`, `["\\u0041", {"key":"\u0041"}]`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 64<<10 {
			t.Skip()
		}
		for _, capturePublic := range []bool{false, true} {
			doc := jsonLiteralsWithPublic(context.Background(), model.Item{Path: "production.json", Text: text}, capturePublic)
			if doc == nil {
				continue
			}
			if !utf8.ValidString(doc.text) {
				t.Fatal("parser produced invalid canonical UTF-8")
			}
			for i := range doc.values {
				v := &doc.values[i]
				if v.start < 0 || v.end < v.start || v.end > len(text) || v.preparedStart < 0 || v.preparedEnd > len(doc.text) || doc.text[v.preparedStart:v.preparedEnd] != v.value {
					t.Fatal("inventory lost source or canonical bounds")
				}
				if doc.locate(v.preparedStart, v.preparedEnd) != v {
					t.Fatal("prepared source lookup selected a different literal")
				}
				var decoded string
				if err := json.Unmarshal([]byte("\""+text[v.start:v.end]+"\""), &decoded); err != nil || decoded != v.value {
					t.Fatal("canonical value does not decode from its original JSON span")
				}
				left, right := doc.sourceSpan(v, v.preparedStart, v.preparedEnd)
				if left != v.start || right != v.end {
					t.Fatal("canonical value no longer maps to its original string")
				}
				if len(v.value) > 0 && len(v.sourceStarts) != len(v.value) {
					t.Fatal("decoded-to-source map lost a byte boundary")
				}
				for at := v.preparedStart; at < v.preparedEnd; at++ {
					left, right := doc.sourceSpan(v, at, at+1)
					if left < v.start || right > v.end || right <= left {
						t.Fatal("decoded byte maps outside its original source")
					}
				}
			}
		}

	})
}
