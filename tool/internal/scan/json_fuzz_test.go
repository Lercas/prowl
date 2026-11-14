package scan

import (
	"context"
	"testing"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/model"
)

func FuzzJSONLiteralInventory(f *testing.F) {
	for _, seed := range []string{`{}`, `{"password":"Winter42!Autumn"}`, `{"key":"\u0041KIA","key":"\ud83d\ude80"}`, `{"password":"quote\"and\nnewline"}`, `["x",{"x":[]}]`, `{"bad":"\ud800"}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 64<<10 {
			t.Skip()
		}
		doc := jsonLiterals(context.Background(), model.Item{Path: "production.json", Text: text})
		if doc == nil {
			return
		}
		if !utf8.ValidString(doc.text) {
			t.Fatal("parser produced invalid canonical UTF-8")
		}
		for i := range doc.values {
			v := &doc.values[i]
			if v.start < 0 || v.end < v.start || v.end > len(text) || v.preparedStart < 0 || v.preparedEnd > len(doc.text) || doc.text[v.preparedStart:v.preparedEnd] != v.value {
				t.Fatal("inventory lost source or canonical bounds")
			}
			left, right := doc.sourceSpan(v, v.preparedStart, v.preparedEnd)
			if left != v.start || right != v.end {
				t.Fatal("canonical value no longer maps to its original string")
			}
			for at := v.preparedStart; at < v.preparedEnd; at++ {
				left, right := doc.sourceSpan(v, at, at+1)
				if left < v.start || right > v.end || right <= left {
					t.Fatal("decoded byte maps outside its original source")
				}
			}
		}
	})
}
