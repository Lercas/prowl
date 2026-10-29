package reconstruct

import "testing"

func FuzzExtract(f *testing.F) {
	for _, seed := range []string{`const key=atob("c2VjcmV0");`, `const key=['a','b'].join('');`, "const p='key'; const x=`${p}suffix`;", `const x=unknown+'foo';`, "\x00\xff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		values, _ := Extract(text)
		if len(values) > maxResults {
			t.Fatal("result budget exceeded")
		}
		for _, v := range values {
			if v.Expression.Start < 0 || v.Expression.End > len(text) || v.Expression.Start >= v.Expression.End {
				t.Fatal("invalid expression span")
			}
			if len(v.Text) > maxValue {
				t.Fatal("value budget exceeded")
			}
			for _, s := range v.Spans {
				if s.Start < 0 || s.End > len(text) || s.Start >= s.End {
					t.Fatal("invalid source span")
				}
			}
		}
	})
}
