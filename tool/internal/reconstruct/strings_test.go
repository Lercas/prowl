package reconstruct

import (
	"fmt"
	"strings"
	"testing"
)

func TestConstantExpressions(t *testing.T) {
	cases := []struct{ code, want string }{
		{`const prefix="sk_live_"; const key=prefix+"Q5t7U9i2O4p6A8s0D3f5G7h9";`, "\x73k_live_Q5t7U9i2O4p6A8s0D3f5G7h9"},
		{`const key=["sk_","live_","Q5t7U9i2O4p6A8s0D3f5G7h9"].join("");`, "\x73k_live_Q5t7U9i2O4p6A8s0D3f5G7h9"},
		{"const p='sk_live_';const k=`${p}Q5t7U9i2O4p6A8s0D3f5G7h9`;", "\x73k_live_Q5t7U9i2O4p6A8s0D3f5G7h9"},
		{`const key=atob("c2tfbGl2ZV9RNXQ3VTlpMk80cDZBOHMwRDNmNUc3aDk=");`, "\x73k_live_Q5t7U9i2O4p6A8s0D3f5G7h9"},
		{`const key=decodeURIComponent("sk%5Flive%5FQ5t7U9i2O4p6A8s0D3f5G7h9");`, "\x73k_live_Q5t7U9i2O4p6A8s0D3f5G7h9"},
	}
	for _, c := range cases {
		vs, limited := Extract(c.code)
		if limited {
			t.Fatal("unexpected limit")
		}
		found := false
		for _, v := range vs {
			if v.Text == c.want {
				found = true
			}
			for _, s := range v.Spans {
				if s.Start < 0 || s.End > len(c.code) || s.Start >= s.End {
					t.Fatal("invalid span")
				}
			}
		}
		if !found {
			t.Fatalf("missing reconstructed value for %s", c.code)
		}
	}
}
func TestUnknownAndMutableBindings(t *testing.T) {
	for _, code := range []string{`const k=unknown+"fragment";`, `let p="sk_live_";const k=p+"fragment";`, `const p="sk_live_";p=unknown;const k=p+"fragment";`, `const atob=unknown; const k=atob("c2tfbGl2ZV9RNXQ3VTk=");`, `const p="sk_live_"; { const k=p+"fragment"; }`, `const k=fetch("https://example.invalid");`} {
		vs, _ := Extract(code)
		for _, v := range vs {
			if strings.HasPrefix(v.Text, "sk_live_") {
				t.Fatalf("invented value for %s", code)
			}
		}
	}
}
func TestBudgets(t *testing.T) {
	if _, limited := Extract(strings.Repeat("x/[", 10000)); !limited {
		t.Fatal("ambiguous regex lookahead has no aggregate work budget")
	}
	if _, limited := Extract(strings.Repeat("x", maxInput+1)); !limited {
		t.Fatal("input limit not signaled")
	}
	var code strings.Builder
	for i := 0; i < 600; i++ {
		fmt.Fprintf(&code, "const key%d='unique%d'+'credential';", i, i)
	}
	values, limited := Extract(code.String())
	if !limited || len(values) > maxResults {
		t.Fatal("constant assignments bypassed the result budget")
	}
}
