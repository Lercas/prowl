package reconstruct

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const bindingKey = "13ad45b4d0a2f6ea65ecbddf6aa260f2"

func TestObjectBindingSourceIdentity(t *testing.T) {
	for _, source := range []string{
		`const c={app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE"};`,
		`const c={"app_id":'ABCDEF1234',"algolia_api_key":'SECRET_VALUE'};`,
		"const c={app_id:`ABCDEF1234`,algolia_api_key:`SECRET_VALUE`};",
		`const c={app_id:("ABCDE"+"F1234"),algolia_api_key:"SECRET_VALUE"};`,
		`const c={app_id:"\u0041BCDEF1234",algolia_api_key:"SECRET_VALUE",enabled:true,other:unknown};`,
		`const c={"\u0061pp_id":"ABCDEF1234",algolia_api_key:"SECRET_VALUE"};`,
		`// до значения — Unicode byte offsets
const c={app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE"};`,
		`const c={nested:{app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE"}};`,
		`const c=[{app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE"}];`,
		`function f(){return {app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE"};}`,
		`const f=()=>({app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE"});`,
		`class C {config={app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE"};}`,
		`const c={app_id:/* owned */"ABCDEF1234",algolia_api_key:"SECRET_VALUE",};`,
		`const ALGOLIA_APP_ID="ABCDEF1234",ALGOLIA_API_KEY="SECRET_VALUE";`,
		`export default {app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE"};`,
		`import x from "https://unreachable.invalid/module.js"; export const c={app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE"};`,
		`with ({}) {const c={app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE"};}`, // Script fallback; never executed.
	} {
		text := strings.ReplaceAll(source, "SECRET_VALUE", bindingKey)
		t.Run(source[:min(24, len(source))], func(t *testing.T) {
			start := strings.Index(text, bindingKey)
			bindings := ParseObjectBindings(t.Context(), text)
			got := bindings.ForSpan(start, start+len(bindingKey), bindingKey)
			if got["app_id"] != "ABCDEF1234" && got["ALGOLIA_APP_ID"] != "ABCDEF1234" {
				t.Fatal("lost exact static group", got)
			}
			got["app_id"] = "mutated"
			again := bindings.ForSpan(start, start+len(bindingKey), bindingKey)
			if again["app_id"] == "mutated" {
				t.Fatal("caller mutated retained bindings")
			}
			if bindings.ForSpan(start, start+len(bindingKey), "other") != nil {
				t.Fatal("substring or foreign value was bound")
			}
		})
	}
}

func TestObjectBindingsRejectAmbiguousAndNonCodeOccurrences(t *testing.T) {
	for _, source := range []string{
		`const c={app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE",...other};`,
		`const c={...other,app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE"};`,
		`const c={app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE",[name]:"override"};`,
		`const c={app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE",get other(){return 0;}};`,
		`const c={app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE",method(){}};`,
		`const c={app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE",app_id:"ZZZZZZ9999"};`,
		`const c={"app_id":"ABCDEF1234",algolia_api_key:"SECRET_VALUE","\u0061pp_id":"ABCDEF1234"};`,
		`// const c={app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE"};`,
		`/* const c={app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE"}; */`,
		`const c="{app_id:'ABCDEF1234',algolia_api_key:'SECRET_VALUE'}";`,
		"const c=`{app_id:'ABCDEF1234',algolia_api_key:'SECRET_VALUE'}`;",
		`const c=/{app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE"}/;`,
		`const c={app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE"}; /*unterminated`,
		`const c={app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE"}; invalid syntax`,
		`type C={app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE"};`,
		`const c=<div>{app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE"}</div>;`,
		`const c={app_id:"ABCDEF1234",algolia_api_key:"SECRET_VALUE"+"suffix"};`,
		`const c={app_id:"ABCDEF1234","algolia_api_key_SECRET_VALUE":"unrelated"};`,
		`const c={app_id:"ABCDEF1234",algolia_api_key:tag("SECRET_VALUE")};`,
	} {
		text := strings.ReplaceAll(source, "SECRET_VALUE", bindingKey)
		t.Run(source[:min(24, len(source))], func(t *testing.T) {
			start := strings.Index(text, bindingKey)
			got := ParseObjectBindings(t.Context(), text).ForSpan(start, start+len(bindingKey), bindingKey)
			if got != nil {
				t.Fatal("unsafe occurrence acquired bindings", got)
			}
		})
	}
}

func TestObjectBindingDoesNotBorrowCompanions(t *testing.T) {
	text := `const a={app_id:"ABCDEF1234",algolia_api_key:"` + bindingKey + `"},b={app_id:"ZZZZZZ9999",algolia_api_key:"` + bindingKey + `"};`
	b := ParseObjectBindings(t.Context(), text)
	first, last := strings.Index(text, bindingKey), strings.LastIndex(text, bindingKey)
	if got := b.ForSpan(first, first+len(bindingKey), bindingKey); got["app_id"] != "ABCDEF1234" {
		t.Fatal(got)
	}
	if got := b.ForSpan(last, last+len(bindingKey), bindingKey); got["app_id"] != "ZZZZZZ9999" {
		t.Fatal(got)
	}
	for _, source := range []string{
		`const c={app_id:"ABCDEF1234",nested:{algolia_api_key:"SECRET_VALUE"}};`,
		`const c={app_id:"ABCDEF1234"},d={algolia_api_key:"SECRET_VALUE"};`,
		`const app_id="ABCDEF1234"; const algolia_api_key="SECRET_VALUE";`,
	} {
		text := strings.ReplaceAll(source, "SECRET_VALUE", bindingKey)
		start := strings.Index(text, bindingKey)
		got := ParseObjectBindings(t.Context(), text).ForSpan(start, start+len(bindingKey), bindingKey)
		if got["app_id"] != "" {
			t.Fatal("borrowed parent/sibling/declaration companion", got)
		}
	}
	for _, value := range []string{"unknown", "getID()", "`ABC${part}1234`", "tag`ABCDEF1234`"} {
		text := `const c={app_id:` + value + `,application_id:"ABCDEF1234",algolia_api_key:"` + bindingKey + `"};`
		start := strings.Index(text, bindingKey)
		got := ParseObjectBindings(t.Context(), text).ForSpan(start, start+len(bindingKey), bindingKey)
		if got == nil {
			t.Fatal("fixture did not retain explicit unknown alias")
		}
		if v, ok := got["app_id"]; !ok || v != "" {
			t.Fatal("unknown alias disappeared or was evaluated", got)
		}
	}
}

func TestObjectBindingBudgetsAndSourceMapIsolation(t *testing.T) {
	text := `const c={app_id:"ABCDEF1234",algolia_api_key:"` + bindingKey + `"};`
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if ParseObjectBindings(ctx, text) != nil || ParseObjectBindings(t.Context(), strings.Repeat(" ", maxInput+1)) != nil || ParseObjectBindings(t.Context(), text+"\xff") != nil {
		t.Fatal("invalid source or canceled budget accepted")
	}
	deep := "const c=" + strings.Repeat("[", 200) + `{app_id:"ABCDEF1234",algolia_api_key:"` + bindingKey + `"}` + strings.Repeat("]", 200) + ";"
	if ParseObjectBindings(t.Context(), deep) != nil {
		t.Fatal("invalid deeply nested source accepted")
	}
	many := strings.Repeat(`({name:"value"});`, maxBindingGroups+1) + text
	if ParseObjectBindings(t.Context(), many) != nil {
		t.Fatal("group budget exceeded")
	}
	for _, number := range []string{strings.Repeat("9", maxBindingNumericAtom+1) + "n", "0x" + strings.Repeat("f", maxBindingNumericAtom) + "n", strings.Repeat("9_", maxBindingNumericAtom) + "9n"} {
		if ParseObjectBindings(t.Context(), "const large="+number+";"+text) != nil {
			t.Fatal("oversized numeric conversion reached parser")
		}
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "must not load source maps", 500)
	}))
	defer server.Close()
	withMap := text + "\n//# sourceMappingURL=" + server.URL + "/map.json"
	start := strings.Index(withMap, bindingKey)
	if got := ParseObjectBindings(t.Context(), withMap).ForSpan(start, start+len(bindingKey), bindingKey); got["app_id"] != "ABCDEF1234" || calls.Load() != 0 {
		t.Fatal("parser performed source-map I/O")
	}
}

func FuzzObjectBindings(f *testing.F) {
	for _, seed := range []string{`const c={app_id:"ABCDEF1234",algolia_api_key:"` + bindingKey + `"};`, `export default {nested:{key:"owned"}};`, `const c={...source};`, `const r=/{key:'value'}/;`, "\x00\xff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		bindings := ParseObjectBindings(t.Context(), text)
		if bindings == nil {
			return
		}
		if len(bindings.scalars) > maxBindingFields {
			t.Fatal("unbounded bindings")
		}
		for _, scalar := range bindings.scalars {
			if scalar.span.Start < 0 || scalar.span.End > len(text) || scalar.span.Start >= scalar.span.End || len(scalar.fields) > 128 || len(scalar.value) > maxValue {
				t.Fatal("invalid binding bounds")
			}
		}
	})
}
