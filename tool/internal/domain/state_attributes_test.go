package domain

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestStateBlocksUseActualHTMLAttributes(t *testing.T) {
	const payload = `{"payload":"\u0051A_STATE_ATTRIBUTE_OWNED"}`
	const decoded = `{"payload":"QA_STATE_ATTRIBUTE_OWNED"}`
	for _, tc := range []struct{ name, markup, fragment string }{
		{"next-single-quote", `<script id='__NEXT_DATA__'>` + payload + `</script>`, "__NEXT_DATA__"},
		{"next-unquoted", `<script id=__NEXT_DATA__>` + payload + `</script>`, "__NEXT_DATA__"},
		{"next-after-nonce", `<script nonce="owned" id="__NEXT_DATA__">` + payload + `</script>`, "__NEXT_DATA__"},
		{"next-spaced-equals", `<script id = "__NEXT_DATA__">` + payload + `</script>`, "__NEXT_DATA__"},
		{"next-entity-id", `<script id="__NEXT&#95;DATA__">` + payload + `</script>`, "__NEXT_DATA__"},
		{"nuxt-single-quote", `<script id='__NUXT_DATA__'>` + payload + `</script>`, "__NUXT_DATA__"},
		{"uppercase-tag-and-attribute", `<SCRIPT ID=__NEXT_DATA__>` + payload + `</SCRIPT>`, "__NEXT_DATA__"},
		{"json-unquoted", `<script type=application/json>` + payload + `</script>`, "json-island"},
		{"json-spaced-equals", `<script type = 'application/json'>` + payload + `</script>`, "json-island"},
		{"json-parameters", `<script type='Application/JSON; charset=utf-8'>` + payload + `</script>`, "json-island"},
		{"quoted-greater-than", `<script nonce=">" type=application/json>` + payload + `</script>`, "json-island"},
		{"EOF-script", `<script id=__NEXT_DATA__>` + payload, "__NEXT_DATA__"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			items := ExtractStateBlobs(tc.markup, "https://attrs.owned.test/")
			if len(items) != 1 || items[0].Text != decoded || items[0].Path != "https://attrs.owned.test/#"+tc.fragment {
				t.Fatalf("state attributes changed or suppressed the payload: %+v", items)
			}
		})
	}
}

func BenchmarkDiscoverDenseStateDocument(b *testing.B) {
	const payload = `<script id=__NEXT_DATA__>{"payload":"\u0051A_STATE_ATTRIBUTE_OWNED"}</script>`
	markup := strings.Repeat("<br>", (maxBodyBytes-len(payload))/4) + payload
	client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
		return ownedResponse(r, 200, markup), nil
	})}
	b.ReportAllocs()
	b.SetBytes(int64(len(markup)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch, reached := Discover(context.Background(), "http://dense.owned.test:8080", Options{Authorized: true, HTTPClient: client})
		count := 0
		for item := range ch {
			if item.Error != nil {
				b.Fatal(item.Error)
			}
			count++
		}
		if !reached.Load() || count != 2 {
			b.Fatalf("dense document lost raw/state content: reached=%v items=%d", reached.Load(), count)
		}
	}
}

func TestStateBlocksIgnoreAttributeLookalikesAndDiscardedMarkup(t *testing.T) {
	const payload = `{"payload":"\u0051A_STATE_ATTRIBUTE_OWNED"}`
	for _, markup := range []string{
		`<script data-id="__NEXT_DATA__">` + payload + `</script>`,
		`<script data-type="application/json">` + payload + `</script>`,
		`<script id="other" id="__NEXT_DATA__">` + payload + `</script>`,
		`<script type="text/plain" type="application/json">` + payload + `</script>`,
		`<meta data-content="\u0051A_STATE_ATTRIBUTE_OWNED">`,
		`<meta content="short" content="\u0051A_STATE_ATTRIBUTE_OWNED">`,
		`<!-- <script type="application/json">` + payload + `</script> -->`,
		`<textarea><script type="application/json">` + payload + `</script></textarea>`,
	} {
		if got := ExtractStateBlobs(markup, "https://attrs.owned.test/"); len(got) != 0 {
			t.Fatalf("non-attributes or discarded markup became a state block: markup=%s items=%+v", markup, got)
		}
	}
}

func TestStateMetaValuesDecodeHTMLOnce(t *testing.T) {
	for _, tc := range []struct {
		markup string
		want   []string
	}{
		{`<meta content=\u0051A_STATE_ATTRIBUTE_OWNED>`, []string{"QA_STATE_ATTRIBUTE_OWNED"}},
		{`<meta value = '\u0051A_STATE_ATTRIBUTE_OWNED'>`, []string{"QA_STATE_ATTRIBUTE_OWNED"}},
		{`<meta content="&#x51;A_STATE_ATTRIBUTE_OWNED">`, []string{"QA_STATE_ATTRIBUTE_OWNED"}},
		{`<meta content="&amp;#x51;A_STATE_ATTRIBUTE_OWNED">`, []string{"&#x51;A_STATE_ATTRIBUTE_OWNED"}},
		{`<meta content="\u0051A_FIRST_ATTRIBUTE_OWNED" value="\u0051A_SECOND_ATTRIBUTE_OWNED">`, []string{"QA_FIRST_ATTRIBUTE_OWNED", "QA_SECOND_ATTRIBUTE_OWNED"}},
	} {
		items := ExtractStateBlobs(tc.markup, "https://attrs.owned.test/")
		var got []string
		for _, item := range items {
			if item.Path != "https://attrs.owned.test/#meta" {
				t.Fatalf("unexpected metadata provenance: %+v", item)
			}
			got = append(got, item.Text)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("metadata values changed: got=%q want=%q", got, tc.want)
		}
	}
}

func TestStateBlocksHandleScriptTextAndDeepFallback(t *testing.T) {
	for _, markup := range []string{
		`<script>if (1 < 2) { const secret = "\u0051A_STATE_ATTRIBUTE_OWNED"; }</script>`,
		`<svg><script><![CDATA[window.__INITIAL_STATE__ = {"payload":"\u0051A_STATE_ATTRIBUTE_OWNED"};]]></script></svg>`,
		strings.Repeat("<div>", 513) + `<script id='__NEXT_DATA__'>{"payload":"\u0051A_STATE_ATTRIBUTE_OWNED"}</script>`,
	} {
		items := ExtractStateBlobs(markup, "https://attrs.owned.test/")
		found := false
		for _, item := range items {
			found = found || strings.Contains(item.Text, "QA_STATE_ATTRIBUTE_OWNED")
		}
		if !found {
			t.Fatalf("available state text was lost: %+v", items)
		}
	}
}

func TestForeignScriptsDoNotInheritDescendantScriptText(t *testing.T) {
	markup := `<svg><script id=__NEXT_DATA__><script type=application/json>{"payload":"\u0051A_STATE_ATTRIBUTE_OWNED"}</script></script></svg>`
	items := ExtractStateBlobs(markup, "https://attrs.owned.test/")
	if len(items) != 1 || items[0].Path != "https://attrs.owned.test/#json-island" {
		t.Fatalf("descendant script text was attributed to its parent: %+v", items)
	}
}

func BenchmarkDiscoverNestedForeignStateDocument(b *testing.B) {
	const prefix = `{"payload":"\u0051A_STATE_ATTRIBUTE_OWNED","padding":"`
	const suffix = `"}`
	start := `<svg>` + strings.Repeat(`<script id=__NEXT_DATA__>`, 127) + `<script type=application/json>`
	end := strings.Repeat(`</script>`, 128) + `</svg>`
	markup := start + prefix + strings.Repeat("x", maxBodyBytes-len(start)-len(end)-len(prefix)-len(suffix)) + suffix + end
	client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
		return ownedResponse(r, 200, markup), nil
	})}
	b.ReportAllocs()
	b.SetBytes(int64(len(markup)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch, reached := Discover(context.Background(), "http://nested.owned.test:8080", Options{Authorized: true, HTTPClient: client})
		count := 0
		for item := range ch {
			if item.Error != nil {
				b.Fatal(item.Error)
			}
			if count > 0 && !strings.HasSuffix(item.Path, "#json-island") {
				b.Fatalf("descendant content was copied into an ancestor: %s", item.Path)
			}
			count++
		}
		if !reached.Load() || count != 2 {
			b.Fatalf("nested document lost raw/state content: reached=%v items=%d", reached.Load(), count)
		}
	}
}
