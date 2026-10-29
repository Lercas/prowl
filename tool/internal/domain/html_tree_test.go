package domain

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestExtractAssetsUsesDocumentTree(t *testing.T) {
	for _, tc := range []struct {
		name, markup, path string
	}{
		{"svg-base", `<svg><base href="/ignored/"/></svg><script src="app.js"></script>`, "/app.js"},
		{"math-base", `<math><base href="/ignored/"/></math><script src="app.js"></script>`, "/app.js"},
		{"select-base", `<select><base href="/ignored/"></select><script src="app.js"></script>`, "/app.js"},
		{"svg-template", `<svg><template/></svg><base href="/release/"><script src="app.js"></script>`, "/release/app.js"},
		{"math-template", `<math><template/></math><base href="/release/"><script src="app.js"></script>`, "/release/app.js"},
		{"svg-html-integration", `<svg><foreignObject><base href="/release/"></foreignObject></svg><script src="app.js"></script>`, "/release/app.js"},
		{"svg-desc-integration", `<svg><desc><base href="/release/"></desc></svg><script src="app.js"></script>`, "/release/app.js"},
		{"math-text-integration", `<math><mtext><base href="/release/"></mtext></math><script src="app.js"></script>`, "/release/app.js"},
		{"math-annotation-integration", `<math><annotation-xml encoding="text/html"><base href="/release/"></annotation-xml></math><script src="app.js"></script>`, "/release/app.js"},
		{"foreign-cdata", `<svg><![CDATA[<base href="/ignored/">]]></svg><script src="app.js"></script>`, "/app.js"},
		{"template-integration", `<template><svg><foreignObject><base href="/inert/"></foreignObject></svg></template><base href="/release/"><script src="app.js"></script>`, "/release/app.js"},
		{"self-closing-html-template", `<template/><base href="/inert/"></template><base href="/release/"><script src="app.js"></script>`, "/release/app.js"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractAssets(tc.markup, "https://tree.owned.test/")
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"https://tree.owned.test" + tc.path}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("wrong document base: got=%v want=%v", got, want)
			}
		})
	}
}

func TestHTMLTreeFailurePreservesTextAndOtherRoots(t *testing.T) {
	const state = `<script id="__NEXT_DATA__" type="application/json">{"owned":"retained inline state"}</script>`
	markup := state + strings.Repeat("<div>", 513) + `<script src="/unparsed.js"></script>`
	client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/unparsed.js" || r.URL.Path == "/unparsed.js.map" {
			t.Errorf("links from a rejected document were followed: %s", r.URL)
		}
		switch r.URL.Path {
		case "", "/":
			if r.URL.Hostname() == "tree.owned.test" {
				return ownedResponse(r, 200, markup), nil
			}
			return ownedResponse(r, 200, `<script src="/alternate.js"></script>`), nil
		case "/alternate.js":
			return ownedResponse(r, 200, "retained alternate asset"), nil
		default:
			return ownedResponse(r, 404, ""), nil
		}
	})}
	ch, reached := Discover(context.Background(), "tree.owned.test", Options{Authorized: true, HTTPClient: client})
	texts := map[string]bool{}
	errors := 0
	for item := range ch {
		if item.Error != nil {
			errors++
			if item.Path != "https://tree.owned.test" || !strings.Contains(item.Error.Error(), "HTML document could not be parsed") {
				t.Errorf("unexpected diagnostic: %+v", item)
			}
		} else {
			texts[item.Text] = true
		}
	}
	if !reached.Load() || errors != 1 || !texts[markup] || !texts[`{"owned":"retained inline state"}`] || !texts["retained alternate asset"] {
		t.Fatalf("parse failure lost available content: reached=%v errors=%d texts=%v", reached.Load(), errors, texts)
	}
}

func BenchmarkExtractAssetsDenseDocument(b *testing.B) {
	markup := strings.Repeat("<br>", maxBodyBytes/4-10) + `<script src="/app.js"></script>`
	b.ReportAllocs()
	b.SetBytes(int64(len(markup)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		links, err := extractAssets(markup, "https://tree.owned.test/")
		if err != nil || len(links) != 1 {
			b.Fatalf("dense document lost its asset: links=%v error=%v", links, err)
		}
	}
}

func TestExtractAssetsIgnoresDiscardedElements(t *testing.T) {
	for _, markup := range []string{
		`<select><a href="/ignored.js"></select><script src="/app.js"></script>`,
		`<svg><![CDATA[<script src="/ignored.js"></script>]]></svg><script src="/app.js"></script>`,
	} {
		got, err := extractAssets(markup, "https://tree.owned.test/")
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"https://tree.owned.test/app.js"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("discarded markup became a resource: got=%v want=%v", got, want)
		}
	}
}
