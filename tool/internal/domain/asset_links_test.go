package domain

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestIdenticalRootsStillDiscoverEachHostsRelativeAssets(t *testing.T) {
	const markup = `<script src="/app.js"></script>`
	var mu sync.Mutex
	requests := map[string]int{}
	client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		requests[r.URL.String()]++
		mu.Unlock()
		switch r.URL.Path {
		case "", "/":
			return ownedResponse(r, 200, markup), nil
		case "/app.js":
			return ownedResponse(r, 200, "asset for "+r.URL.Hostname()), nil
		default:
			return ownedResponse(r, 404, ""), nil
		}
	})}
	ch, reached := Discover(context.Background(), "identical.owned.test", Options{Authorized: true, HTTPClient: client})
	texts := map[string]int{}
	for item := range ch {
		if item.Error != nil {
			t.Errorf("complete fixture became incomplete: %v", item.Error)
		}
		texts[item.Text]++
	}
	if !reached.Load() || texts[markup] != 1 || texts["asset for identical.owned.test"] != 1 || texts["asset for www.identical.owned.test"] != 1 {
		t.Fatalf("raw deduplication suppressed a distinct host's asset: texts=%v reached=%v", texts, reached.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	for _, host := range []string{"identical.owned.test", "www.identical.owned.test"} {
		if requests["https://"+host+"/app.js"] != 1 || requests["https://"+host+"/app.js.map"] != 1 {
			t.Errorf("host %s did not fetch its own bundle and map once: %v", host, requests)
		}
	}
}

func TestExtractAssetLinksUsesHTMLAttributes(t *testing.T) {
	for _, tc := range []struct {
		name, markup string
		want         []string
	}{
		{"unquoted", `<script SRC=/app.js></script>`, []string{"https://links.owned.test/app.js"}},
		{"entity-query", `<script src="/app.js?a=1&amp;b=2"></script>`, []string{"https://links.owned.test/app.js?a=1&b=2"}},
		{"encoded-path-fragment", `<script src="/app%2Ejs#section"></script>`, []string{"https://links.owned.test/app%2Ejs"}},
		{"upper-extension", `<script src="/APP.JS"></script>`, []string{"https://links.owned.test/APP.JS"}},
		{"comment", `<!-- <script src="/fake.js"></script> -->`, nil},
		{"data-attribute", `<script data-src="/fake.js"></script>`, nil},
		{"script-string", `<script>const markup = '<script src="/fake.js">';</script>`, nil},
		{"suffix-only", `<a href="/guide.txt?next=/fake.js">guide</a>`, nil},
		{"duplicate-attribute", `<script src="/first.js" src="/ignored.js"></script>`, []string{"https://links.owned.test/first.js"}},
		{"fragment-dedup", `<script src="/app.js#one"></script><script src="/app.js#two"></script>`, []string{"https://links.owned.test/app.js"}},
		{"base-directory", `<base href="/release/"><script src="app.js"></script>`, []string{"https://links.owned.test/release/app.js"}},
		{"late-base", `<script src="app.js"></script><base href="/release/">`, []string{"https://links.owned.test/release/app.js"}},
		{"first-base", `<base href="/first/"><base href="/ignored/"><script src="app.js"></script>`, []string{"https://links.owned.test/first/app.js"}},
		{"base-target-only", `<base target="_blank"><base href="/release/"><script src="app.js"></script>`, []string{"https://links.owned.test/release/app.js"}},
		{"invalid-first-base", `<base href="/%zz"><base href="/ignored/"><script src="app.js"></script>`, []string{"https://links.owned.test/app.js"}},
		{"data-first-base", `<base href="data:text/plain,ignored"><base href="/ignored/"><script src="app.js"></script>`, []string{"https://links.owned.test/app.js"}},
		{"template-base", `<template><base href="/inert/"></template><base href="/release/"><script src="app.js"></script>`, []string{"https://links.owned.test/release/app.js"}},
		{"duplicate-base-href", `<base href="/release/" href="/ignored/"><script src="app.js"></script>`, []string{"https://links.owned.test/release/app.js"}},
		{"credentials", `<script src="https://user:private-input@links.owned.test/app.js"></script>`, nil},
		{"unsupported-scheme", `<script src="ftp://links.owned.test/app.js"></script>`, nil},
		{"invalid-port", `<script src="https://links.owned.test:65536/app.js"></script>`, nil},
		{"IDN-host", `<script src="https://пример.рф/app.js"></script>`, []string{"https://xn--e1afmkfd.xn--p1ai/app.js"}},
		{"foreign-base", `<base href="https://foreign.invalid/"><script src="app.js"></script><script src="https://links.owned.test/owned.js"></script>`, []string{"https://links.owned.test/owned.js"}},
		{"sibling-base", `<base href="https://cdn.links.owned.test/release/"><script src="app.js"></script>`, []string{"https://cdn.links.owned.test/release/app.js"}},
		{"public-suffix-base", `<base href="https://other.github.io/"><script src="app.js"></script>`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := "https://links.owned.test/"
			if tc.name == "public-suffix-base" {
				base = "https://owned.github.io/"
			}
			if tc.name == "IDN-host" {
				base = "https://xn--e1afmkfd.xn--p1ai/"
			}
			got, err := extractAssets(tc.markup, base)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("wrong asset URLs: got=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestSourceMapProbePreservesURLComponents(t *testing.T) {
	for _, tc := range []struct{ source, want string }{
		{"https://links.owned.test/app.js?a=1&b=2", "https://links.owned.test/app.js.map?a=1&b=2"},
		{"https://links.owned.test/app.js#section", "https://links.owned.test/app.js.map"},
		{"https://links.owned.test/app%2Ejs?v=a%2Fb#section", "https://links.owned.test/app%2Ejs.map?v=a%2Fb"},
		{"https://links.owned.test/APP.JS?v=2", "https://links.owned.test/APP.JS.map?v=2"},
	} {
		got := withSourceMaps([]string{tc.source})
		want := []string{tc.source, tc.want}
		if i := strings.IndexByte(tc.want, '?'); i >= 0 {
			want = append(want, tc.want[:i])
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("map probe changed URL components: got=%v want=%s", got, tc.want)
		}
	}
	if got := withSourceMaps([]string{"https://links.owned.test/data.json?path=app.js"}); len(got) != 1 || strings.HasSuffix(got[0], ".map") {
		t.Fatalf("query string was mistaken for a JavaScript path: %v", got)
	}
}
