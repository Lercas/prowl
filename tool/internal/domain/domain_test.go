package domain

import (
	"sort"
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"https://www.Acme.com/path?q=1": "acme.com",
		"http://acme.com":               "acme.com",
		"acme.com":                      "acme.com",
		"WWW.acme.com:8080":             "acme.com",
	}
	for in, want := range cases {
		if got := normalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractAssetsSameSiteOnly(t *testing.T) {
	html := `<html>
<script src="/static/app.js"></script>
<script src="https://cdn.acme.com/vendor.js"></script>
<link href="https://acme.com/style.css.map"/>
<script src="https://googletagmanager.com/gtag.js"></script>
<script src="data:text/js,evil"></script>`
	got := extractAssets(html, "https://acme.com")
	hostOK := true
	for _, u := range got {
		if strings.Contains(u, "googletagmanager") {
			hostOK = false // third-party must be excluded
		}
	}
	if !hostOK {
		t.Error("third-party asset not filtered")
	}
	// same-apex assets (apex + cdn subdomain) included
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "acme.com/static/app.js") {
		t.Errorf("relative same-host asset missing: %v", got)
	}
	if !strings.Contains(joined, "cdn.acme.com/vendor.js") {
		t.Errorf("same-apex CDN asset missing: %v", got)
	}
}

func TestWithSourceMaps(t *testing.T) {
	got := withSourceMaps([]string{"https://a.com/app.js", "https://a.com/data.json?v=2"})
	sort.Strings(got)
	want := "https://a.com/app.js"
	found := false
	for _, u := range got {
		if u == want+".map" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a .map probe for the .js asset, got %v", got)
	}
}

func TestSameSiteAndApex(t *testing.T) {
	if !sameSite("cdn.acme.com", "acme.com") || !sameSite("acme.com", "www.acme.com") {
		t.Error("same-apex hosts should match")
	}
	if sameSite("evil.com", "acme.com") {
		t.Error("different apex should not match")
	}
	if apexOf("a.b.acme.com") != "acme.com" {
		t.Errorf("apexOf wrong: %s", apexOf("a.b.acme.com"))
	}
}

// TestSameSitePublicSuffix guards the authorization-scope boundary: hosts that merely share a
// public suffix (github.io, co.uk) must be DISTINCT sites so `domain --authorized` never fetches a
// third party's assets, while real subdomains of one registrable domain stay same-site.
func TestSameSitePublicSuffix(t *testing.T) {
	if sameSite("x.github.io", "y.github.io") {
		t.Error("x.github.io and y.github.io share only the public suffix github.io — must NOT be same site")
	}
	if !sameSite("a.example.com", "b.example.com") {
		t.Error("a.example.com and b.example.com share registrable domain example.com — must be same site")
	}
	if sameSite("attacker.co.uk", "victim.co.uk") {
		t.Error("attacker.co.uk and victim.co.uk share only the public suffix co.uk — must NOT be same site")
	}
}

func TestDecodeEscapesUnmasksSlash(t *testing.T) {
	in := `{"url":"postgres:\/\/u:p@h\/db","k":"a/b"}`
	out := decodeEscapes(in)
	if !strings.Contains(out, "postgres://u:p@h/db") {
		t.Errorf("backslash-slash not decoded: %q", out)
	}
	if !strings.Contains(out, "a/b") {
		t.Errorf("unicode escape not decoded: %q", out)
	}
}

func TestExtractStateBlobsFindsKnownContainers(t *testing.T) {
	html := `<script id="__NEXT_DATA__" type="application/json">{"k":"aaaaaaaaaaaaaaaa"}</script>
<script>window.__INITIAL_STATE__ = {"x":"yyyyyyyyyyyyyyyy"};</script>`
	items := ExtractStateBlobs(html, "https://acme.com")
	paths := map[string]bool{}
	for _, it := range items {
		paths[it.Path] = true
	}
	if !paths["https://acme.com#__NEXT_DATA__"] {
		t.Errorf("__NEXT_DATA__ not extracted: %v", paths)
	}
	if !paths["https://acme.com#__INITIAL_STATE__"] {
		t.Errorf("__INITIAL_STATE__ not extracted: %v", paths)
	}
}
