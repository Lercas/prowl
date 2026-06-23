package domain

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// crtshSubdomains enumerates subdomains via Certificate Transparency (crt.sh).
func crtshSubdomains(ctx context.Context, apex string) []string {
	c := newClient(25 * time.Second)
	body, ok := getText(ctx, c, "https://crt.sh/?q=%25."+url.QueryEscape(apex)+"&output=json")
	set := map[string]bool{apex: true}
	if ok {
		var rows []struct {
			NameValue string `json:"name_value"`
		}
		if json.Unmarshal([]byte(body), &rows) == nil {
			for _, r := range rows {
				for _, name := range strings.Split(r.NameValue, "\n") {
					name = strings.TrimPrefix(strings.TrimSpace(strings.ToLower(name)), "*.")
					if name == apex || strings.HasSuffix(name, "."+apex) {
						set[name] = true
					}
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// waybackAssets returns historical asset URLs from the Wayback Machine (archive.org).
func waybackAssets(ctx context.Context, apex string, max int) []string {
	c := newClient(25 * time.Second)
	body, ok := getText(ctx, c, "http://web.archive.org/cdx/search/cdx?url="+url.QueryEscape(apex)+
		"/*&output=json&fl=original,timestamp&collapse=urlkey&limit=4000")
	var urls []string
	if ok {
		var rows [][]string
		if json.Unmarshal([]byte(body), &rows) == nil {
			for i, r := range rows {
				if i == 0 || len(r) < 2 {
					continue // header / malformed
				}
				orig, ts := r[0], r[1]
				if interestingAsset(orig) {
					// id_ suffix returns the raw archived bytes
					urls = append(urls, "https://web.archive.org/web/"+ts+"id_/"+orig)
					if len(urls) >= max {
						break
					}
				}
			}
		}
	}
	return urls
}

func interestingAsset(u string) bool {
	low := strings.ToLower(u)
	for _, suf := range []string{".js", ".map", ".json", ".env", ".yml", ".yaml", ".config", ".txt"} {
		if strings.Contains(low, suf) {
			return true
		}
	}
	return false
}

var reAsset = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"'<>]+?\.(?:js|json|map|env|cfg|config)(?:\?[^"'<>]*)?)["']`)

func extractAssets(html, base string) []string {
	bu, err := url.Parse(base)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range reAsset.FindAllStringSubmatch(html, -1) {
		ref, err := url.Parse(strings.TrimSpace(m[1]))
		if err != nil {
			continue
		}
		abs := bu.ResolveReference(ref)
		// stay on the same registrable host family
		if !sameSite(abs.Hostname(), bu.Hostname()) {
			continue
		}
		s := abs.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// commonPaths are publicly-served misconfiguration paths probed during recon.
var commonPaths = []string{
	"/.env", "/.env.local", "/.env.production", "/config.json", "/config.js",
	"/.git/config", "/.well-known/security.txt", "/api/swagger.json", "/swagger.json",
	"/firebase-config.js", "/appsettings.json", "/.npmrc", "/backup.sql", "/app.config.js",
	"/static/js/main.js.map", "/assets/index.js.map", "/wp-config.php.bak",
}

// sameSite reports whether two hosts belong to the same registrable site, so domain recon stays
// within the authorized scope. It uses the public suffix list (publicsuffix.EffectiveTLDPlusOne)
// to compute the real registrable domain (eTLD+1): this treats x.github.io and y.github.io as
// DISTINCT sites (their shared "apex" github.io is a public suffix, not a registrable domain),
// closing the authorization-scope escape a naive last-2-labels apex would open for *.github.io,
// *.s3.amazonaws.com, *.co.uk, etc.
func sameSite(a, b string) bool {
	a, b = strings.ToLower(a), strings.ToLower(b)
	return a == b || registrable(a) == registrable(b)
}

// registrable returns the eTLD+1 (registrable domain) of host per the public suffix list. When the
// host is itself a public suffix (or otherwise has no registrable domain), EffectiveTLDPlusOne
// errors; we fall back to the raw host so two distinct public-suffix-only hosts stay distinct.
func registrable(host string) string {
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

// apexOf returns the naive last-two-labels "apex" of a host. Retained as a helper; sameSite no
// longer relies on it because last-two-labels is wrong for multi-label public suffixes (github.io,
// co.uk). Use registrable() for scope decisions.
func apexOf(host string) string {
	p := strings.Split(host, ".")
	if len(p) >= 2 {
		return strings.Join(p[len(p)-2:], ".")
	}
	return host
}
