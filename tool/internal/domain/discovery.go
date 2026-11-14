package domain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/Lercas/prowl/tool/internal/jsonstrict"
	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"
)

// crtshSubdomains enumerates subdomains via Certificate Transparency (crt.sh).
func (f *textFetcher) crtshSubdomains(ctx context.Context, apex string) ([]string, error) {
	body, present, err := f.getText(ctx, "https://crt.sh/?q=%25."+url.QueryEscape(apex)+"&output=json")
	set := map[string]bool{apex: true}
	if err != nil || !present {
		return []string{apex}, errors.Join(errors.New("crt.sh inventory unavailable"), err)
	}
	if err := jsonstrict.ValidateEncoding([]byte(body)); err != nil || !strings.HasPrefix(strings.TrimSpace(body), "[") {
		return []string{apex}, errors.New("invalid crt.sh inventory encoding")
	}
	var rows []json.RawMessage
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		return []string{apex}, errors.New("invalid crt.sh inventory schema")
	}
	for _, r := range rows {
		fields, err := jsonstrict.Object(r, false)
		if err != nil {
			return []string{apex}, errors.New("invalid crt.sh inventory row")
		}
		var nameValue string
		if err := json.Unmarshal(fields["name_value"], &nameValue); err != nil || strings.TrimSpace(nameValue) == "" {
			return []string{apex}, errors.New("invalid crt.sh inventory name_value")
		}
		for _, name := range strings.Split(nameValue, "\n") {
			name = strings.TrimPrefix(strings.TrimSpace(strings.ToLower(name)), "*.")
			if name == apex || strings.HasSuffix(name, "."+apex) {
				// CT data is untrusted. Suffix matching alone accepts paths and URL userinfo.
				if strings.ContainsAny(name, "/:@#?\\") || strings.IndexFunc(name, func(r rune) bool { return r <= ' ' }) >= 0 {
					return []string{apex}, errors.New("invalid crt.sh domain name")
				}
				set[name] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

// waybackAssets returns historical asset URLs from the Wayback Machine (archive.org).
func (f *textFetcher) waybackAssets(ctx context.Context, apex string, max int) ([]string, error) {
	body, present, err := f.getText(ctx, "https://web.archive.org/cdx/search/cdx?url="+url.QueryEscape(apex)+
		"/*&output=json&fl=original,timestamp&collapse=urlkey&limit=4000")
	var urls []string
	if err != nil || !present {
		return nil, errors.Join(errors.New("wayback inventory unavailable"), err)
	}
	if err := jsonstrict.ValidateEncoding([]byte(body)); err != nil || !strings.HasPrefix(strings.TrimSpace(body), "[") {
		return nil, errors.New("invalid Wayback inventory encoding")
	}
	var rows [][]string
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		return nil, errors.New("invalid Wayback inventory schema")
	}
	for i, r := range rows {
		if i == 0 {
			if len(r) != 2 || r[0] != "original" || r[1] != "timestamp" {
				return nil, errors.New("invalid Wayback inventory header")
			}
			continue
		}
		if len(r) != 2 {
			return nil, errors.New("invalid Wayback inventory row")
		}
		orig, ts := r[0], r[1]
		if interestingAsset(orig) {
			u, err := url.Parse(orig)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || !sameSite(u.Hostname(), apex) {
				continue // Never fetch archived URLs from another site's inventory.
			}
			if len(ts) != 14 || strings.IndexFunc(ts, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return nil, errors.New("invalid Wayback timestamp")
			}
			if len(urls) >= max {
				return urls, fmt.Errorf("wayback asset limit exhausted (%d)", max)
			}
			// id_ suffix returns the raw archived bytes
			urls = append(urls, "https://web.archive.org/web/"+ts+"id_/"+orig)
		}
	}
	if len(rows) >= 4001 { // Header plus the requested server-side limit; completeness is unknown.
		return urls, errors.New("wayback catalog row limit exhausted")
	}
	return urls, nil
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

func extractAssets(markup, base string) ([]string, error) {
	root, err := parseHTMLDocument(markup)
	if err != nil {
		return nil, err
	}
	return extractAssetsFromDocument(root, base)
}

func extractAssetsFromDocument(root *html.Node, base string) ([]string, error) {
	bu, err := url.Parse(base)
	if err != nil {
		return nil, errors.New("invalid HTML document URL")
	}
	document, err := ParseTarget(base)
	if err != nil {
		return nil, errors.New("invalid HTML document URL")
	}
	// Collect actual attributes before resolving references, since a later base element also
	// determines earlier relative links. Tree construction handles discarded tags and foreign
	// namespaces; a token named "base" is not necessarily an HTML base element.
	var refs []string
	firstBase := false
	walkHTMLDocument(root, func(node *html.Node, inert bool) {
		if node.Type != html.ElementNode {
			return
		}
		attrs := map[string]bool{}
		for _, attr := range node.Attr {
			if attr.Namespace != "" || attrs[attr.Key] {
				continue // HTML uses the first occurrence of a duplicate attribute.
			}
			attrs[attr.Key] = true
			if node.Namespace == "" && node.Data == "base" {
				// Template contents do not supply a base URL for the document itself.
				if attr.Key == "href" && !firstBase && !inert {
					firstBase = true
					if ref, err := url.Parse(strings.TrimSpace(attr.Val)); err == nil {
						resolved := bu.ResolveReference(ref)
						if resolved.Scheme != "data" && resolved.Scheme != "javascript" {
							bu = resolved
						}
					}
				}
				continue
			}
			if attr.Key == "src" || attr.Key == "href" {
				refs = append(refs, attr.Val)
			}
		}
	})
	seen := map[string]bool{}
	var out []string
	for _, raw := range refs {
		ref, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		abs := bu.ResolveReference(ref)
		if abs.Scheme != "http" && abs.Scheme != "https" {
			continue
		}
		asset, err := ParseTarget(abs.String())
		// A foreign base URL must not redefine the authorized host family.
		if err != nil || !sameSite(asset.Host, document.Host) {
			continue
		}
		canonical, err := url.Parse(asset.Canonical)
		if err != nil {
			continue
		}
		abs.Host = canonical.Host // Normalize IDN, IP spelling and explicit ports for URL deduplication.
		switch strings.ToLower(path.Ext(abs.Path)) {
		case ".js", ".json", ".map", ".env", ".cfg", ".config":
		default:
			continue
		}
		abs.Fragment, abs.RawFragment = "", "" // Fragments do not select different HTTP resources.
		s := abs.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out, nil
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
