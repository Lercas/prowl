package domain

import (
	"crypto/sha1"
	"encoding/hex"
	"html"
	"regexp"
	"strconv"
	"strings"

	"github.com/Lercas/prowl/tool/internal/model"
)

// stateBlobPatterns match SSR/hydration state blobs that frequently leak secrets.
var stateBlobPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"__NEXT_DATA__", regexp.MustCompile(`(?is)<script\s+id="__NEXT_DATA__"[^>]*>(.*?)</script>`)},
	{"__NUXT_DATA__", regexp.MustCompile(`(?is)<script[^>]*\bid="__NUXT_DATA__"[^>]*>(.*?)</script>`)},
	{"__NUXT__", regexp.MustCompile(`(?is)window\.__NUXT__\s*=\s*(.*?)\s*</script>`)},
	{"__INITIAL_STATE__", regexp.MustCompile(`(?is)window\.__INITIAL_STATE__\s*=\s*(.*?);?\s*</script>`)},
	{"__PRELOADED_STATE__", regexp.MustCompile(`(?is)window\.__PRELOADED_STATE__\s*=\s*(.*?);?\s*</script>`)},
	{"__APOLLO_STATE__", regexp.MustCompile(`(?is)window\.__APOLLO_STATE__\s*=\s*(.*?);?\s*</script>`)},
	{"__remixContext", regexp.MustCompile(`(?is)window\.__remixContext\s*=\s*(.*?);?\s*</script>`)},
	{"__sveltekit", regexp.MustCompile(`(?is)__sveltekit_[\w]+\s*=\s*(.*?);?\s*</script>`)},
	{"__GATSBY", regexp.MustCompile(`(?is)window\.___gatsby\s*=\s*(.*?);?\s*</script>`)},
	{"window.env", regexp.MustCompile(`(?is)window\.(?:__ENV__|__RUNTIME_CONFIG__|runtimeConfig|ENV|env|CONFIG|_config|appConfig)\s*=\s*(\{.*?\})\s*;?\s*</script>`)},
}

var (
	reJSONIsland   = regexp.MustCompile(`(?is)<script[^>]*type=["']application/json["'][^>]*>(.*?)</script>`)
	reInlineScript = regexp.MustCompile(`(?is)<script(?:(?:[^>]*?)(?:\bsrc=)?[^>]*)?>([^<]{16,})</script>`)
	reMetaToken    = regexp.MustCompile(`(?is)<meta[^>]+(?:content|value)=["']([^"']{16,})["'][^>]*>`)
	reUnicodeEsc   = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
)

// decodeEscapes HTML-entity-decodes then JSON/JS-unescapes (\/ \" \uXXXX) so secrets inside blobs
// are matchable — e.g. an AWS key's '/' is `\/` in __NEXT_DATA__ and would otherwise be missed.
func decodeEscapes(s string) string {
	s = html.UnescapeString(s)
	s = strings.ReplaceAll(s, `\/`, `/`)
	s = strings.ReplaceAll(s, `\"`, `"`)
	s = strings.ReplaceAll(s, `&`, "&")
	s = reUnicodeEsc.ReplaceAllStringFunc(s, func(m string) string {
		n, err := strconv.ParseInt(m[2:], 16, 32)
		if err != nil {
			return m
		}
		return string(rune(n))
	})
	return s
}

// ExtractStateBlobs pulls inline hydration/state/config/JSON blobs from an HTML page, decodes their
// escapes, and returns them as separate Items tagged by blob name.
func ExtractStateBlobs(htmlText, sourceURL string) []model.Item {
	var items []model.Item
	seen := map[string]bool{}
	add := func(name, content string) {
		content = strings.TrimSpace(content)
		if len(content) < 12 {
			return
		}
		decoded := decodeEscapes(content)
		h := sha1.Sum([]byte(decoded))
		key := hex.EncodeToString(h[:8])
		if seen[key] {
			return
		}
		seen[key] = true
		items = append(items, model.Item{Text: decoded, Source: "code", Path: sourceURL + "#" + name})
	}
	for _, p := range stateBlobPatterns {
		for _, m := range p.re.FindAllStringSubmatch(htmlText, -1) {
			add(p.name, m[1])
		}
	}
	for _, m := range reJSONIsland.FindAllStringSubmatch(htmlText, -1) {
		add("json-island", m[1])
	}
	for _, m := range reInlineScript.FindAllStringSubmatch(htmlText, -1) {
		low := strings.ToLower(m[1])
		if strings.Contains(low, "key") || strings.Contains(low, "token") || strings.Contains(low, "secret") ||
			strings.Contains(low, "config") || strings.Contains(low, "apikey") || strings.Contains(low, "env") {
			add("inline-script", m[1])
		}
	}
	for _, m := range reMetaToken.FindAllStringSubmatch(htmlText, -1) {
		add("meta", m[1])
	}
	return items
}
