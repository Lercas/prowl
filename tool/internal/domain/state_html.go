package domain

import (
	"crypto/sha256"
	"mime"
	"strings"

	"github.com/Lercas/prowl/tool/internal/model"
	"golang.org/x/net/html"
)

type stateScript struct {
	attrs        map[string]string
	text         string
	unescapeHTML bool
}

type stateInventory struct {
	scripts []stateScript
	meta    []string
}

// ExtractStateBlobs pulls actual hydration/state/config blocks and metadata from HTML.
// If tree construction fails, the available tokenized contents are still inspected.
func ExtractStateBlobs(markup, sourceURL string) []model.Item {
	root, _ := parseHTMLDocument(markup)
	return extractStateBlobsFromDocument(markup, root, sourceURL)
}

func extractStateBlobsFromDocument(markup string, root *html.Node, sourceURL string) []model.Item {
	var inventory stateInventory
	if root == nil {
		inventory = stateInventoryFromTokens(markup)
	} else {
		walkHTMLDocument(root, func(node *html.Node, _ bool) {
			if node.Type != html.ElementNode {
				return
			}
			switch node.Data {
			case "script":
				inventory.scripts = append(inventory.scripts, stateScript{
					attrs: firstStateAttributes(node.Attr), text: stateScriptText(node), unescapeHTML: node.Namespace == "",
				})
			case "meta":
				inventory.addMeta(node.Attr)
			}
		})
	}
	return inventory.items(sourceURL)
}

func firstStateAttributes(attrs []html.Attribute) map[string]string {
	first := map[string]string{}
	for _, attr := range attrs {
		if attr.Namespace != "" {
			continue
		}
		if _, exists := first[attr.Key]; !exists {
			first[attr.Key] = attr.Val
		}
	}
	return first
}

func (inventory *stateInventory) addMeta(attrs []html.Attribute) {
	seen := map[string]bool{}
	for _, attr := range attrs {
		if attr.Namespace != "" || seen[attr.Key] {
			continue
		}
		seen[attr.Key] = true
		if (attr.Key == "content" || attr.Key == "value") && len(attr.Val) >= 16 {
			inventory.meta = append(inventory.meta, attr.Val)
		}
	}
}

func stateScriptText(node *html.Node) string {
	if child := node.FirstChild; child != nil && child.NextSibling == nil && child.Type == html.TextNode {
		return child.Data
	}
	var text strings.Builder
	// Script source is child text content, not descendant text content. In particular,
	// nested foreign scripts must not copy their payload into every ancestor script.
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.TextNode {
			text.WriteString(child.Data)
		}
	}
	return text.String()
}

func stateInventoryFromTokens(markup string) stateInventory {
	var inventory stateInventory
	var current *stateScript
	var text strings.Builder
	finish := func() {
		if current != nil {
			current.text = text.String()
			inventory.scripts = append(inventory.scripts, *current)
			current = nil
			text = strings.Builder{}
		}
	}
	z := html.NewTokenizer(strings.NewReader(markup))
	for {
		switch z.Next() {
		case html.ErrorToken:
			finish()
			return inventory
		case html.StartTagToken, html.SelfClosingTagToken:
			token := z.Token()
			switch token.Data {
			case "script":
				finish()
				current = &stateScript{attrs: firstStateAttributes(token.Attr), unescapeHTML: true}
			case "meta":
				inventory.addMeta(token.Attr)
			}
		case html.TextToken:
			if current != nil {
				text.Write(z.Text())
			}
		case html.EndTagToken:
			if z.Token().Data == "script" {
				finish()
			}
		}
	}
}

func (inventory stateInventory) items(sourceURL string) []model.Item {
	var items []model.Item
	seen := map[[32]byte]bool{}
	add := func(name, content string, unescapeHTML bool) {
		content = strings.TrimSpace(content)
		if len(content) < 12 {
			return
		}
		var decoded string
		if unescapeHTML {
			decoded = decodeEscapes(content)
		} else {
			decoded = decodeStringEscapes(content)
		}
		hash := sha256.Sum256([]byte(decoded))
		if !seen[hash] {
			seen[hash] = true
			items = append(items, model.Item{Text: decoded, Source: "code", Path: sourceURL + "#" + name})
		}
	}
	// Retain the established container priority so an equivalent representation has stable provenance.
	for _, id := range []string{"__NEXT_DATA__", "__NUXT_DATA__"} {
		for _, script := range inventory.scripts {
			if strings.EqualFold(script.attrs["id"], id) {
				add(id, script.text, script.unescapeHTML)
			}
		}
	}
	for _, pattern := range stateAssignmentPatterns {
		for _, script := range inventory.scripts {
			for _, match := range pattern.re.FindAllStringSubmatch(script.text, -1) {
				add(pattern.name, match[1], script.unescapeHTML)
			}
		}
	}
	for _, script := range inventory.scripts {
		mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(script.attrs["type"]))
		if err == nil && mediaType == "application/json" {
			add("json-island", script.text, script.unescapeHTML)
		}
	}
	for _, script := range inventory.scripts {
		low := strings.ToLower(script.text)
		if len(script.text) >= 16 && (strings.Contains(low, "key") || strings.Contains(low, "token") || strings.Contains(low, "secret") ||
			strings.Contains(low, "config") || strings.Contains(low, "apikey") || strings.Contains(low, "env")) {
			add("inline-script", script.text, script.unescapeHTML)
		}
	}
	for _, value := range inventory.meta {
		add("meta", value, false) // The HTML parser already decoded attribute entities once.
	}
	return items
}
