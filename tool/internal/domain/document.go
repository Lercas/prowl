package domain

import (
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

func parseHTMLDocument(markup string) (*html.Node, error) {
	root, err := html.Parse(strings.NewReader(markup))
	if err != nil {
		return nil, fmt.Errorf("HTML document could not be parsed: %w", err)
	}
	return root, nil
}

// walkHTMLDocument visits nodes in tree order, keeping only pending siblings at each depth.
func walkHTMLDocument(root *html.Node, visit func(*html.Node, bool)) {
	type entry struct {
		node  *html.Node
		inert bool
	}
	if root == nil {
		return
	}
	stack := []entry{{node: root}}
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		node := current.node
		childInert := current.inert || node.Type == html.ElementNode && node.Namespace == "" && node.Data == "template"
		if node.NextSibling != nil {
			stack = append(stack, entry{node: node.NextSibling, inert: current.inert})
		}
		if node.FirstChild != nil {
			stack = append(stack, entry{node: node.FirstChild, inert: childInert})
		}
		visit(node, current.inert)
	}
}
