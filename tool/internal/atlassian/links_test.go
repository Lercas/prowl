package atlassian

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestNextCursorSeparatesURLComponents(t *testing.T) {
	for _, pair := range [][2]string{
		{"/next?cursor=a#anchor", "a"},
		{"https://fixture.invalid/wiki/api/v2/pages?limit=250&cursor=a%23b#anchor", "a#b"},
		{"?cursor=a%2Bb%26c%3Dd%3Fe%20f#anchor", "a+b&c=d?e f"},
		{"relative?cursor=%E2%98%83%2Fvalue", "☃/value"},
		{"/next#anchor?cursor=not-a-query", ""},
		{"/next?cursor=a&cursor=b", ""},
		{"/next?cursor=a&cursor=a", ""},
		{"/next?cursor=a&%63ursor=b", ""},
		{"/%zz?cursor=a", ""},
		{"http://[broken?cursor=a", ""},
		{"/next?cursor=a&bad=%zz", ""},
		{"/next?cursor=", ""}, {"/next?limit=2", ""}, {"", ""},
	} {
		if got := nextCursor(pair[0]); got != pair[1] {
			t.Errorf("cursor mixed URL components or accepted ambiguity: link=%q got=%q want=%q", pair[0], got, pair[1])
		}
	}
}

func TestJiraFindingLinksKeepIdentifiersInTheirComponents(t *testing.T) {
	const base = "https://fixture.invalid/ctx%2F"
	dep := Deployment{BaseURL: base}
	for _, key := range []string{"P-1", "P/1?query=x#fragment", "P%2F café +&="} {
		for _, comment := range []string{"", "123", "id?next=x&focusedCommentId=other#fragment + café"} {
			var items []model.Item
			emit := func(it model.Item) { items = append(items, it) }
			jiraEmitCurrent(dep, []string{"summary"}, jiraIssue{Key: key, Fields: map[string]any{"summary": "owned text"}}, emit)
			jiraEmitComment(dep, key, comment, "owned text", emit)
			var history jiraHistory
			if err := json.Unmarshal([]byte(`{"created":"now","items":[{"fromString":"owned text"}]}`), &history); err != nil {
				t.Fatal(err)
			}
			jiraEmitHistory(dep, key, history, emit)
			if len(items) != 3 {
				t.Fatal("a source was not emitted")
			}
			for i, it := range items {
				raw, _ := it.Meta["url"].(string)
				u, err := url.Parse(raw)
				if err != nil {
					t.Fatalf("invalid finding URL: source=%d link=%q err=%v", i, raw, err)
				}
				const prefix = "/ctx%2F/browse/"
				escapedKey := strings.TrimPrefix(u.EscapedPath(), prefix)
				decodedKey, err := url.PathUnescape(escapedKey)
				if err != nil || u.Host != "fixture.invalid" || u.Fragment != "" || !strings.HasPrefix(u.EscapedPath(), prefix) || strings.Contains(escapedKey, "/") || decodedKey != key {
					t.Fatalf("identifier escaped its path component: source=%d link=%q err=%v", i, raw, err)
				}
				q, err := url.ParseQuery(u.RawQuery)
				if err != nil || (i == 1 && comment != "" && (len(q) != 1 || len(q["focusedCommentId"]) != 1 || q.Get("focusedCommentId") != comment)) || ((i != 1 || comment == "") && len(q) != 0) {
					t.Fatalf("comment identifier escaped its query value: source=%d link=%q", i, raw)
				}
				if i == 0 && it.Path != key || i == 1 && comment != "" && !strings.HasSuffix(it.Path, "#comment-"+comment) || i == 2 && it.Path != key+"@now" {
					t.Fatal("URL encoding changed finding identity")
				}
			}
		}
	}
}
