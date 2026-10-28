package atlassian

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const extractionToken = "QA_TEXT_A7s9D4k2M8w5R1p6T3x0V9zQ"

func adfNode(kind string, children ...any) map[string]any {
	return map[string]any{"type": kind, "content": children}
}

func adfFragment(text string) map[string]any {
	return map[string]any{"type": "text", "text": text}
}

func TestADFReconstructsAdjacentFormattedText(t *testing.T) {
	for split := 1; split < len(extractionToken); split++ {
		left := adfFragment("before " + extractionToken[:split])
		left["marks"] = []any{map[string]any{"type": "link", "attrs": map[string]any{"href": "https://owned.invalid/?token=metadata-token"}}}
		right := adfFragment(extractionToken[split:] + " after")
		right["marks"] = []any{map[string]any{"type": "strong"}}
		got := fieldText(adfNode("doc", adfNode("paragraph", left, right)))
		if !strings.HasPrefix(got, "before "+extractionToken+" after") || strings.Count(got, "metadata-token") != 1 {
			t.Fatalf("split %d: visible text interrupted or mark lost: %q", split, got)
		}
	}
}

func TestADFDoesNotJoinSeparateText(t *testing.T) {
	left, right := extractionToken[:12], extractionToken[12:]
	for name, node := range map[string]any{
		"paragraphs": adfNode("doc", adfNode("paragraph", adfFragment(left)), adfNode("paragraph", adfFragment(right))),
		"hardBreak":  adfNode("doc", adfNode("paragraph", adfFragment(left), map[string]any{"type": "hardBreak"}, adfFragment(right))),
		"cells":      adfNode("doc", adfNode("table", adfNode("tableRow", adfNode("tableCell", adfNode("paragraph", adfFragment(left))), adfNode("tableCell", adfNode("paragraph", adfFragment(right)))))),
		"mention":    adfNode("doc", adfNode("paragraph", adfFragment(left), map[string]any{"type": "mention", "attrs": map[string]any{"text": "@user"}}, adfFragment(right))),
		"unknown":    adfNode("doc", adfNode("paragraph", adfFragment(left), map[string]any{"type": "futureInline", "attrs": map[string]any{"value": "other"}}, adfFragment(right))),
		"strings":    []any{left, right},
	} {
		t.Run(name, func(t *testing.T) {
			got := fieldText(node)
			if strings.Contains(got, extractionToken) || !strings.Contains(got, left) || !strings.Contains(got, right) {
				t.Fatalf("separate text joined or lost: %q", got)
			}
		})
	}
}

func TestJiraExtractionReadsNestedValues(t *testing.T) {
	for name, node := range map[string]any{
		"cascading-option": map[string]any{"value": "parent", "child": map[string]any{"value": extractionToken}},
		"unknown-attribute": map[string]any{"type": "media", "attrs": map[string]any{
			"occurrenceKey": extractionToken,
		}},
		"nested-attribute": map[string]any{"type": "extension", "attrs": map[string]any{
			"parameters": map[string]any{"credentials": []any{map[string]any{"apiToken": extractionToken}}},
		}},
		"nested-array":     []any{map[string]any{"custom": []any{[]any{map[string]any{"opaque": extractionToken}}}}},
		"custom-type":      map[string]any{"type": extractionToken, "attrs": map[string]any{"value": "ordinary value"}},
		"custom-content":   map[string]any{"type": "paragraph", "content": map[string]any{"value": extractionToken}},
		"custom-text":      map[string]any{"type": "text", "text": []any{extractionToken}},
		"custom-marks":     map[string]any{"type": "text", "marks": []any{extractionToken}},
		"custom-version":   map[string]any{"type": "doc", "version": extractionToken, "content": []any{}},
		"custom-mark-type": map[string]any{"type": "text", "marks": []any{map[string]any{"type": extractionToken}}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := fieldText(node); strings.Count(got, extractionToken) != 1 {
				t.Fatalf("nested value lost or duplicated: %q", got)
			}
		})
	}
}

func TestJiraExtractionPreservesValueContextAndOrder(t *testing.T) {
	node := map[string]any{"z": map[string]any{"token": extractionToken}, "a": map[string]any{"password": "pässwörd"}, "empty": "", "count": json.Number("9007199254740993")}
	want := "password = pässwörd\ntoken = " + extractionToken
	for i := 0; i < 100; i++ {
		if got := fieldText(node); got != want {
			t.Fatalf("value context, Unicode, or deterministic order lost: %q", got)
		}
	}
}

func TestJiraExtractionReachesCurrentAndAllComments(t *testing.T) {
	for _, cloud := range []bool{false, true} {
		t.Run(map[bool]string{true: "Cloud", false: "Server"}[cloud], func(t *testing.T) {
			v := "2"
			if cloud {
				v = "3"
			}
			body := func(value string) any {
				return adfNode("doc", map[string]any{"type": "extension", "attrs": map[string]any{"parameters": map[string]any{"token": value}}})
			}
			items := collectFixture(t, "jira", Options{Projects: []string{"P"}, Fields: []string{"customfield_10000"}, CurrentOnly: true}, func(r *http.Request) (int, any) {
				switch r.URL.Path {
				case "/rest/api/2/serverInfo":
					return 200, map[string]any{"deploymentType": map[bool]string{true: "Cloud", false: "Server"}[cloud]}
				case "/rest/api/" + v + "/search", "/rest/api/" + v + "/search/jql":
					return 200, map[string]any{"isLast": true, "total": 1, "issues": []any{map[string]any{
						"id": "1", "key": "P-1", "fields": map[string]any{
							"customfield_10000": map[string]any{"value": "parent", "child": map[string]any{"value": "custom secret"}},
							"comment":           map[string]any{"total": 2, "comments": []any{map[string]any{"id": "1", "body": body("inline secret")}}},
						},
					}}}
				case "/rest/api/" + v + "/issue/P-1/comment":
					return 200, map[string]any{"total": 2, "comments": []any{map[string]any{"id": "1", "body": body("inline secret")}, map[string]any{"id": "2", "body": body("dedicated secret")}}}
				}
				return 404, nil
			})
			if len(items) != 3 || diagnostics(items) != 0 || !anyContains(items, "custom secret") || !anyContains(items, "inline secret") || !anyContains(items, "dedicated secret") {
				t.Fatalf("nested extraction lost a source or bypassed comment dedup: %+v", items)
			}
		})
	}
}
