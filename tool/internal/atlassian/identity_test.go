package atlassian

import (
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestQualifiedLogicalPathsKeepTenantAndLiteralLabelsDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, product := range []string{"jira", "confluence"} {
		for _, base := range []string{"https://owned.invalid/a", "https://owned.invalid/b", "http://owned.invalid/a"} {
			for _, label := range []string{"P-1#comment-11", "P-1%23comment-11", "P/1", "P%2F1"} {
				path := qualifiedPath(base, product, label)
				if seen[path] || model.SafeLocator(path) != path {
					t.Fatal("distinct tenant, product, transport or literal label collapsed")
				}
				seen[path] = true
			}
		}
	}
	clean := NewClient("https://owned.invalid/a", Auth{}, time.Second)
	decorated := NewClient("https://u:private@owned.invalid/a?token=private", Auth{}, time.Second)
	if qualifiedPath(clean.base, "jira", "P-1") != qualifiedPath(decorated.base, "jira", "P-1") {
		t.Fatal("credential rotation changed tenant identity")
	}
}
