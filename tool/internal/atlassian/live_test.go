package atlassian

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
)

// Live integration tests run ONLY when PROWL_LIVE_TEST=1. They exercise the real package (Collect ->
// detect -> walk -> extract) against PUBLIC, anonymously-readable Atlassian instances, BOUNDED (small
// MaxItems, few workers, a timeout) so they are a respectful read-only functional probe — NOT a crawl.
// They assert traversal/detection/version-walking and print only METADATA (path, version, sizes), never
// the collected Text, so third-party content/secrets are never surfaced.
func liveGuard(t *testing.T) {
	t.Helper()
	if os.Getenv("PROWL_LIVE_TEST") == "" {
		t.Skip("set PROWL_LIVE_TEST=1 to run live integration tests against public instances")
	}
}

// liveCollect runs a bounded anonymous Collect and returns the items + deployment, skipping the case
// gracefully if the instance is unreachable (public instances go down / rate-limit).
func liveCollect(t *testing.T, base, product string, opts Options) ([]model.Item, Deployment) {
	t.Helper()
	if opts.MaxItems == 0 {
		opts.MaxItems = 25
	}
	if opts.Workers == 0 {
		opts.Workers = 3
	}
	if opts.Timeout == 0 {
		opts.Timeout = 45 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	start := time.Now()
	ch, dep, err := Collect(ctx, base, product, Auth{}, opts) // anonymous (public instance)
	if err != nil {
		t.Skipf("%s unreachable/!detect (%v) — skipping", base, err)
	}
	var items []model.Item
	for it := range ch {
		items = append(items, it)
	}
	t.Logf("%s -> %s | %d items in %v (history=%v, max=%d)", base, dep.String(), len(items), time.Since(start).Round(time.Millisecond), !opts.CurrentOnly, opts.MaxItems)
	return items, dep
}

func sample(t *testing.T, items []model.Item, n int) {
	for i, it := range items {
		if i >= n {
			break
		}
		t.Logf("    [%s] path=%q version=%v textLen=%d", it.Source, it.Path, it.Meta["version"], len(it.Text))
	}
}

func TestLiveJiraServer(t *testing.T) {
	liveGuard(t)
	bases := []string{"https://issues.apache.org/jira", "https://jira.atlassian.com"}
	for _, base := range bases {
		t.Run(base, func(t *testing.T) {
			// 1) current-only: light — validates detect + project/issue enumeration + field extraction.
			cur, dep := liveCollect(t, base, "jira", Options{CurrentOnly: true})
			if dep.Product != "jira" || dep.Kind == "" {
				t.Fatalf("bad deployment: %+v", dep)
			}
			if len(cur) == 0 {
				t.Fatalf("no items collected (anonymous read may be disabled)")
			}
			for _, it := range cur {
				if it.Source != "jira" || it.Path == "" {
					t.Fatalf("bad item: source=%q path=%q", it.Source, it.Path)
				}
			}
			sample(t, cur, 3)

			// 2) history: the core feature — must surface items from PAST versions (changelog). A history
			// item's Path is key@<timestamp> (jiraEmitHistory), distinct from current (key) / comment.
			hist, _ := liveCollect(t, base, "jira", Options{})
			histItems := 0
			for _, it := range hist {
				if v, _ := it.Meta["version"].(string); v != "" && v != "current" && !strings.HasPrefix(v, "comment") {
					histItems++
				}
			}
			t.Logf("    history-derived items: %d / %d", histItems, len(hist))
			sample(t, hist, 4)
			if histItems == 0 {
				t.Logf("    NOTE: no historical-version items in the first %d — issues scanned may have no changelog", len(hist))
			}
		})
	}
}

func TestLiveConfluenceServer(t *testing.T) {
	liveGuard(t)
	bases := []string{"https://cwiki.apache.org/confluence", "https://confluence.atlassian.com"}
	for _, base := range bases {
		t.Run(base, func(t *testing.T) {
			// current-only first (light), then a bounded history walk to exercise scanVersionsParallel.
			cur, dep := liveCollect(t, base, "confluence", Options{CurrentOnly: true})
			if dep.Product != "confluence" || dep.Kind == "" {
				t.Fatalf("bad deployment: %+v", dep)
			}
			if len(cur) == 0 {
				t.Fatalf("no items (anonymous read may be disabled)")
			}
			for _, it := range cur {
				if it.Source != "confluence" || it.Path == "" {
					t.Fatalf("bad item: source=%q path=%q", it.Source, it.Path)
				}
			}
			sample(t, cur, 3)

			hist, _ := liveCollect(t, base, "confluence", Options{})
			multiVer := 0
			for _, it := range hist {
				if n, ok := it.Meta["version"].(int); ok && n > 1 {
					multiVer++
				}
			}
			t.Logf("    items at version>1 (history walked): %d / %d", multiVer, len(hist))
			sample(t, hist, 4)
		})
	}
}
