package atlassian

import (
	"context"
	"net/url"
	"sort"

	"github.com/Lercas/prowl/tool/internal/model"
)

func sortedSelection(values []string) []string {
	result := append([]string{}, values...)
	sort.Strings(result)
	return result
}

// Scope contains operator selection and bounded acquisition policy, never auth or HTTPClient state.
func registerScope(ctx context.Context, base, product string, opts Options) {
	model.CoverageFrom(ctx).RegisterScope(product, scopeOrigin(base), struct {
		BaseURL                                           string
		Revision                                          string
		CurrentOnly                                       bool
		Projects, Spaces, Fields                          []string
		MaxItems, Workers, Pages, Versions, ResponseBytes int
		Timeout                                           int64
	}{base, "1.5.0-atlassian-v2", opts.CurrentOnly, sortedSelection(opts.Projects), sortedSelection(opts.Spaces), sortedSelection(opts.Fields), opts.MaxItems, workerCount(opts), maxPages, maxVersionsPerPage, maxResponseBytes, int64(opts.Timeout)})
}

// These are producer labels, not immutable revision proofs. In particular Jira changelogs contain
// old/new field fragments, and current comment bodies do not establish comment edit history.
func attachSourceMetadata(it *model.Item) {
	meta := make(map[string]any, len(it.Meta)+2)
	for key, value := range it.Meta {
		meta[key] = value
	}
	if raw, ok := meta["url"].(string); ok && raw != "" {
		meta["source_url"] = model.SafeLocator(raw)
	}
	if version, ok := meta["version"]; ok {
		meta["source_version"] = version
	}
	it.Meta = meta
}

func scopeOrigin(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return "[atlassian]"
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
}

// The logical URI is namespaced by product, transport and the normalized tenant context. The
// original browse URL remains in metadata; escaped local labels are not invented HTTP endpoints.
func qualifiedPath(base, product, local string) string {
	return product + "+" + base + "/" + url.PathEscape(local)
}
