package atlassian

import (
	"context"
	"fmt"
	"hash/fnv"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
)

// --- response shapes (v2 = Cloud, v1 = Server/DC) --------------------------

type confLinks struct {
	Next  string `json:"next"`
	Webui string `json:"webui"`
}

type confSpaceV2 struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}
type confSpacesPageV2 struct {
	Results []confSpaceV2 `json:"results"`
	Links   confLinks     `json:"_links"`
}

type confPageV2 struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	SpaceID string `json:"spaceId"`
	Version struct {
		Number int `json:"number"`
	} `json:"version"`
	Links confLinks `json:"_links"`
}
type confPagesPageV2 struct {
	Results []confPageV2 `json:"results"`
	Links   confLinks    `json:"_links"`
}

type confVersionV2 struct {
	Number    int    `json:"number"`
	CreatedAt string `json:"createdAt"`
	AuthorID  string `json:"authorId"`
}
type confVersionsPageV2 struct {
	Results []confVersionV2 `json:"results"`
	Links   confLinks       `json:"_links"`
}

type confBody struct {
	Storage struct {
		Value string `json:"value"`
	} `json:"storage"`
}
type confPageBodyV2 struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Body    confBody `json:"body"`
	Version struct {
		Number    int    `json:"number"`
		CreatedAt string `json:"createdAt"`
		AuthorID  string `json:"authorId"`
	} `json:"version"`
	Links confLinks `json:"_links"`
}

// Server/DC v1
type confContentV1 struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Body    confBody `json:"body"`
	Version struct {
		Number int    `json:"number"`
		When   string `json:"when"`
		By     struct {
			Email       string `json:"email"`
			DisplayName string `json:"displayName"`
		} `json:"by"`
	} `json:"version"`
	Links confLinks `json:"_links"`
}
type confContentPageV1 struct {
	Results []confContentV1 `json:"results"`
	Size    int             `json:"size"`
	Limit   int             `json:"limit"`
	Links   confLinks       `json:"_links"`
}
type confSpacesPageV1 struct {
	Results []struct {
		Key string `json:"key"`
	} `json:"results"`
	Size  int       `json:"size"`
	Limit int       `json:"limit"`
	Links confLinks `json:"_links"`
}
type confVersionsPageV1 struct {
	Results []struct {
		Number int    `json:"number"`
		When   string `json:"when"`
	} `json:"results"`
	Size  int       `json:"size"`
	Limit int       `json:"limit"`
	Links confLinks `json:"_links"`
}

// maxPages bounds offset-paginated loops (space/page/version listings on Server/DC) against a
// server that ignores `start` and re-serves the same page with _links.next forever.
const maxPages = 10000

// maxVersionsPerPage is a per-page fetch budget: a page with more versions than this caps how many
// version BODIES we fetch (independent of how many dedupe away). The global emitted-item cap counts
// EMITTED items, so a page whose versions all dedupe to one body would otherwise issue unbounded
// round-trips the cap never sees. We keep the most recent maxVersionsPerPage.
const maxVersionsPerPage = 5000

// capVersions enforces the per-page fetch budget with a loud warn, keeping the most recent (numerically
// largest) maxVersionsPerPage. It sorts first because the version-list endpoints return numbers in API
// order (Cloud v2 is newest-first), so a positional tail-slice would otherwise keep the OLDEST window.
func capVersions(versions []int, pageID string) []int {
	if len(versions) <= maxVersionsPerPage {
		return versions
	}
	logx.Warn("confluence: version count exceeds per-page budget — scanning the most recent only",
		"page", pageID, "versions", len(versions), "cap", maxVersionsPerPage)
	sorted := append([]int(nil), versions...)
	sort.Ints(sorted)
	return sorted[len(sorted)-maxVersionsPerPage:]
}

// scanVersionsParallel fetches each version of one page CONCURRENTLY, bounded by the shared sem so the
// total in-flight body fetches across ALL pages stay within the worker budget. It dedups byte-identical
// bodies per page (mutex-guarded) and emits the new ones. Fanning the per-version fetches out stops a
// single heavily-versioned page from monopolizing one pool worker while the others idle — Confluence
// has no bulk endpoint, so per-version concurrency is the only speed lever.
func scanVersionsParallel(ctx context.Context, sem chan struct{}, versions []int, fetch func(n int) (model.Item, bool), emit func(model.Item)) {
	type winner struct {
		n  int
		it model.Item
	}
	var mu sync.Mutex
	// bodyHash -> the item from the SMALLEST version number with that body. Picking the min version
	// (rather than whichever goroutine won the mutex race) makes the emitted Path/Fingerprint of an
	// unchanged-across-versions secret DETERMINISTIC across runs, so a --baseline doesn't flap. The min
	// is also the version where the secret first appeared with that content — the most useful locator.
	winners := map[uint64]winner{}
	// A bounded set of workers (<= the global sem capacity) pulls version numbers off a channel, rather
	// than spawning one goroutine per version — a page with thousands of versions would otherwise create
	// thousands of mostly-blocked goroutines. Concurrency is still bounded GLOBALLY by sem.
	nw := cap(sem)
	if nw < 1 {
		nw = 1
	}
	if nw > len(versions) {
		nw = len(versions)
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < nw; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range jobs {
				// Hold the sem ONLY across the fetch (the HTTP cost); release via defer so a fetch panic
				// can't leak a slot. The ctx.Done branch returns BEFORE the defer is registered, so it
				// never releases a slot it didn't acquire.
				it, ok := func() (model.Item, bool) {
					select {
					case sem <- struct{}{}:
					case <-ctx.Done():
						return model.Item{}, false
					}
					defer func() { <-sem }()
					return fetch(n)
				}()
				if !ok || it.Text == "" {
					continue
				}
				h := bodyHash(it.Text)
				mu.Lock()
				if w, exists := winners[h]; !exists || n < w.n {
					winners[h] = winner{n, it}
				}
				mu.Unlock()
			}
		}()
	}
	for _, n := range versions {
		if ctx.Err() != nil {
			break
		}
		select {
		case jobs <- n:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
	// Emit the deduped winners in a deterministic, version-ascending order.
	out := make([]winner, 0, len(winners))
	for _, w := range winners {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].n < out[j].n })
	for _, w := range out {
		emit(w.it)
	}
}

// --- walker ----------------------------------------------------------------

// walkConfluence drives the whole Confluence scan: spaces -> pages -> EVERY version of each page.
func walkConfluence(ctx context.Context, c *Client, dep Deployment, opts Options, emit func(model.Item)) error {
	logx.Info("confluence: scanning", "deployment", dep.String(), "history", !opts.CurrentOnly)
	if dep.Cloud() {
		if dep.CloudV1 {
			// only the legacy v1 Cloud API answered; the v2 walker below would 404 and scan nothing.
			return fmt.Errorf("this Confluence Cloud site exposes only the legacy v1 REST API (removed by Atlassian 2025-03-31) — the v2 scanner cannot run against it")
		}
		return walkConfluenceCloud(ctx, c, dep, opts, emit)
	}
	return walkConfluenceServer(ctx, c, dep, opts, emit)
}

// nextCursor pulls the opaque `cursor` value out of a v2 `_links.next` URL so we can re-issue the
// same path without worrying about whether the link is root- or context-relative.
func nextCursor(next string) string {
	if next == "" {
		return ""
	}
	i := strings.IndexByte(next, '?')
	if i < 0 {
		return ""
	}
	q, err := url.ParseQuery(next[i+1:])
	if err != nil {
		return ""
	}
	return q.Get("cursor")
}

func spaceWanted(key string, filter []string) bool {
	if len(filter) == 0 {
		return true
	}
	for _, f := range filter {
		if strings.EqualFold(f, key) {
			return true
		}
	}
	return false
}

// --- Confluence Cloud (v2) -------------------------------------------------

type confCloudJob struct {
	spaceKey string
	page     confPageV2
}

func walkConfluenceCloud(ctx context.Context, c *Client, dep Deployment, opts Options, emit func(model.Item)) error {
	spaces, err := confCloudSpaces(ctx, c, opts.Spaces)
	if err != nil {
		return err
	}
	workers := workerCount(opts)
	logx.Info("confluence: spaces", "count", len(spaces), "workers", workers)
	// sem bounds TOTAL in-flight version-body fetches across all pages to the worker budget, so a page
	// that fans its versions out (scanVersionsParallel) can't oversubscribe the host.
	sem := make(chan struct{}, workers)
	// Page LISTING per space stays sequential (cursor); each page's per-version body fetches — the
	// dominant Confluence cost — run across the worker pool.
	runPool(ctx, workers,
		func(push func(confCloudJob)) {
			for _, sp := range spaces {
				if ctx.Err() != nil {
					return
				}
				if err := confCloudEnumSpace(ctx, c, sp, func(p confPageV2) { push(confCloudJob{sp.Key, p}) }); err != nil {
					logx.Warn("confluence: space enumeration stopped early", "space", sp.Key, "err", err)
				}
			}
		},
		func(j confCloudJob) { confCloudScanPage(ctx, c, dep, sem, j.spaceKey, j.page, opts, emit) },
	)
	return nil
}

func confCloudSpaces(ctx context.Context, c *Client, filter []string) ([]confSpaceV2, error) {
	var out []confSpaceV2
	seen := map[string]bool{}
	// current AND archived spaces — pages in an archived space are otherwise invisible (T20).
	for _, status := range []string{"current", "archived"} {
		cursor := ""
		for pages := 0; ; pages++ {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			params := url.Values{"limit": {"250"}, "status": {status}}
			if cursor != "" {
				params.Set("cursor", cursor)
			}
			var page confSpacesPageV2
			if err := c.get(ctx, "/wiki/api/v2/spaces", params, &page); err != nil {
				if status == "archived" {
					break
				}
				return out, err
			}
			for _, s := range page.Results {
				if s.ID != "" && !seen[s.ID] && spaceWanted(s.Key, filter) {
					seen[s.ID] = true
					out = append(out, s)
				}
			}
			next := nextCursor(page.Links.Next)
			if next == "" || next == cursor || pages >= maxPages { // empty-but-with-cursor page is legitimate
				break
			}
			cursor = next
		}
	}
	return out, nil
}

func confCloudEnumSpace(ctx context.Context, c *Client, sp confSpaceV2, push func(confPageV2)) error {
	// Two status groups: live content (current+archived) is REQUIRED — its error fails the space; the
	// trashed/deleted pass is best-effort, so a build that rejects those statuses (a 400 on the
	// combined request) does not also lose the live pages (T20). seen dedupes a page in both groups.
	seen := map[string]bool{}
	groups := []struct {
		statuses []string
		required bool
	}{
		{[]string{"current", "archived"}, true},
		{[]string{"trashed", "deleted"}, false},
	}
	for _, g := range groups {
		cursor := ""
		for pages := 0; ; pages++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			params := url.Values{"limit": {"250"}}
			for _, st := range g.statuses {
				params.Add("status", st)
			}
			if cursor != "" {
				params.Set("cursor", cursor)
			}
			var page confPagesPageV2
			if err := c.get(ctx, "/wiki/api/v2/spaces/"+url.PathEscape(sp.ID)+"/pages", params, &page); err != nil {
				if !g.required {
					break // optional trashed/deleted unsupported — live pages already scanned
				}
				return err
			}
			for _, p := range page.Results {
				if p.ID == "" || seen[p.ID] {
					continue
				}
				seen[p.ID] = true
				push(p)
			}
			next := nextCursor(page.Links.Next)
			if next == "" || next == cursor || pages >= maxPages { // empty-but-with-cursor page is legitimate
				break
			}
			cursor = next
		}
	}
	return nil
}

func confCloudScanPage(ctx context.Context, c *Client, dep Deployment, sem chan struct{}, spaceKey string, p confPageV2, opts Options, emit func(model.Item)) {
	cur := p.Version.Number
	if cur == 0 { // a page list missing version.number must not become ?version=0 (which is skipped)
		cur = 1
	}
	versions := []int{cur}
	if !opts.CurrentOnly && cur > 1 { // cur==1 -> only one version exists; skip the version-list call
		// Enumerate version numbers WITHOUT body-format (T18: body-format caps limit at 50).
		all, err := confCloudPageVersions(ctx, c, p.ID)
		if err != nil {
			logx.Warn("confluence: version list failed", "page", p.ID, "err", err)
		} else if len(all) > 0 {
			versions = capVersions(all, p.ID)
			if !containsInt(versions, cur) {
				versions = append(versions, cur)
			}
		}
	}
	// Fetch the per-version bodies concurrently (bounded by sem) — see scanVersionsParallel.
	scanVersionsParallel(ctx, sem, versions, func(n int) (model.Item, bool) {
		params := url.Values{"body-format": {"storage"}, "version": {strconv.Itoa(n)}}
		var body confPageBodyV2
		if err := c.get(ctx, "/wiki/api/v2/pages/"+url.PathEscape(p.ID), params, &body); err != nil {
			logx.Warn("confluence: version body fetch failed", "page", p.ID, "version", n, "err", err)
			return model.Item{}, false
		}
		text := storageText(body.Body.Storage.Value)
		if text == "" {
			return model.Item{}, false
		}
		return model.Item{
			Source: "confluence",
			Path:   confPath(p.Title, p.ID, n),
			Text:   text,
			Meta: map[string]any{
				"url":     dep.BaseURL + dep.WikiPrefix + body.Links.Webui,
				"version": n,
				"page_id": p.ID,
				"space":   spaceKey,
				"updated": body.Version.CreatedAt,
			},
		}, true
	}, emit)
}

// storageEntities decodes ONLY the five XML predefined entities that Confluence storage XHTML uses to
// escape literal characters. A full html.UnescapeString would also decode 250+ HTML named entities and
// LEGACY semicolon-less forms (e.g. "&copy" -> "©"), which can corrupt a secret value that happens to
// contain such a byte sequence (notably inside a CDATA code block). strings.Replacer makes a single
// left-to-right pass, so a double-escaped "&amp;lt;" decodes once to the literal "&lt;", not to "<".
var storageEntities = strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'", "&amp;", "&")

// storageText prepares a Confluence storage body for scanning: it entity-decodes it (so a secret whose
// '&' is stored as '&amp;' — common in URLs/connection strings — is reconstructed contiguous and not
// split by the detector) WITHOUT stripping tags, so macro params and CDATA code blocks are still scanned
// in place (T23). leakhunt decoded via html2text; this rewrite must not drop that step.
func storageText(raw string) string {
	if raw == "" {
		return ""
	}
	return storageEntities.Replace(raw)
}

func confCloudPageVersions(ctx context.Context, c *Client, pageID string) ([]int, error) {
	var nums []int
	cursor := ""
	for pages := 0; ; pages++ {
		if err := ctx.Err(); err != nil {
			return nums, err
		}
		// NO sort param: the v2 VersionSortOrder enum is only {modified-date,-modified-date}; sending
		// sort=version makes the strict Cloud API return 400, which dropped the WHOLE page history.
		// Order is irrelevant here — every Number is collected regardless.
		params := url.Values{"limit": {"250"}}
		if cursor != "" {
			params.Set("cursor", cursor)
		}
		var page confVersionsPageV2
		if err := c.get(ctx, "/wiki/api/v2/pages/"+url.PathEscape(pageID)+"/versions", params, &page); err != nil {
			return nums, err
		}
		for _, v := range page.Results {
			nums = append(nums, v.Number)
		}
		next := nextCursor(page.Links.Next)
		if next == "" || next == cursor || pages >= maxPages { // empty-but-with-cursor page is legitimate
			return nums, nil
		}
		cursor = next
	}
}

// --- Confluence Server / Data Center (v1) ----------------------------------

type confServerJob struct {
	spaceKey string
	status   string
	page     confContentV1
}

func walkConfluenceServer(ctx context.Context, c *Client, dep Deployment, opts Options, emit func(model.Item)) error {
	keys, err := confServerSpaceKeys(ctx, c, opts.Spaces)
	if err != nil {
		return err
	}
	workers := workerCount(opts)
	logx.Info("confluence: spaces", "count", len(keys), "workers", workers)
	sem := make(chan struct{}, workers) // bounds total in-flight version-body fetches across pages
	runPool(ctx, workers,
		func(push func(confServerJob)) {
			for _, sk := range keys {
				if ctx.Err() != nil {
					return
				}
				if err := confServerEnumSpace(ctx, c, sk, func(status string, p confContentV1) {
					push(confServerJob{sk, status, p})
				}); err != nil {
					logx.Warn("confluence: space enumeration stopped early", "space", sk, "err", err)
				}
			}
		},
		func(j confServerJob) { confServerScanPage(ctx, c, dep, sem, j.spaceKey, j.status, j.page, opts, emit) },
	)
	return nil
}

func confServerSpaceKeys(ctx context.Context, c *Client, filter []string) ([]string, error) {
	if len(filter) > 0 {
		return filter, nil
	}
	// list current AND archived spaces — pages in an archived space are otherwise never visited (T20).
	var keys []string
	seen := map[string]bool{}
	for _, status := range []string{"current", "archived"} {
		start, pages := 0, 0
		for {
			if err := ctx.Err(); err != nil {
				return keys, err
			}
			params := url.Values{"limit": {"100"}, "start": {strconv.Itoa(start)}, "status": {status}}
			var page confSpacesPageV1
			if err := c.get(ctx, "/rest/api/space", params, &page); err != nil {
				if status == "archived" {
					break // some builds reject status=archived — current pass still ran
				}
				return keys, err
			}
			for _, s := range page.Results {
				if s.Key != "" && !seen[s.Key] {
					seen[s.Key] = true
					keys = append(keys, s.Key)
				}
			}
			pages++
			if page.Links.Next == "" || len(page.Results) == 0 {
				break
			}
			if pages >= maxPages {
				logx.Warn("confluence: space listing hit the page cap — some spaces not enumerated", "status", status)
				break
			}
			start += len(page.Results)
		}
	}
	return keys, nil
}

func confServerEnumSpace(ctx context.Context, c *Client, spaceKey string, push func(status string, p confContentV1)) error {
	// Walk current pages plus draft/trashed ones (a secret can linger in a trashed or never-published
	// page, T20). A status the build rejects is skipped, not fatal. seen dedupes a page that appears
	// under more than one status pass.
	seen := map[string]bool{}
	for _, status := range []string{"current", "draft", "trashed"} {
		start, pages := 0, 0
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			params := url.Values{
				"spaceKey": {spaceKey}, "type": {"page"}, "status": {status},
				"expand": {"version"}, "limit": {"100"}, "start": {strconv.Itoa(start)},
			}
			var page confContentPageV1
			if err := c.get(ctx, "/rest/api/content", params, &page); err != nil {
				if status != "current" {
					break // optional status unsupported on this build — keep the other passes
				}
				return err
			}
			for _, p := range page.Results {
				if p.ID == "" || seen[p.ID] {
					continue
				}
				seen[p.ID] = true
				push(status, p)
			}
			pages++
			if page.Links.Next == "" || len(page.Results) == 0 {
				break
			}
			if pages >= maxPages {
				logx.Warn("confluence: page listing hit the page cap — some pages not enumerated", "space", spaceKey, "status", status)
				break
			}
			start += len(page.Results)
		}
	}
	return nil
}

func confServerScanPage(ctx context.Context, c *Client, dep Deployment, sem chan struct{}, spaceKey, listStatus string, p confContentV1, opts Options, emit func(model.Item)) {
	current := p.Version.Number
	if current == 0 {
		current = 1
	}
	versions := []int{current}
	// Only walk history for live (current) pages: a draft/trashed page's live body is fetched with
	// its own status (below); its historical versions are not reliably retrievable, so scan just the
	// one we can read rather than fire 404s.
	if !opts.CurrentOnly && listStatus == "current" && current > 1 { // current==1 -> only one version
		all, err := confServerPageVersions(ctx, c, p.ID)
		if err != nil {
			logx.Warn("confluence: version list failed", "page", p.ID, "err", err)
		} else if len(all) > 0 {
			for _, n := range all {
				if n > current {
					current = n
				}
			}
			versions = capVersions(all, p.ID)
			// some DC builds omit the live version from /version — always scan the page's own
			// current number so the latest content is never dropped.
			if !containsInt(versions, current) {
				versions = append(versions, current)
			}
		}
	}
	// current is finalized above; the fetch closure reads it (no concurrent mutation).
	scanVersionsParallel(ctx, sem, versions, func(n int) (model.Item, bool) {
		// The live version is fetched WITHOUT status=historical (Confluence 404s
		// status=historical&version=<current>); a draft/trashed page's live body needs ITS status.
		// Older versions use the portable status=historical&version=N (works Confluence 5.7 -> 10.x).
		params := url.Values{"expand": {"body.storage,version"}}
		switch {
		case n != current:
			params.Set("status", "historical")
			params.Set("version", strconv.Itoa(n))
		case listStatus != "current" && listStatus != "":
			params.Set("status", listStatus)
		}
		var cont confContentV1
		if err := c.get(ctx, "/rest/api/content/"+url.PathEscape(p.ID), params, &cont); err != nil {
			logx.Warn("confluence: version body fetch failed", "page", p.ID, "version", n, "err", err)
			return model.Item{}, false
		}
		text := storageText(cont.Body.Storage.Value)
		if text == "" {
			return model.Item{}, false
		}
		author := cont.Version.By.Email
		if author == "" {
			author = cont.Version.By.DisplayName
		}
		return model.Item{
			Source: "confluence",
			Path:   confPath(p.Title, p.ID, n),
			Text:   text,
			Meta: map[string]any{
				"url":     dep.BaseURL + cont.Links.Webui,
				"version": n,
				"page_id": p.ID,
				"space":   spaceKey,
				"updated": cont.Version.When,
				"author":  author,
			},
		}, true
	}, emit)
}

func confServerPageVersions(ctx context.Context, c *Client, pageID string) ([]int, error) {
	// The version list is OFFSET-paginated: a page edited for years has hundreds of versions, and the
	// oldest (which may hold a since-removed secret) sit on later pages. A single fetch would silently
	// drop them — the exact T30 history-walk miss. Loop on start until the last page.
	path := "/rest/api/content/" + url.PathEscape(pageID) + "/version"
	exp := "/rest/experimental/content/" + url.PathEscape(pageID) + "/version"
	var nums []int
	start, pages := 0, 0
	for {
		if err := ctx.Err(); err != nil {
			return nums, err
		}
		params := url.Values{"start": {strconv.Itoa(start)}, "limit": {"200"}}
		var page confVersionsPageV1
		err := c.get(ctx, path, params, &page)
		if err != nil {
			if statusOf(err) == 404 && path != exp {
				path = exp // DC 7.x / Server expose the version list only under /rest/experimental
				continue
			}
			return nums, err
		}
		for _, v := range page.Results {
			nums = append(nums, v.Number)
		}
		pages++
		// Primary terminal is the absence of _links.next (Confluence v1 sets it whenever more rows
		// remain); a short page is NOT treated as terminal here, so a partial middle page cannot drop
		// the older versions on later pages. maxPages backstops a server that never drops next.
		if page.Links.Next == "" || len(page.Results) == 0 {
			return nums, nil
		}
		if pages >= maxPages {
			logx.Warn("confluence: version list exceeded the page cap — older versions not enumerated", "page", pageID)
			return nums, nil
		}
		start += len(page.Results)
	}
}

// confPath builds the finding Path. It embeds the page ID so two DISTINCT pages that share a title and
// version (a copied "Runbook" template across spaces) do NOT collapse to one Fingerprint (sha256 over
// type|path|value) — which would make a --baseline / SARIF / DefectDojo dedupe silently hide the second
// page's leak. leakhunt keyed page identity on the page_id for the same reason.
func confPath(title, pageID string, version int) string {
	title = strings.TrimSpace(title)
	if title == "" {
		title = "(untitled)"
	}
	if pageID != "" {
		title += " (" + pageID + ")"
	}
	return title + "@v" + strconv.Itoa(version)
}

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// bodyHash is a fast non-cryptographic hash used only to detect a page version whose storage body is
// byte-identical to one already scanned (de-dup), never for security.
func bodyHash(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}
