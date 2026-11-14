package atlassian

import (
	"context"
	"errors"
	"fmt"
	"math"
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
	Status  string `json:"status"`
	SpaceID string `json:"spaceId"`
	Version struct {
		Number int `json:"number"`
	} `json:"version"`
	Links confLinks `json:"_links"`
	// Keep the listing filter when optional response metadata does not identify the status.
	listStatuses []string
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
		Value *string `json:"value"`
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

// versionWindow counts distinct versions, not repeated entries from overlapping API pages.
func versionWindow(versions []int, limit int) ([]int, bool) {
	window := newBoundedVersions(limit)
	for _, n := range versions {
		window.add(n)
	}
	return window.window()
}

func itemVersionRank(it model.Item, fallback int) int {
	if n, ok := it.Meta["version"].(int); ok && n > 0 {
		return n
	}
	if fallback > 0 {
		return fallback
	}
	return math.MaxInt
}

func withVersionSlot(ctx context.Context, sem chan struct{}, fetch func() error) error {
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-sem }()
	return fetch()
}

// scanVersionsParallel fetches each version of one page CONCURRENTLY, bounded by the shared sem so the
// total in-flight body fetches across ALL pages stay within the worker budget. It dedups byte-identical
// bodies per page (mutex-guarded) and emits the new ones. Fanning the per-version fetches out stops a
// single heavily-versioned page from monopolizing one pool worker while the others idle — Confluence
// has no bulk endpoint, so per-version concurrency is the only speed lever.
func scanVersionsParallel(ctx context.Context, sem chan struct{}, versions []int, fetch func(n int) (model.Item, bool), emit func(model.Item), initial ...model.Item) {
	type winner struct {
		n  int
		it model.Item
	}
	var mu sync.Mutex
	// Exact text -> the item from the SMALLEST version number with that body. Picking the min version
	// (rather than whichever goroutine won the mutex race) makes the emitted Path/Fingerprint of an
	// unchanged-across-versions secret DETERMINISTIC across runs, so a --baseline doesn't flap. The min
	// is also the version where the secret first appeared with that content — the most useful locator.
	winners := map[string]winner{}
	for _, it := range initial {
		if it.Text != "" {
			winners[it.Text] = winner{itemVersionRank(it, 0), it}
		}
	}
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
				if it.Error != nil {
					emit(it)
					continue
				}
				if !ok || it.Text == "" {
					continue
				}
				rank := itemVersionRank(it, n)
				mu.Lock()
				if w, exists := winners[it.Text]; !exists || rank < w.n {
					winners[it.Text] = winner{rank, it}
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
	u, err := url.Parse(next)
	if err != nil {
		return ""
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return ""
	}
	values := q["cursor"]
	if len(values) != 1 {
		return ""
	}
	return values[0]
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
		emit(sourceFailure("confluence", "spaces", "space listing failed"))
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
					emit(sourceFailure("confluence", sp.Key, "space enumeration failed"))
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
		var walk cursorWalk
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
				if status == "archived" && unsupportedStatus(err, pages == 0) {
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
			if page.Links.Next != "" && next == "" {
				return out, fmt.Errorf("invalid pagination link")
			}
			if err := walk.advance(next); err != nil {
				return out, err
			}
			if next == "" {
				break
			}
			cursor = next
		}
	}
	return out, nil
}

func confCloudEnumSpace(ctx context.Context, c *Client, sp confSpaceV2, push func(confPageV2)) error {
	// Two status groups: live content (current+archived) is REQUIRED — its error marks the walk incomplete; the
	// trashed/deleted pass is best-effort, so a build that rejects those statuses (a 400 on the
	// combined request) does not also lose the live pages (T20). seen dedupes a page in both groups.
	seen := map[string]bool{}
	type statusGroup struct {
		statuses []string
		required bool
	}
	groups := []statusGroup{
		{[]string{"current", "archived"}, true},
		{[]string{"trashed", "deleted"}, false},
	}
	var failures []error
	for group := 0; group < len(groups); group++ {
		g := groups[group]
		cursor := ""
		var walk cursorWalk
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
				if !g.required && unsupportedStatus(err, pages == 0) {
					// A rejected combined filter does not prove each status is unsupported.
					if len(g.statuses) > 1 {
						for _, status := range g.statuses {
							groups = append(groups, statusGroup{[]string{status}, false})
						}
					}
					break
				}
				failures = append(failures, err)
				break
			}
			for _, p := range page.Results {
				if p.ID == "" || seen[p.ID] {
					continue
				}
				seen[p.ID] = true
				p.listStatuses = g.statuses
				push(p)
			}
			next := nextCursor(page.Links.Next)
			if page.Links.Next != "" && next == "" {
				failures = append(failures, fmt.Errorf("invalid pagination link"))
				break
			}
			if err := walk.advance(next); err != nil {
				failures = append(failures, err)
				break
			}
			if next == "" {
				break
			}
			cursor = next
		}
	}
	return errors.Join(failures...)
}

func confCloudScanPage(ctx context.Context, c *Client, dep Deployment, sem chan struct{}, spaceKey string, p confPageV2, opts Options, emit func(model.Item)) {
	cur := p.Version.Number
	fetch := func(n int) (model.Item, bool) {
		params := url.Values{"body-format": {"storage"}, "include-version": {"true"}}
		statuses := p.listStatuses
		if p.Status != "" {
			statuses = []string{p.Status}
		}
		for _, status := range statuses {
			params.Add("status", status)
		}
		if n > 0 {
			params.Set("version", strconv.Itoa(n))
			if n != cur && len(statuses) > 0 {
				params.Add("status", "historical")
			}
		}
		var body confPageBodyV2
		if err := c.get(ctx, "/wiki/api/v2/pages/"+url.PathEscape(p.ID), params, &body); err != nil {
			return sourceFailure("confluence", confPath(p.Title, p.ID, n), "version body fetch failed"), false
		}
		version := n
		if body.Version.Number > 0 {
			version = body.Version.Number
			if n > 0 && version != n {
				emit(sourceFailure("confluence", confPath(p.Title, p.ID, n), "requested version differs from response metadata"))
			}
		}
		return confBodyItem(p.Title, p.ID, spaceKey, version, storageText(*body.Body.Storage.Value),
			dep.BaseURL+dep.WikiPrefix+body.Links.Webui, body.Version.CreatedAt, ""), true
	}
	// Read the live body independently of page-list and version-list snapshots. Either listing
	// can lag behind an edit; pinning its number would miss the actual latest content.
	var live model.Item
	var liveOK bool
	if withVersionSlot(ctx, sem, func() error { live, liveOK = fetch(0); return nil }) != nil {
		return
	}
	if live.Error != nil {
		emit(live)
	}
	if opts.CurrentOnly {
		if liveOK && live.Text != "" {
			emit(live)
		}
		return
	}
	var initial []model.Item
	if liveOK {
		initial = append(initial, live)
	}
	// Finalize the live number before historical workers start using the fetch closure.
	cur, _ = live.Meta["version"].(int)
	versions := []int{p.Version.Number, cur}
	var listingCapped bool
	if cur != 1 || p.Version.Number > 1 || !liveOK {
		all, capped, err := confCloudPageVersions(ctx, c, p.ID)
		listingCapped = capped
		if err != nil {
			emit(sourceFailure("confluence", p.ID+"#versions", "version listing failed"))
		}
		if len(all) == 0 && err == nil {
			emit(sourceFailure("confluence", p.ID+"#versions", "version listing is empty for an existing page"))
		}
		versions = append(versions, all...)
	}
	// The live attempt spends one body slot even on failure. A known successful live number is
	// cached, including an explicitly empty body, and must not be fetched again as historical.
	pending := make([]int, 0, len(versions))
	for _, n := range versions {
		if n > 0 && (!liveOK || n != cur) {
			pending = append(pending, n)
		}
	}
	pending, capped := versionWindow(pending, maxVersionsPerPage-1)
	if capped || listingCapped {
		emit(sourceFailure("confluence", p.ID+"#versions", "version budget exhausted"))
	}
	scanVersionsParallel(ctx, sem, pending, fetch, emit, initial...)
}

func confBodyItem(title, pageID, spaceKey string, version int, text, bodyURL, updated, author string) model.Item {
	var metaVersion any = version
	if version <= 0 {
		metaVersion = "current"
	}
	return model.Item{Source: "confluence", Path: confPath(title, pageID, version), Text: text,
		Meta: map[string]any{"url": bodyURL, "version": metaVersion, "page_id": pageID,
			"space": spaceKey, "updated": updated, "author": author}}
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

func confCloudPageVersions(ctx context.Context, c *Client, pageID string) ([]int, bool, error) {
	window := newBoundedVersions(maxVersionsPerPage)
	cursor := ""
	var walk cursorWalk
	for {
		if err := ctx.Err(); err != nil {
			return window.listing(err)
		}
		// NO sort param: the v2 VersionSortOrder enum is only {modified-date,-modified-date}; sending
		// sort=version makes the strict Cloud API return 400, which dropped the WHOLE page history.
		// Page order cannot affect the retained window: keep the highest distinct numbers.
		params := url.Values{"limit": {"250"}}
		if cursor != "" {
			params.Set("cursor", cursor)
		}
		var page confVersionsPageV2
		if err := c.get(ctx, "/wiki/api/v2/pages/"+url.PathEscape(pageID)+"/versions", params, &page); err != nil {
			return window.listing(err)
		}
		for _, v := range page.Results {
			window.add(v.Number)
		}
		next := nextCursor(page.Links.Next)
		if page.Links.Next != "" && next == "" {
			return window.listing(fmt.Errorf("invalid pagination link"))
		}
		if err := walk.advance(next); err != nil {
			return window.listing(err)
		}
		if next == "" {
			return window.listing(nil)
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
		emit(sourceFailure("confluence", "spaces", "space listing failed"))
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
					emit(sourceFailure("confluence", sk, "space enumeration failed"))
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
				if status == "archived" && unsupportedStatus(err, pages == 0) {
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
			if page.Links.Next == "" {
				break
			}
			if len(page.Results) == 0 {
				return keys, fmt.Errorf("empty page with pagination link")
			}
			if pages >= maxPages {
				return keys, fmt.Errorf("space page budget exhausted")
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
	var failures []error
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
				if status != "current" && unsupportedStatus(err, pages == 0) {
					break // optional status unsupported on this build — keep the other passes
				}
				failures = append(failures, err)
				break
			}
			for _, p := range page.Results {
				if p.ID == "" || seen[p.ID] {
					continue
				}
				seen[p.ID] = true
				push(status, p)
			}
			pages++
			if page.Links.Next == "" {
				break
			}
			if len(page.Results) == 0 {
				failures = append(failures, fmt.Errorf("empty page with pagination link"))
				break
			}
			if pages >= maxPages {
				failures = append(failures, fmt.Errorf("content page budget exhausted"))
				break
			}
			start += len(page.Results)
		}
	}
	return errors.Join(failures...)
}

func confServerScanPage(ctx context.Context, c *Client, dep Deployment, sem chan struct{}, spaceKey, listStatus string, p confContentV1, opts Options, emit func(model.Item)) {
	// Fetch the live body once before choosing history requests. An edit between the page list
	// and this request must not label a new body with the old list's version number.
	params := url.Values{"expand": {"body.storage,version"}}
	if listStatus != "" && listStatus != "current" {
		params.Set("status", listStatus)
	}
	var live confContentV1
	liveErr := withVersionSlot(ctx, sem, func() error {
		return c.get(ctx, "/rest/api/content/"+url.PathEscape(p.ID), params, &live)
	})
	current := live.Version.Number
	var initial []model.Item
	if liveErr != nil {
		emit(sourceFailure("confluence", confPath(p.Title, p.ID, 0), "current body fetch failed"))
	} else {
		author := live.Version.By.Email
		if author == "" {
			author = live.Version.By.DisplayName
		}
		initial = append(initial, confBodyItem(p.Title, p.ID, spaceKey, current,
			storageText(*live.Body.Storage.Value), dep.BaseURL+live.Links.Webui, live.Version.When, author))
	}
	// Draft/trashed history is outside the supported Server/DC API contour.
	if opts.CurrentOnly || (listStatus != "" && listStatus != "current") {
		for _, it := range initial {
			if it.Text != "" {
				emit(it)
			}
		}
		return
	}
	versions := []int{p.Version.Number, current}
	var listingCapped bool
	if current != 1 || p.Version.Number > 1 || liveErr != nil {
		all, capped, err := confServerPageVersions(ctx, c, p.ID)
		listingCapped = capped
		if err != nil {
			emit(sourceFailure("confluence", p.ID+"#versions", "version listing failed"))
		}
		if len(all) == 0 && err == nil && (current > 1 || p.Version.Number > 1 || current == 0) {
			emit(sourceFailure("confluence", p.ID+"#versions", "version listing is empty for an existing page"))
		}
		versions = append(versions, all...)
	}
	// The live request has already spent one body slot, even if its metadata/body was unavailable.
	// Its known number is cached; only other numbers consume further requests.
	pending := make([]int, 0, len(versions))
	for _, n := range versions {
		if n > 0 && (liveErr != nil || n != current) {
			pending = append(pending, n)
		}
	}
	pending, capped := versionWindow(pending, maxVersionsPerPage-1)
	if capped || listingCapped {
		emit(sourceFailure("confluence", p.ID+"#versions", "version budget exhausted"))
	}
	fetch := func(n int) (model.Item, bool) {
		q := url.Values{"expand": {"body.storage,version"}, "status": {"historical"}, "version": {strconv.Itoa(n)}}
		var body confContentV1
		if err := c.get(ctx, "/rest/api/content/"+url.PathEscape(p.ID), q, &body); err != nil {
			return sourceFailure("confluence", confPath(p.Title, p.ID, n), "version body fetch failed"), false
		}
		version := n
		if body.Version.Number > 0 {
			version = body.Version.Number
			if version != n {
				emit(sourceFailure("confluence", confPath(p.Title, p.ID, n), "requested version differs from response metadata"))
			}
		}
		author := body.Version.By.Email
		if author == "" {
			author = body.Version.By.DisplayName
		}
		return confBodyItem(p.Title, p.ID, spaceKey, version, storageText(*body.Body.Storage.Value),
			dep.BaseURL+body.Links.Webui, body.Version.When, author), true
	}
	scanVersionsParallel(ctx, sem, pending, fetch, emit, initial...)
}

func confServerPageVersions(ctx context.Context, c *Client, pageID string) ([]int, bool, error) {
	// The version list is OFFSET-paginated: a page edited for years has hundreds of versions, and the
	// oldest (which may hold a since-removed secret) sit on later pages. A single fetch would silently
	// drop them — the exact T30 history-walk miss. Loop on start until the last page.
	path := "/rest/api/content/" + url.PathEscape(pageID) + "/version"
	exp := "/rest/experimental/content/" + url.PathEscape(pageID) + "/version"
	window := newBoundedVersions(maxVersionsPerPage)
	start, pages := 0, 0
	for {
		if err := ctx.Err(); err != nil {
			return window.listing(err)
		}
		params := url.Values{"start": {strconv.Itoa(start)}, "limit": {"200"}}
		var page confVersionsPageV1
		err := c.get(ctx, path, params, &page)
		if err != nil {
			if statusOf(err) == 404 && path != exp {
				path = exp // DC 7.x / Server expose the version list only under /rest/experimental
				continue
			}
			return window.listing(err)
		}
		for _, v := range page.Results {
			window.add(v.Number)
		}
		pages++
		// Primary terminal is the absence of _links.next (Confluence v1 sets it whenever more rows
		// remain); a short page is NOT treated as terminal here, so a partial middle page cannot drop
		// the older versions on later pages. maxPages backstops a server that never drops next.
		if page.Links.Next == "" {
			return window.listing(nil)
		}
		if len(page.Results) == 0 {
			return window.listing(fmt.Errorf("empty page with pagination link"))
		}
		if pages >= maxPages {
			return window.listing(fmt.Errorf("version page budget exhausted"))
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
	if version <= 0 {
		return title + "@current"
	}
	return title + "@v" + strconv.Itoa(version)
}
