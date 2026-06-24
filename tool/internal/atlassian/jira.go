package atlassian

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
)

// jiraTextFields are the built-in issue fields scanned as text/ADF. Comments are handled separately
// (jiraScanComments, paginated) and custom textarea/url fields are added via --field (opts.Fields).
var jiraTextFields = []string{"summary", "description", "environment"}

func jiraAPIVer(dep Deployment) string {
	if dep.Cloud() {
		return "3" // Cloud: v3 (ADF bodies; adfText handles them). Server/DC has no v3.
	}
	return "2" // Server/DC: v2 only, bodies are wiki-markup strings.
}

// --- response shapes -------------------------------------------------------

type jiraProjectPage struct {
	StartAt    int  `json:"startAt"`
	MaxResults int  `json:"maxResults"`
	Total      int  `json:"total"`
	IsLast     bool `json:"isLast"`
	Values     []struct {
		Key string `json:"key"`
	} `json:"values"`
}

type jiraIssue struct {
	ID     string         `json:"id"`
	Key    string         `json:"key"`
	Fields map[string]any `json:"fields"`
}

type jiraSearchPage struct {
	Issues        []jiraIssue `json:"issues"`
	NextPageToken string      `json:"nextPageToken"` // Cloud /search/jql cursor
	IsLast        bool        `json:"isLast"`        // Cloud
	StartAt       int         `json:"startAt"`       // Server/DC /search
	MaxResults    int         `json:"maxResults"`    // Server/DC
	Total         int         `json:"total"`         // Server/DC (absent on Cloud /search/jql)
}

type jiraAuthor struct {
	DisplayName  string `json:"displayName"`
	EmailAddress string `json:"emailAddress"`
	AccountID    string `json:"accountId"`
}

func (a jiraAuthor) label() string {
	if a.EmailAddress != "" {
		return a.EmailAddress
	}
	if a.DisplayName != "" {
		return a.DisplayName
	}
	return a.AccountID
}

type jiraHistory struct {
	ID      string     `json:"id"`
	Created string     `json:"created"`
	Author  jiraAuthor `json:"author"`
	Items   []struct {
		Field      string `json:"field"`
		FieldID    string `json:"fieldId"`
		FromString string `json:"fromString"`
		ToString   string `json:"toString"`
	} `json:"items"`
}

type jiraChangelogPage struct {
	StartAt    int           `json:"startAt"`
	MaxResults int           `json:"maxResults"`
	Total      int           `json:"total"`
	IsLast     bool          `json:"isLast"`
	Values     []jiraHistory `json:"values"`    // dedicated /changelog endpoint
	Histories  []jiraHistory `json:"histories"` // embedded issue?expand=changelog form
}

func (p jiraChangelogPage) entries() []jiraHistory {
	if len(p.Values) > 0 {
		return p.Values
	}
	return p.Histories
}

// --- walker ----------------------------------------------------------------

// walkJira drives the whole Jira scan: projects -> issues (oldest first) -> current content + full
// changelog history. Each scannable unit is handed to emit as a model.Item. It returns the first
// fatal error (auth/enumeration); per-issue errors are logged and skipped so one bad issue does not
// abort the run.
func walkJira(ctx context.Context, c *Client, dep Deployment, opts Options, emit func(model.Item)) error {
	keys, err := jiraProjects(ctx, c, dep, opts.Projects)
	if err != nil {
		return err
	}
	logx.Info("jira: scanning projects", "count", len(keys), "deployment", dep.String(),
		"history", !opts.CurrentOnly, "workers", workerCount(opts))
	// The JQL search cursor stays sequential per project; the detail work runs across a worker pool.
	// Two job kinds keep parallelism FINE-grained while still batching history on Cloud:
	//   - a per-issue job: current fields + all comments (+ per-issue changelog on Server/DC, which has
	//     no bulk endpoint), so chatty issues parallelize across workers;
	//   - a bulk-history job (Cloud only): ONE /changelog/bulkfetch for jiraBatchSize issues at once,
	//     instead of one /changelog call per issue.
	bulk := dep.Cloud() && !opts.CurrentOnly
	runPool(ctx, workerCount(opts),
		func(push func(jiraJob)) {
			var hbatch []jiraIssue
			for _, pk := range keys {
				if ctx.Err() != nil {
					break
				}
				err := jiraEnumProject(ctx, c, dep, pk, opts, func(iss jiraIssue) {
					push(jiraJob{issue: iss})
					if bulk {
						hbatch = append(hbatch, iss)
						if len(hbatch) >= jiraBatchSize {
							push(jiraJob{history: hbatch})
							hbatch = nil
						}
					}
				})
				if err != nil {
					logx.Warn("jira: project enumeration stopped early", "project", pk, "err", err)
				}
			}
			if len(hbatch) > 0 {
				push(jiraJob{history: hbatch})
			}
		},
		func(j jiraJob) { jiraDoJob(ctx, c, dep, opts, j, emit) },
	)
	return nil
}

// jiraBatchSize is how many issues share one bulk changelog fetch on Cloud.
const jiraBatchSize = 50

// jiraJob is one unit of pool work: a per-issue job (history == nil) or a bulk-history batch.
type jiraJob struct {
	issue   jiraIssue
	history []jiraIssue
}

func jiraDoJob(ctx context.Context, c *Client, dep Deployment, opts Options, j jiraJob, emit func(model.Item)) {
	if ctx.Err() != nil {
		return
	}
	if j.history != nil {
		jiraBulkHistory(ctx, c, dep, j.history, emit) // Cloud: one fetch for the whole batch
		return
	}
	iss := j.issue
	scanFields := append(append([]string{}, jiraTextFields...), opts.Fields...)
	jiraEmitCurrent(dep, scanFields, iss, emit)
	jiraScanComments(ctx, c, dep, iss, emit)
	if !opts.CurrentOnly && !dep.Cloud() { // Server/DC has no bulk endpoint -> per-issue history here
		if err := jiraScanHistory(ctx, c, dep, iss.Key, emit); err != nil {
			logx.Warn("jira: changelog fetch failed", "issue", iss.Key, "err", err)
		}
	}
}

type jiraBulkHistoryPage struct {
	NextPageToken   string `json:"nextPageToken"`
	IssueChangeLogs []struct {
		IssueID         string        `json:"issueId"`
		ChangeHistories []jiraHistory `json:"changeHistories"`
	} `json:"issueChangeLogs"`
}

// jiraBulkHistory fetches the full changelog for a whole batch of issues in one (paginated) Cloud
// POST /rest/api/3/changelog/bulkfetch call — ~jiraBatchSize fewer round-trips than per-issue. It
// reconstructs old field values from items[].fromString/toString exactly as the per-issue path does,
// and falls back to per-issue changelog if the endpoint is unavailable on an older Cloud.
func jiraBulkHistory(ctx context.Context, c *Client, dep Deployment, batch []jiraIssue, emit func(model.Item)) {
	idToKey := make(map[string]string, len(batch))
	ids := make([]string, 0, len(batch))
	for _, iss := range batch {
		if iss.ID != "" {
			ids = append(ids, iss.ID)
			idToKey[iss.ID] = iss.Key
		}
	}
	if len(ids) == 0 {
		return
	}
	seen := make(map[string]bool, len(ids))
	errored := false
	token := ""
	for pages := 0; ; pages++ {
		if ctx.Err() != nil {
			return
		}
		body := map[string]any{"issueIdsOrKeys": ids, "maxResults": 1000}
		if token != "" {
			body["nextPageToken"] = token
		}
		var page jiraBulkHistoryPage
		if err := c.post(ctx, "/rest/api/3/changelog/bulkfetch", nil, body, &page); err != nil {
			// Any failure — endpoint gone (404/405 on an older Cloud) or transient (5xx/network) on the
			// first OR a later page — stops pagination; the post-loop fallback then fetches the UNSEEN
			// issues per-issue. Issues already emitted from earlier pages are in `seen`, so they are NOT
			// re-fetched (no double-emit), and issues that only appear on dropped later pages are not lost.
			if s := statusOf(err); s != 404 && s != 405 {
				logx.Warn("jira: bulk changelog failed", "err", err)
			}
			errored = true
			break
		}
		for _, icl := range page.IssueChangeLogs {
			seen[icl.IssueID] = true
			key := idToKey[icl.IssueID]
			if key == "" {
				key = icl.IssueID
			}
			for _, h := range icl.ChangeHistories {
				jiraEmitHistory(dep, key, h, emit)
			}
		}
		if page.NextPageToken == "" || page.NextPageToken == token || pages >= maxPages {
			break
		}
		token = page.NextPageToken
	}
	// Per-issue fallback for issues NOT emitted by the bulk response. On an ERROR, fetch every unseen
	// issue (its history was genuinely not retrieved). On a CLEAN run, only fall back when a MINORITY are
	// missing — a large omission means the endpoint simply does not return no-history issues (correct to
	// skip), and falling back on all of them would defeat the batch.
	var missing []jiraIssue
	for _, iss := range batch {
		if iss.ID != "" && !seen[iss.ID] {
			missing = append(missing, iss)
		}
	}
	if len(missing) > 0 && (errored || len(missing)*2 <= len(ids)) {
		for _, iss := range missing {
			if e := jiraScanHistory(ctx, c, dep, iss.Key, emit); e != nil {
				logx.Warn("jira: changelog fetch failed", "issue", iss.Key, "err", e)
			}
		}
	}
}

func jiraProjects(ctx context.Context, c *Client, dep Deployment, filter []string) ([]string, error) {
	if len(filter) > 0 {
		return filter, nil // explicit --project list: trust it, skip enumeration
	}
	v := jiraAPIVer(dep)
	if !dep.Cloud() {
		var projects []struct {
			Key string `json:"key"`
		}
		if err := c.get(ctx, "/rest/api/"+v+"/project", nil, &projects); err != nil {
			return nil, err
		}
		keys := make([]string, 0, len(projects))
		for _, p := range projects {
			if p.Key != "" {
				keys = append(keys, p.Key)
			}
		}
		return keys, nil
	}
	var keys []string
	startAt := 0
	for pages := 0; ; pages++ {
		if err := ctx.Err(); err != nil {
			return keys, err
		}
		var page jiraProjectPage
		params := url.Values{"startAt": {strconv.Itoa(startAt)}, "maxResults": {"50"}}
		if err := c.get(ctx, "/rest/api/"+v+"/project/search", params, &page); err != nil {
			return keys, err
		}
		for _, p := range page.Values {
			if p.Key != "" {
				keys = append(keys, p.Key)
			}
		}
		if page.IsLast || len(page.Values) == 0 {
			break
		}
		step := page.MaxResults
		if step <= 0 { // a server reporting maxResults=0 must not stall startAt into an infinite loop
			step = len(page.Values)
		}
		startAt += step
		if (page.Total > 0 && startAt >= page.Total) || pages >= maxPages {
			break
		}
	}
	return keys, nil
}

// jiraEnumProject enumerates a project's issues (oldest first) via the JQL search cursor and hands
// each to push (which queues it to the worker pool). The search response already carries the current
// field values; the per-issue detail fetches happen in jiraProcessIssue.
func jiraEnumProject(ctx context.Context, c *Client, dep Deployment, projectKey string, opts Options, push func(jiraIssue)) error {
	// Escape backslash BEFORE quote so a key ending in '\' can't escape the closing quote and break
	// (or inject into) the JQL. Real project keys are alnum, but a typo'd --project must stay inert.
	jql := `project="` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(projectKey) + `" ORDER BY created ASC`
	// scanFields are the text/ADF fields extracted from each issue; --field custom textareas are
	// included so they are both REQUESTED and EXTRACTED (the flag was previously a no-op). comment is
	// requested too, but its bodies are scanned by jiraScanComments (the search field is capped ~20).
	scanFields := append(append([]string{}, jiraTextFields...), opts.Fields...)
	fields := strings.Join(append(append([]string{}, scanFields...), "comment"), ",")
	v := jiraAPIVer(dep)

	emitIssue := push

	if dep.Cloud() {
		// Cloud: GET /search/jql, cursor pagination (no total/startAt), fields REQUIRED (T7/T8).
		token := ""
		for pages := 0; ; pages++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			params := url.Values{"jql": {jql}, "fields": {fields}, "maxResults": {"100"}}
			if token != "" {
				params.Set("nextPageToken", token)
			}
			var page jiraSearchPage
			if err := c.get(ctx, "/rest/api/"+v+"/search/jql", params, &page); err != nil {
				return err
			}
			for _, iss := range page.Issues {
				emitIssue(iss)
			}
			// Terminate ONLY on no cursor or isLast — an empty page that still carries a
			// nextPageToken is legitimate (results still materializing, or a fully permission-
			// filtered page), so len(issues)==0 must NOT stop the walk. The token==token guard stops a
			// repeated cursor; the pages cap stops a server that streams distinct empty cursors forever
			// (the item budget can't, since it only fires inside emit and an empty page emits nothing).
			if page.NextPageToken == "" || page.IsLast || page.NextPageToken == token || pages >= maxPages {
				return nil
			}
			token = page.NextPageToken
		}
	}

	// Server/DC: POST /search, classic startAt/maxResults/total pagination. Terminate on the server's
	// total (when present) or an empty page; a SHORT page is NOT treated as terminal (a permission-
	// thinned middle page would drop later pages — and with no total there is no reliable short-page
	// signal). The pages cap backstops a server that ignores startAt and never returns empty.
	startAt := 0
	for pages := 0; ; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		body := map[string]any{
			"jql": jql, "startAt": startAt, "maxResults": 100,
			"fields": append(append([]string{}, scanFields...), "comment"),
		}
		var page jiraSearchPage
		if err := c.post(ctx, "/rest/api/"+v+"/search", nil, body, &page); err != nil {
			return err
		}
		for _, iss := range page.Issues {
			emitIssue(iss)
		}
		got := len(page.Issues)
		if got == 0 {
			return nil
		}
		startAt += got
		if page.Total > 0 && startAt >= page.Total {
			return nil
		}
		if pages >= maxPages {
			logx.Warn("jira: search page cap reached — some issues not enumerated", "project", projectKey)
			return nil
		}
	}
}

// jiraEmitCurrent extracts the current value of every scan field (summary, description, environment,
// and any --field custom textarea/url field — ADF or string) into one scannable item.
func jiraEmitCurrent(dep Deployment, scanFields []string, iss jiraIssue, emit func(model.Item)) {
	var b strings.Builder
	for _, f := range scanFields {
		if t := fieldText(iss.Fields[f]); t != "" {
			b.WriteString(t)
			b.WriteByte('\n')
		}
	}
	text := strings.TrimSpace(b.String())
	if text == "" {
		return
	}
	emit(model.Item{
		Source: "jira",
		Path:   iss.Key,
		Text:   text,
		Meta: map[string]any{
			"url":     dep.BaseURL + "/browse/" + iss.Key,
			"version": "current",
		},
	})
}

type jiraCommentPage struct {
	StartAt    int `json:"startAt"`
	MaxResults int `json:"maxResults"`
	Total      int `json:"total"`
	Comments   []struct {
		ID   string `json:"id"`
		Body any    `json:"body"`
	} `json:"comments"`
}

// jiraScanComments scans EVERY comment body. The search `comment` field is capped (~20 comments), so
// when it reports more than it returned, the full set is paged from the dedicated /comment endpoint —
// otherwise an old comment that holds a secret is silently missed. Each comment is its own item so
// one chatty issue can't fill the per-item match cap and so the path attributes the finding.
func jiraScanComments(ctx context.Context, c *Client, dep Deployment, iss jiraIssue, emit func(model.Item)) {
	cm, _ := iss.Fields["comment"].(map[string]any)
	var inline []any
	total := 0
	if cm != nil {
		if arr, ok := cm["comments"].([]any); ok {
			inline = arr
		}
		if t, ok := cm["total"].(float64); ok {
			total = int(t)
		}
	}
	if total > len(inline) { // search truncated the comments — page the dedicated endpoint for all
		jiraFetchAllComments(ctx, c, dep, iss.Key, emit)
		return
	}
	for _, cAny := range inline {
		if cMap, ok := cAny.(map[string]any); ok {
			id, _ := cMap["id"].(string)
			jiraEmitComment(dep, iss.Key, id, cMap["body"], emit)
		}
	}
}

func jiraFetchAllComments(ctx context.Context, c *Client, dep Deployment, key string, emit func(model.Item)) {
	v := jiraAPIVer(dep)
	path := "/rest/api/" + v + "/issue/" + url.PathEscape(key) + "/comment"
	startAt := 0
	for pages := 0; ; pages++ {
		if err := ctx.Err(); err != nil {
			return
		}
		params := url.Values{"startAt": {strconv.Itoa(startAt)}, "maxResults": {"100"}}
		var page jiraCommentPage
		if err := c.get(ctx, path, params, &page); err != nil {
			logx.Warn("jira: comment fetch failed", "issue", key, "err", err)
			return
		}
		for _, cm := range page.Comments {
			jiraEmitComment(dep, key, cm.ID, cm.Body, emit)
		}
		got := len(page.Comments)
		if got == 0 {
			return
		}
		startAt += got
		if (page.Total > 0 && startAt >= page.Total) || pages >= maxPages {
			return
		}
	}
}

func jiraEmitComment(dep Deployment, key, commentID string, body any, emit func(model.Item)) {
	text := strings.TrimSpace(fieldText(body))
	if text == "" {
		return
	}
	// Discriminate the Path by comment id so two DISTINCT comments on one issue that contain the same
	// secret value don't collapse to one Fingerprint (type|path|value) — which a --baseline / SARIF /
	// DefectDojo dedupe would otherwise treat as one, hiding the second comment's leak.
	path, version := key, "comment"
	url := dep.BaseURL + "/browse/" + key
	if commentID != "" {
		path = key + "#comment-" + commentID
		version = "comment-" + commentID
		url += "?focusedCommentId=" + commentID
	}
	emit(model.Item{
		Source: "jira",
		Path:   path,
		Text:   text,
		Meta: map[string]any{
			"url":     url,
			"version": version,
		},
	})
}

// jiraScanHistory walks the full, paginated changelog and emits, per change event, the old and new
// text values of every changed field (items[].fromString / toString) — this is how a secret that
// lived only in a past field value (e.g. a token pasted into the description and later removed) is
// recovered. Comments are NOT in the changelog (T12), so only current comment bodies are scannable.
func jiraScanHistory(ctx context.Context, c *Client, dep Deployment, key string, emit func(model.Item)) error {
	v := jiraAPIVer(dep)
	path := "/rest/api/" + v + "/issue/" + url.PathEscape(key) + "/changelog"
	startAt := 0
	for pages := 0; ; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		params := url.Values{"startAt": {strconv.Itoa(startAt)}, "maxResults": {"100"}}
		var page jiraChangelogPage
		err := c.get(ctx, path, params, &page)
		if err != nil {
			// Old Server/DC (<8.6) lacks the dedicated endpoint: fall back to the embedded,
			// capped changelog on the issue itself (best effort; logs the truncation risk).
			if statusOf(err) == 404 {
				return jiraScanHistoryEmbedded(ctx, c, dep, key, emit)
			}
			return err
		}
		entries := page.entries()
		for _, h := range entries {
			jiraEmitHistory(dep, key, h, emit)
		}
		// Terminate on isLast, an empty page, or the server's total; a SHORT page is not terminal (a
		// thinned page would drop older history). The pages cap backstops a server that ignores startAt.
		if page.IsLast || len(entries) == 0 {
			return nil
		}
		startAt += len(entries)
		if page.Total > 0 && startAt >= page.Total {
			return nil
		}
		if pages >= maxPages {
			logx.Warn("jira: changelog page cap reached — oldest history not enumerated", "issue", key)
			return nil
		}
	}
}

func jiraScanHistoryEmbedded(ctx context.Context, c *Client, dep Deployment, key string, emit func(model.Item)) error {
	v := jiraAPIVer(dep)
	params := url.Values{"expand": {"changelog"}, "fields": {"summary"}}
	var iss struct {
		Changelog jiraChangelogPage `json:"changelog"`
	}
	if err := c.get(ctx, "/rest/api/"+v+"/issue/"+url.PathEscape(key), params, &iss); err != nil {
		return err
	}
	got := len(iss.Changelog.Histories)
	if iss.Changelog.Total > got {
		logx.Warn("jira: changelog truncated by the embedded API cap — older versions not scanned",
			"issue", key, "scanned", got, "total", iss.Changelog.Total)
	}
	for _, h := range iss.Changelog.Histories {
		jiraEmitHistory(dep, key, h, emit)
	}
	return nil
}

func jiraEmitHistory(dep Deployment, key string, h jiraHistory, emit func(model.Item)) {
	var b strings.Builder
	for _, it := range h.Items {
		// Scan the *String (human text) variants, never from/to (opaque IDs) — T13.
		if it.FromString != "" {
			b.WriteString(it.FromString)
			b.WriteByte('\n')
		}
		if it.ToString != "" {
			b.WriteString(it.ToString)
			b.WriteByte('\n')
		}
	}
	text := strings.TrimSpace(b.String())
	if text == "" {
		return
	}
	emit(model.Item{
		Source: "jira",
		Path:   key + "@" + h.Created,
		Text:   text,
		Meta: map[string]any{
			"url":     dep.BaseURL + "/browse/" + key,
			"version": "history",
			"author":  h.Author.label(),
			"updated": h.Created,
		},
	})
}
