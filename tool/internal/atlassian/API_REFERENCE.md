# Atlassian Jira + Confluence multi-version scanner — API reference

> Synthesized from a 5-area research pass (developer.atlassian.com). The spec the scanner follows.

This is a synthesis task — no need for tools. I'll produce the reference directly from the five findings.

# Atlassian Jira + Confluence Multi-Version Secret Scanner — Implementation Reference

Scope: read-only scanner that enumerates EVERY historical version (from version 1) of Jira issue fields and Confluence page bodies, across Cloud, Server, and Data Center. Authoritative source of truth for the Go implementation.

---

## 0. Core mental model

- **Two products** (Jira, Confluence) × **three deployments** (Cloud, Server, Data Center). Detect product+deployment per base URL, cache the result, then pick paths.
- **Jira history** is NOT a document store — old field values are *reconstructed from the changelog* (`items[].fromString` / `toString`). Comments are NOT versioned anywhere.
- **Confluence history** IS a document store — each page version has a fetchable body. You must enumerate versions then fetch each version's body.
- **The whole point**: a secret added then deleted survives only in history. Scanning current content alone is a silent miss. Every operation below must walk to version 1.
- **Jira Cloud, big break (CHANGE-2046)**: legacy `/search` is **410 Gone** since Oct 2025. Use `/search/jql` with `nextPageToken`. No `total`, no `startAt`. Server/DC is unaffected.
- **Confluence Cloud, big break (RFC-19)**: v1 `/wiki/rest/api/*` endpoints with v2 equivalents were **removed 2025-03-31**. Use `/wiki/api/v2/*`. Server/DC keeps v1 forever (has no v2).

---

## 1. DEPLOYMENT DETECTION (run FIRST, per base URL, then cache)

### 1.0 Hostname hint — NON-authoritative, never decide on this alone
`*.atlassian.net` / `*.jira.com` suggests Cloud; arbitrary corporate host suggests Server/DC. BUT Cloud supports custom domains and DC sits on any host. Use only to order probes, never to classify.

### 1.1 Jira — authoritative probe
```
GET <base>/rest/api/2/serverInfo        (v2 path exists on ALL deployments; prefer it)
```
- **200** → read `.deploymentType` ∈ `{"Cloud","Server","DataCenter"}` — this single field is authoritative for Jira. Also capture `.version` (`"9.4.0"`), `.versionNumbers` (`[9,4,0]`), `.buildNumber`, `.baseUrl` (canonical self-URL; use to normalize redirects).
- **401/403** → instance exists but needs auth. **A 401 does NOT mean DC.** Retry *with credentials* before classifying. (Some Cloud sites also gate serverInfo.)
- DC quirk: older Jira may report `deploymentType:"Server"` from `/rest/api/3/serverInfo`, but the cross-cutting `/rest/api/2/serverInfo` returns the proper `"DataCenter"`. For read paths Server and DataCenter are identical anyway — treat them the same.

### 1.2 Confluence — no `deploymentType` exists; probe path shape
```
1. GET <base>/wiki/api/v2/spaces?limit=1   → 200/401 ⇒ Cloud (v2 present)
2. else GET <base>/wiki/rest/api/space?limit=1  → 200/401 ⇒ Cloud (v1 only; rare now post-2025-03-31)
3. else GET <base>/rest/api/space?limit=1  (NO /wiki) → 200/401 ⇒ Server/DC
```
- Confirm Cloud: `GET <base>/wiki/rest/api/settings/systemInfo` (Cloud-only; analog of Jira serverInfo, but has no version string — Cloud is continuously deployed).
- Confirm + version Server/DC: `GET <base>/rest/troubleshooting/1.0/pre-upgrade/info` (since Confluence 6.15.8, requires auth) → build/version. Or `GET <base>/rest/applinks/1.0/manifest` → XML `<typeId>confluence</typeId>` + `<version>X.Y.Z</version>` (Cloud 404s this).

### 1.3 API-version selection (decision table)

| Product | Deployment | Use | Avoid |
|---|---|---|---|
| Jira | Cloud | `/rest/api/3` (ADF) or `/rest/api/2` (strings) + `/search/jql` | `/rest/api/3/search` (410 Gone) |
| Jira | Server/DC | `/rest/api/2` only + `/search` (startAt) | `/rest/api/3` (does not exist), `nextPageToken` |
| Confluence | Cloud | `/wiki/api/v2` + v1 `/wiki/rest/api` as fallback | bare `/rest/api` (no `/wiki` ⇒ 404) |
| Confluence | Server/DC | `/rest/api` (v1, NO `/wiki`, NO v2) | any `/wiki` prefix, any `v2` |

### 1.4 Cache key
Per base URL, cache `{product, deployment, apiVersion, basePathPrefix, version, versionNumbers, authMode, supportsDedicatedChangelog, supportsStableVersionListing, supportsPAT}` so every later call uses the right shape without re-probing.

### 1.5 OAuth-3LO cloudId resolution (Cloud, only if using OAuth not Basic)
```
GET https://api.atlassian.com/oauth/token/accessible-resources   (Authorization: Bearer <token>)
```
Returns all reachable sites in **no guaranteed order**. **Match by `url`, never take index 0.** Take that site's `id` = `{cloudId}`, then call `https://api.atlassian.com/ex/jira/{cloudId}/...` or `https://api.atlassian.com/ex/confluence/{cloudId}/wiki/...`.

---

## 2. ENDPOINT MATRIX

Notation: `{key}` = issue id-or-key, `{id}` = numeric content/page id, `{N}` = version number.

### 2.A JIRA CLOUD (`https://<site>.atlassian.net` or `https://api.atlassian.com/ex/jira/{cloudId}`)

| Operation | Method + Path | Key params | Pagination |
|---|---|---|---|
| **List projects** | `GET /rest/api/3/project/search` | `startAt`(0), `maxResults`(≤50), `query`, `expand` | Classic page: `{startAt,maxResults,total,isLast,values[]}`. Loop while `isLast==false`, `startAt+=maxResults`. `total` IS present here. |
| **List issues (CURRENT)** | `GET /rest/api/3/search/jql` | `jql`, `maxResults`(server may return fewer; cap ~5000), `fields`(CSV — **required**, default returns only `id`), `expand`(`renderedFields,changelog,names`), `nextPageToken`, `reconcileIssues` | **Cursor**: `{issues[],nextPageToken,isLast}`. No `total`, no `startAt`. Loop on `nextPageToken` until absent / `isLast==true`. **Sequential only — cannot parallelize one result set.** |
| **List issues (long JQL)** | `POST /rest/api/3/search/jql` | JSON body: `{jql,maxResults,nextPageToken,fields:[],expand}` | same cursor |
| **Approx count** (progress only) | `POST /rest/api/3/search/approximate-count` | `{jql}` → `{count}` | replaces removed `total`; APPROXIMATE |
| **Issue detail** | `GET /rest/api/3/issue/{key}` | `fields`, `expand=renderedFields,changelog,names`, `properties` | embedded `changelog` is **CAPPED ~100** — do not rely on it for full history |
| **List versions (full history)** | `GET /rest/api/3/issue/{key}/changelog` | `startAt`(0), `maxResults`(100) | Classic page: `{startAt,maxResults,total,isLast,values[]}`. Loop until `isLast`. **THE authoritative full history.** |
| **Bulk history (org-wide speedup)** | `POST /rest/api/3/changelog/bulkfetch` | `{issueIdsOrKeys:[],fieldIds:[],maxResults,nextPageToken}` | Cursor `nextPageToken`. GA since early 2025. Use `fieldIds` to filter to secret-bearing fields. |
| **Comments** (not in changelog) | `GET /rest/api/3/issue/{key}/comment` | `startAt,maxResults,total`; `expand=renderedBody` | classic page |

### 2.B JIRA SERVER / DATA CENTER (`https://<host>[/context]`)

| Operation | Method + Path | Key params | Pagination |
|---|---|---|---|
| **List projects** | `GET /rest/api/2/project` | `expand`, `recent` | **NOT paginated** — flat array of all visible projects in one call. |
| **List issues** | `POST /rest/api/2/search` (preferred) / `GET` | `{jql,startAt,maxResults,fields:[],expand:["changelog","renderedFields"],validateQuery:false}` | Classic: `{startAt,maxResults,total,issues[]}`. Loop `startAt+=len` until `startAt+len>=total`. **No nextPageToken, no /search/jql here.** |
| **Issue detail** | `GET /rest/api/2/issue/{key}` | `fields`, `expand` | — |
| **List versions (embedded)** | `GET /rest/api/2/issue/{key}?expand=changelog` | — | `changelog={startAt,maxResults,total,histories[]}`. **Embedded is CAPPED (~100); no startAt control.** If `total > len(histories)` → switch to dedicated endpoint. |
| **List versions (full, paginated)** | `GET /rest/api/2/issue/{key}/changelog` | `startAt`(0), `maxResults`(100) | `{startAt,maxResults,total,values[]}`, oldest-first. **DC/Server 8.6+ only.** Probe: 200 supported / 404 → fall back to embedded + accept cap. |
| **Comments** | `GET /rest/api/2/issue/{key}/comment` | `expand=renderedBody` | classic page |
| **Field map** | `GET /rest/api/2/field` | — | resolve `customfield_*` ids |
| **Detect/version** | `GET /rest/api/2/serverInfo` | — | anonymous-OK on many DC |

### 2.C CONFLUENCE CLOUD (`https://<site>.atlassian.net/wiki`)

| Operation | Method + Path | Key params | Pagination |
|---|---|---|---|
| **List spaces** | `GET /wiki/api/v2/spaces` | `keys[]`, `type`(global\|personal\|…), `status`(current\|archived — **default current only; do an `archived` pass**), `limit`(≤250), `cursor` | **Cursor** via `_links.next`. Captures both numeric `id` (for v2) and `key` (for v1/CQL). |
| **List pages (per space)** | `GET /wiki/api/v2/spaces/{id}/pages` | `depth=all`, `status[]`(current\|archived\|deleted\|trashed — **pass explicitly**), `body-format`, `limit`(≤250), `cursor` | cursor `_links.next` |
| **List pages (whole site)** | `GET /wiki/api/v2/pages` | `space-id[]`, `status[]`, `body-format`(inlines current body), `subtype`, `cursor` | cursor |
| **Page detail / version body** | `GET /wiki/api/v2/pages/{id}` | `body-format=storage` (comma-sep for multiple), **`version={N}` ← cleanest way to fetch a specific old version's BODY**, `get-draft` | — |
| **List versions** | `GET /wiki/api/v2/pages/{id}/versions` | `sort`, `body-format`, `limit`, `cursor` | cursor. **PITFALL (2026-06-01): when `body-format` is set, `limit` is HARD-CAPPED at 50.** Enumerate `number`s WITHOUT body-format (large pages), then fetch bodies individually. |
| **Version metadata (NO body)** | `GET /wiki/api/v2/pages/{id}/versions/{N}` | — | `DetailedVersion` (number, authorId, message, createdAt, prevVersion, nextVersion). **No body, no `_links`.** Don't use for content. |

### 2.D CONFLUENCE SERVER / DATA CENTER (`https://<host>[/context]`, NO `/wiki`)

| Operation | Method + Path | Key params | Pagination |
|---|---|---|---|
| **List spaces** | `GET /rest/api/space` | `spaceKey[]`, `type`(global\|personal), `status`(current\|archived), `start`, `limit` | Offset `start/limit` + `_links.next` until absent. |
| **List pages** | `GET /rest/api/content` | `spaceKey`, `type=page`(also blogpost/comment/attachment), `status`(current\|trashed\|historical\|draft), `expand=version`, `start`, `limit` | offset + `_links.next` |
| **Search (alt enum)** | `GET /rest/api/content/search?cql=...` | `cql`, `expand`, `limit` | cursor on newer DC; good for incremental (`cql=lastModified > '...'`) |
| **Page detail (body)** | `GET /rest/api/content/{id}?expand=body.storage,version,history,space` | body NOT returned unless `expand=body.storage` | — |
| **List versions (fast)** | `GET /rest/api/content/{id}/version?start=0&limit=100&expand=content` | `expand=content` / `content.body.storage` | offset + `_links.next`. **Stable on DC 8.x+. DC 7.x/Server → `/rest/experimental/content/{id}/version`.** |
| **Fetch version N body (PORTABLE — works 5.7→10.x)** | `GET /rest/api/content/{id}?status=historical&version={N}&expand=body.storage,version` | `status=historical` + `version=N` | **Lowest-common-denominator; source of truth.** |
| **History fallback (ancient builds)** | `GET /rest/api/content/{id}/history?expand=previousVersion,nextVersion` | — | only current/prev/next pointers; chain backwards when `/version` 404s |
| **Detect/version** | `GET /rest/applinks/1.0/manifest` | — | XML version + confluence typeId |

---

## 3. AUTH MATRIX

| Deployment | Method | Header | Notes |
|---|---|---|---|
| **Cloud (both products)** | Basic = email + **API token** | `Authorization: Basic base64(email:api_token)` | Token from id.atlassian.com/manage/api-tokens. **NOT the password** (password Basic removed 2019-06-03). Send `Accept: application/json`. Works against `<site>.atlassian.net`, **NOT** against `api.atlassian.com` gateway. 2025: unscoped tokens being deprecated → prefer scoped/OAuth. |
| **Cloud** | OAuth 2.0 (3LO) | `Authorization: Bearer <access_token>` | **Must** call `api.atlassian.com/ex/{jira\|confluence}/{cloudId}/...`, never `<site>.atlassian.net`. Resolve cloudId via accessible-resources. Token ~1h; refresh with `offline_access`. Granular read scopes: `read:project:jira, read:issue:jira, read:comment:jira, read:issue.changelog:jira, read:jql:jira`; `read:space:confluence, read:page:confluence` (or classic `read:jira-work`, `read:confluence-content.all`). |
| **Server/DC** | **PAT (recommended)** | `Authorization: Bearer <PAT>` | **Literal token, NOT base64.** Jira 8.14+ / JSM 4.15+ / Confluence 7.9+. Inherits creating user's perms — use a broad-read service account. For POST/PUT add `X-Atlassian-Token: no-check` (not needed for read-only). |
| **Server/DC** | Basic = real username:password | `Authorization: Basic base64(user:password)` | Works on all versions (instance's own directory). Required on Jira <8.14 / Confluence <7.9 (no PAT). May be blocked by SSO/2FA; **repeated failures trip CAPTCHA lockout** → even valid creds 401. |
| **Server/DC** | Cookie / OAuth 1.0a | `Cookie: JSESSIONID=...` / `Authorization: OAuth ...` | Legacy; avoid. Cookie via `POST /rest/auth/1/session`. |

**Cloud API tokens do NOT work on Server/DC, and vice-versa.** Atlassian gateway (`api.atlassian.com`) requires Bearer; `.atlassian.net` host accepts Basic(email:token).

---

## 4. CONTENT EXTRACTION (what to scan, per source)

| Source | Format | Extraction |
|---|---|---|
| **Jira Cloud v3** fields (description, environment, comment.body, textarea customfields) | **ADF** JSON `{version:1,type:"doc",content:[...]}` | **Recursively** walk `content[]`. Real text in nodes with a `text` prop. **Also scan `attrs` of `link`/`inlineCard`/`mention` nodes** (href/url/value can hide secrets). |
| **Jira Cloud v2** / **Jira Server/DC** same fields | **Wiki markup / plain strings** | Regex directly — no traversal. (Prefer v2 on Cloud if you just want greppable strings.) |
| **Jira `renderedFields`** | **v2 → rendered HTML** (easy); **v3 → raw ADF, NOT HTML** (bug ACJIRA-2349) | Only use renderedFields for HTML on v2. On v3 walk ADF yourself. |
| **Jira changelog** `items[].fromString` / `toString` | **PLAIN STRINGS in both v2 and v3** (never ADF) | Scan directly. `from`/`to` are opaque IDs — **scan the `*String` variants.** |
| **Confluence body** | `storage` (XHTML/`ac:`,`ri:` macros), `atlas_doc_format` (ADF JSON), `view` (rendered HTML) | **Scan `storage` as primary** — it is raw authored source incl. macro params + CDATA. v1: `expand=body.storage`; v2: `body-format=storage`. Optionally cross-check `view` (catches dynamic text storage hides). |
| **Confluence code-block secrets** | `<ac:structured-macro ac:name="code"><ac:plain-text-body><![CDATA[ ... ]]>` | **Scan the raw storage string; do NOT strip tags** — naive XML parsers mangle CDATA. Also check `<ac:parameter>` and `href`/`ri:value` attrs. |

---

## 5. PER-OPERATION FALLBACK CHAINS (try new → fall back on 404/410)

**Jira — list issues**
1. Cloud: `GET /rest/api/3/search/jql` (cursor). On **410 Gone** from `/rest/api/3/search` → confirms post-migration Cloud, you were on the wrong path; switch to `/search/jql`.
2. Long JQL → `POST /rest/api/3/search/jql`.
3. Server/DC: `POST /rest/api/2/search` (startAt). `/search/jql` 404s here → that's the DC signal.

**Jira — full version history**
1. `GET /rest/api/{2|3}/issue/{key}/changelog` (paginate to `isLast`/`total`). Bulk: `POST /rest/api/3/changelog/bulkfetch`.
2. On 404 (old Server/DC <8.6) → `GET /rest/api/2/issue/{key}?expand=changelog`, compare `changelog.total` vs `len(histories)`; if truncated, you must accept the ~100 cap (no other path). Log the gap.

**Confluence — list pages / spaces**
1. Cloud: `/wiki/api/v2/spaces`, `/wiki/api/v2/pages` (cursor).
2. On 404 → v1 `/wiki/rest/api/space`, `/wiki/rest/api/content` (offset). (Rare post-2025-03-31.)
3. If `/wiki/*` 404s entirely → drop `/wiki`: `/rest/api/space`, `/rest/api/content` ⇒ you are on Server/DC.

**Confluence — list versions**
1. Cloud: `GET /wiki/api/v2/pages/{id}/versions` (no body-format, cursor) to enumerate numbers.
2. Cloud fallback: v1 `GET /wiki/rest/api/content/{id}/version` (offset).
3. Server/DC: `GET /rest/api/content/{id}/version` → on 404 (DC 7.x/Server) `GET /rest/experimental/content/{id}/version` → on 404 chain `GET /rest/api/content/{id}/history?expand=previousVersion`.

**Confluence — fetch version N body**
1. Cloud v2: `GET /wiki/api/v2/pages/{id}?version={N}&body-format=storage` (cleanest). Or re-list with `body-format` in **≤50** chunks.
2. Cloud v1 (reliable): `GET /wiki/rest/api/content/{id}/version/{N}?expand=content.body.storage` (**`content.` prefix required**). Do NOT use bare `?status=historical&version=N` on Cloud — unreliable.
3. Server/DC (portable, all versions): `GET /rest/api/content/{id}?status=historical&version={N}&expand=body.storage,version`.

**Generic rule:** on 404 for a v2/v3 path retry the v1/v2 equivalent; on 404 for a `/wiki`-prefixed path retry without `/wiki` (= Server/DC). On 410, the old endpoint is permanently gone (Cloud search) — switch, don't retry. **Cache the winning shape per base URL.**

---

## 6. TOP PITFALLS → ENCODE AS TESTS

**Detection / routing**
- T1: Never classify Cloud-vs-DC by hostname (custom domains exist). Must use `serverInfo.deploymentType` (Jira) / path-shape probe (Confluence).
- T2: `serverInfo` 401 ≠ DC. Retry authenticated before classifying.
- T3: Confluence `/wiki` prefix on Cloud only; hard-coding it breaks DC, omitting it breaks Cloud.
- T4: `accessible-resources` order is non-deterministic → match by `url`, not `[0]`.
- T5: OAuth Bearer must hit `api.atlassian.com/ex/...`; Basic(email:token) must hit `.atlassian.net`. Crossing them → 401.

**Jira search**
- T6: Never call `/rest/api/3/search` on Cloud → 410 Gone. Use `/search/jql`.
- T7: `/search/jql` returns **only `id`** by default — missing `fields` = silent empty scan. Always pass `fields` (e.g. `summary,description,environment,comment` + custom field ids) or `*all`.
- T8: No `total` on `/search/jql` — loop on `nextPageToken`/`isLast`, never precompute page count. `approximate-count` is estimate-only.
- T9: `maxResults` is advisory on `/search/jql` (server may return fewer); read back actual page size. Pages sequential — parallelize across projects/JQL slices, not within one cursor.
- T10: Server/DC `maxResults` silently capped (~100); read returned `maxResults`/`total`, don't assume requested honored.

**Jira history**
- T11: Embedded `expand=changelog` (issue/search) is CAPPED ~100. Compare `changelog.total` vs `len(histories)`; if smaller, use dedicated `/changelog` endpoint or you drop old (secret-bearing) versions.
- T12: Comments are NOT in changelog and comment edits are NOT versioned — only current comment body retrievable. A secret edited out of a comment is unrecoverable; scan current comment bodies via `/comment`.
- T13: Scan changelog `*String` (human text), not `from`/`to` (opaque IDs).
- T14: Epic Link/Parent changelog field labels changed to `IssueParentAssociation` (2021-06-10→12-10); old reparenting history uses different labels — don't key history parsing on `"Epic Link"`/`"Parent"` alone.

**Jira content**
- T15: v3 `renderedFields` returns ADF not HTML (ACJIRA-2349). Walk ADF; don't expect HTML.
- T16: ADF extraction must be recursive AND include `attrs` (href/url/value) of link/inlineCard/mention nodes.

**Confluence**
- T17: v2 `/pages/{id}/versions/{N}` returns metadata only, no body → use `/pages/{id}?version={N}&body-format=storage`.
- T18: v2 versions `limit` hard-capped at 50 when `body-format` set (2026-06-01) — request still 200s but truncates silently. Enumerate numbers without body-format, fetch bodies separately.
- T19: v1 historical body: bare `?status=historical&version=N` unreliable on Cloud → use `/content/{id}/version/{N}?expand=content.body.storage` (note `content.` prefix).
- T20: Default status filters HIDE content. Pass `status[]=archived,deleted,trashed` + `depth=all` (v2) / `status=historical,draft,trashed` (v1). Personal & archived spaces need separate passes (`type=personal`, `status=archived`).
- T21: Body NOT returned by default — must request `expand=body.storage` (v1) / `body-format=storage` (v2), or scanner finds nothing.
- T22: Confluence DC context path (e.g. `/confluence`) — discover real base; don't assume root.
- T23: Code-block secrets live in `<![CDATA[...]]>` — scan raw storage, don't tag-strip.
- T24: v1=offset (`start/limit`), v2=cursor (`_links.next`/`Link: rel="next"`), Jira-new=`nextPageToken`, Jira-old/DC=`startAt/total`. A single pagination assumption silently truncates.

**Cross-cutting**
- T25: Permissions are per-user — search/changelog/pages only return what the auth account sees. Scanner account needs Browse Projects (Jira) / broad space read (Confluence) on everything, or silent misses. Restricted content → 403/filtered.
- T26: Rate limits: honor HTTP 429 `Retry-After`; exponential backoff + jitter; watch `RateLimit-Reason`/`X-RateLimit-Remaining`. Full-history walks are request-heavy (O(versions) per page on Confluence; per-issue changelog on Jira) — prefer bulk endpoints, steady refill-rate pacing, parallelize across projects/spaces not within a cursor.
- T27: PAT version floor — Jira <8.14 / Confluence <7.9 have no PAT; detect via serverInfo/version probe and fall back to Basic.
- T28: Custom fields (`customfield_10010`, textarea/url/text) holding secrets are NOT in the default navigable set — request explicitly or via `*all`; resolve names via `/rest/api/2/field`.
- T29: CAPTCHA lockout on Server/DC after repeated bad Basic logins — throttle auth attempts; prefer PAT.
- T30: **The core invariant test**: for any issue/page, the scanner must surface a secret that exists only in version 1 (or any non-current version) and is absent from current content. If a test secret planted in v1 and removed in v_current is not found, the history walk is broken.