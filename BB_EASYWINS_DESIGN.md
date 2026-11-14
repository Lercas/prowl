# Bug-bounty easy wins — design

Three low-risk additions that turn Prowl into a drop-in verify layer for an offensive recon
pipeline. No new subsystems; each reuses shipped machinery.

## 1. `--targets FILE` for `prowl domain` (host-list fan-out)

**Goal:** scan a whole recon host list with live-verify in one invocation, aggregated into one report.

**Design** (`cmd/prowl/main.go: cmdDomain`):
- New flag `--targets FILE`. Targets resolve as: `--targets` file if given, else the single
  positional host. File format: one host per line, blank lines and `#` comments ignored, deduped.
- Build `det`/`eng`/`vset` once, reuse across hosts.
- Hosts run across a **bounded pool (8 workers)** — a subdomain sweep is mostly dead hosts whose
  connect-timeout dominates wall time, so they must time out concurrently. Each host's own asset
  fetches stay internally concurrent; the pool fans across DISTINCT hosts (no single host hammered).
  One host == one worker, so the positional single-target path is unchanged. *(The first cut was a
  sequential loop; the 2h soak showed big lists never finished — 127 hosts timed out at 420s — because
  ~85% of crt.sh subdomains are dead and each ate ~12s serially. Pooled: the same 127-host sweep
  completes in 137s, exit 0.)*
- A dead host is a `Warn`+`continue`, not a whole-run exit-2. `reachedAny` (mutex-guarded) is tracked
  across workers; only error out if **no** host was reachable.
- `--verified-only` / `--fail-on-verified` / `summarize` / `writeReport` / `gate` run **once** at the
  end over the aggregated findings. `--authorized` still required.
- `--max-assets` is per-host; the run `--timeout` bounds the whole sweep.

**Touchpoints:** `cmdDomain`; new `readTargetList`; register `--targets` in `knownFlags` + `domainHelp`.

**Edge cases:** ctx cancel mid-sweep breaks the loop; empty/comment-only file → usage error; both
`--targets` and a positional → `--targets` wins.

## 2. BB headline in pretty output (live/dead/unverified verdict)

**Goal:** one paste-able verdict line — the "is there anything to write up" signal — without
scrolling, only when verification actually ran.

**Design** (`internal/report/report.go: writePretty`):
- After the existing `N findings · by-severity · in N files` footer, append one line:
  `BB: <n> LIVE (<sev> <type>); <d> dead; <u> unverified`.
- Counts derive from `model.Finding.Verified` (`nil` = unverified, `true` = live, `false` = dead).
  `LIVE` annotated with the highest-severity live finding's `severity type`.
- Suppressed when no finding was verified (`live==0 && dead==0`) so non-verify runs are unaffected.
- `LIVE>0` painted red, else green; attacker-controlled `Type` is terminal-sanitized.

**Touchpoints:** `writePretty` + new `bbSummary`. Pretty-format only (JSON/SARIF already carry
`verified`). Affects every command's pretty output uniformly.

## 3. `--gists` for `prowl org` (GitHub gist scanning)

**Goal:** public gists are a top live-verifiable secret surface that `prowl org` never touches.

**Design** (`internal/forge/forge.go` + `cmd/prowl/main.go: cmdOrg`):
- New `forge.ListGists(ctx, "github:<user>")` paginating `GET /users/{user}/gists?per_page=100`.
  Gists clone from `git_pull_url` (`https://gist.github.com/<id>.git`), **not** `clone_url`, so
  `githubList` can't be reused as-is. Reuses `getJSON`/`bearer`/`GITHUB_TOKEN`/`maxPages`.
- `cmdOrg`: when `--gists` is set, call `ListGists` instead of `ListRepos`. The clone URLs flow
  through the existing worker pool / `scanOrgRepo` / `source.CloneRepo` / report path unchanged.
- Gists are user-scoped (orgs have none); a `github:<org>` target yields an empty list (clean exit).
  Target is resolved with `firstNonFlag(rest)` so `--gists` may appear before the target.

**Touchpoints:** `forge.ListGists`; `cmdOrg` branch; register `--gists` in `knownFlags` + `orgHelp`.

## Testing

- Unit: `--targets` list parse + multi-host aggregate (httptest hosts, one dead); `bbSummary`
  output for live/dead/unverified mixes and the no-verify suppression; `ListGists` pagination +
  `git_pull_url` selection (httptest GitHub mock).
- `go build/vet ./... && go test ./... -race` + `test/e2e.sh`.
- Real run: drive `--targets` from a recon subdomain list and `--gists` against live GitHub users
  for ~2h, watching for crashes / hangs / rate-limit handling; fix what surfaces.
