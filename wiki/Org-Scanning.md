# Org-Wide Scanning

```
prowl org <platform>:<name> [flags]
```

Scan every repository under a GitHub org or user, a GitLab group, or a Bitbucket workspace in one command. Prowl lists the repositories via the platform's REST API, then clones and scans each one in turn. Each repository is cloned into a temporary directory, scanned, and the checkout is removed before the next one — nothing is left on disk.

By default each repository's working tree (the default branch) is scanned. Add `--history` to scan every blob in each repository's full git history instead.

`prowl org` accepts every [`prowl scan`](Scanning-Files.md) flag (verification, fail-on gating, output format, rule selection, tags, …) in addition to `--history`. It is the multi-repository counterpart to [`prowl repo`](Repository-Scanning.md), which scans a single git URL. To scan a built container image rather than source, see [Container Scanning](Container-Scanning.md); to download & scan an S3 / GCS prefix, see [Cloud Storage Scanning](Bucket-Scanning.md).

## Targets

The target is `<platform>:<name>`.

| Target | Lists |
|--------|-------|
| `github:<org-or-user>` | Every repository in a GitHub org. If the name is not an org, Prowl falls back to the user account and lists that user's own repositories. |
| `gitlab:<group>` | Every project in a GitLab group, **subgroups included**. |
| `bitbucket:<workspace>` | Every repository in a Bitbucket workspace. |

```bash
prowl org github:my-org
prowl org gitlab:my-group
prowl org bitbucket:my-workspace
```

## Authentication

Listing and cloning use a per-platform environment token. A token is needed for private repositories and for higher API rate limits; without one, only public repositories reachable anonymously are listed.

| Platform | Token env var | API host override |
|----------|---------------|-------------------|
| GitHub | `GITHUB_TOKEN` | `GITHUB_API` (default `https://api.github.com`) |
| GitLab | `GITLAB_TOKEN` | `GITLAB_API` (default `https://gitlab.com/api/v4`) |
| Bitbucket | `BITBUCKET_TOKEN` | — |

Set `GITHUB_API` / `GITLAB_API` to point at a self-hosted instance — for example `GITLAB_API=https://gitlab.example.com/api/v4` for an on-prem GitLab. Bitbucket targets always use the hosted Bitbucket Cloud API.

The clone step itself shells out to your local `git`, so private repositories also need credentials `git` can use (an SSH agent, a credential helper, or a token the token env var covers). See [Repository Scanning → Authentication](Repository-Scanning.md) for the cloning details.

## `--history`

| Mode | What it scans per repository |
|------|------------------------------|
| default | The checked-out working tree of the default branch. |
| `--history` | Every blob ever committed across all refs (a full clone). Catches secrets removed from `HEAD` but still present in history. |

`--history` applies to every repository in the org, so it is slower and downloads each repository in full. Combine it with `--timeout` on large orgs — partial results are still reported per repository.

## `--exclude-repo`

`--exclude-repo S,…` skips any repository whose **clone URL** contains one of the comma-separated substrings — useful for dropping a vendored fork, a mirror, or an archived repo from an org-wide sweep without listing every other repo by hand.

```
--exclude-repo <substr>,<substr>,…
```

Matching is a plain case-sensitive substring test against each listed clone URL, so a substring of the `owner/repo` slug (or the host) is enough. Excluded repositories are dropped before any clone happens, and a count is logged (`excluded repositories count=N`).

```bash
# Scan the org but skip the vendored fork and the docs mirror
GITHUB_TOKEN=ghp_xxx prowl org github:my-org --exclude-repo my-org/vendored-fork,docs-mirror --fail-on high
```

## Per-repository config is not honored

When `prowl org` scans a repository, that repository's own `.prowl.yaml` is **ignored**. This is deliberate: you are scanning code you may not own, and an auto-discovered config could otherwise disable detectors or allowlist findings — letting a repository suppress its own secrets. Only an explicit `--config FILE` you pass on the command line is trusted, and it is then applied uniformly to every repository in the scan. See [Security Model](Security-Model.md).

## Exit code

| Code | Meaning |
|------|---------|
| `0` | No finding tripped `--fail-on` (or it was not set), even if some repositories failed to clone. |
| `1` | A finding at or above the `--fail-on` threshold was found in any repository. |
| `2` | The repository listing failed (bad target, API error, bad token), or **no** repository could be scanned. |

The code reflects `--fail-on` over the **merged** findings of every repository, so `prowl org … --fail-on <sev>` is a CI gate over a whole org. A repository that fails to clone is logged and **skipped** — a few unreachable repos do not fail the run; only a total listing failure or zero scannable repos returns `2`. A `failed=N` line is logged when some repositories error, so partial failures stay visible.

## Output

Repositories are cloned and scanned **in parallel** — `--concurrency N` (default `min(4, number of repos)`) — each in its own temp checkout that is removed as it finishes. Progress is logged to stderr (`scanned repo=… findings=N`) so you can watch a long sweep.

All repositories' findings are merged into **one report**, with every path prefixed `"<owner>/<repo>: "` so you can tell which repository each finding came from (e.g. `octocat/linguist: samples/Apex/TwilioAPI.cls`). Because it is a single report:

- **`pretty`** groups findings across the whole org by file.
- **`json` / `sarif`** is **one valid document** spanning all repositories — pipe it straight into a SARIF consumer or `jq`, no stream-splitting needed.

## Examples

```bash
# GitHub org over an authenticated token, fail CI on any high-or-worse finding
GITHUB_TOKEN=ghp_xxx prowl org github:my-org --fail-on high

# GitLab group (subgroups included), full history, one aggregate JSON document, 8 repos at a time
GITLAB_TOKEN=glpat-xxx prowl org gitlab:my-group --history --concurrency 8 --format json -o org.json

# Bitbucket workspace, confirm each hit is live against the provider's API
BITBUCKET_TOKEN=xxx prowl org bitbucket:my-workspace --verify --verified-only

# Self-hosted GitLab via GITLAB_API override
GITLAB_API=https://gitlab.example.com/api/v4 \
GITLAB_TOKEN=glpat-xxx \
  prowl org gitlab:platform --fail-on critical
```

## See also

- [Repository Scanning](Repository-Scanning.md)
- [Scanning Files](Scanning-Files.md)
- [CI/CD Integration](CI-CD-Integration.md)
- [Home](README.md)
