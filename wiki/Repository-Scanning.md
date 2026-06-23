# Repository Scanning

```
prowl repo <git-url> [flags]
```

Clone a remote git repository and scan it. Works with any git URL — GitHub, GitLab, Bitbucket, or a self-hosted server. The repository is cloned into a temporary directory, scanned, and the checkout is removed afterwards; nothing is left on disk.

> To scan many repositories at once, see [Org-Wide Scanning](Org-Scanning.md). To scan a built container image instead of source, see [Container Scanning](Container-Scanning.md); to scan an S3 / GCS prefix, see [Cloud Storage Scanning](Bucket-Scanning.md).

By default `prowl repo` does a fast shallow clone (depth 1) of the remote's default branch and scans the resulting working tree. Add `--history` to scan every blob in the repository's history instead.

`prowl repo` accepts every [`prowl scan`](Scanning-Files.md) flag (verification, fail-on gating, output format, rule selection, baselines, …) in addition to the clone-specific flags below.

## Flags

| Flag | Description |
|------|-------------|
| `--history` | Scan EVERY blob in the repository's history (`git rev-list --objects --all`) instead of just the working tree. Forces a full clone; `--depth` is ignored. |
| `--branch NAME` | Clone a specific branch or tag instead of the remote's default branch. Adds `--single-branch`. |
| `--depth N` | Shallow-clone depth (positive integer, default `1`). Ignored with `--history`. |
| `+ all scan flags` | `--verify`, `--verified-only`, `--fail-on`, `--format`, `-o`/`--output`, `--rules-dir`, `--rules`, `--tags`, `--exclude-tags`, `--rule-severity`, `--baseline`, `--exclude`, `--workers`, `--timeout`, logging flags, … See [Scanning Files](Scanning-Files.md). |

Value flags accept both `--flag value` and `--flag=value`.

## Tree scan vs. `--history`

| Mode | What it clones | What it scans |
|------|----------------|---------------|
| default | A shallow clone (depth `--depth`, default 1) of the default branch (or `--branch`). | The checked-out working tree — the files as they exist at the tip of that branch. |
| `--history` | A full clone (all refs, full depth). | Every blob ever committed across all refs. Catches secrets that were removed from `HEAD` but still live in history. |

Use the default mode for a quick "is there anything live in the current tree" pass; use `--history` when you need to know whether a secret was ever committed (the case that requires rotation even after a "fix" commit). A full-history scan is slower and downloads the whole repository, so combine it with `--timeout` on large repositories — partial results are still reported.

## Authentication

`prowl repo` shells out to your local `git`, so it uses whatever credentials `git` already has. Private repositories work three ways:

- **SSH keys** — clone over SSH and your agent / `~/.ssh` keys are used:

  ```bash
  prowl repo git@github.com:org/private-repo.git
  ```

- **Credential helper** — an HTTPS clone uses your configured git credential helper (the OS keychain, `gh auth`, a `.git-credentials` store, etc.), exactly as `git clone` would.

- **Token in the URL** — embed a personal access token / deploy token directly:

  ```bash
  prowl repo https://<token>@github.com/org/private-repo.git
  prowl repo https://oauth2:<token>@gitlab.com/group/private-repo.git
  ```

No prowl-specific credential configuration exists; if `git clone <url>` works in your shell, `prowl repo <url>` works.

## Transport security

The clone is transport-hardened so a hostile URL cannot turn a scan into command execution:

- Only explicit, non-RCE transports are accepted: `https://`, `http://`, `ssh://`, `git://`, and the scp-like `git@host:path` form. A bare `.git` suffix is not sufficient — `prowl repo ext::sh -c …` is rejected outright.
- The git `ext` remote helper (which would run an arbitrary command from the URL) is disabled (`protocol.ext.allow=never`), and the `file` helper is restricted to the invoking user.
- The URL is passed after a `--` separator so it can never be reinterpreted as a git flag.

This is the same hardening `prowl rules update` applies to remote rule sources. `http://` is permitted here (unlike rule installation) because the target is a read-only scan target you chose, not executable rules. See [Security Model](Security-Model.md).

## Examples

```bash
# GitHub over HTTPS — shallow clone of the default branch, scan the tree
prowl repo https://github.com/org/repo

# GitLab over SSH — full history, gate CI on any high-or-worse finding
prowl repo git@gitlab.com:group/repo.git --history --fail-on high

# Bitbucket — scan a specific release branch
prowl repo https://bitbucket.org/team/repo --branch release

# Confirm hits are live against the provider's API
prowl repo https://github.com/org/repo --verify --verified-only

# SARIF artifact for a code-scanning dashboard, JSON logs for CI
prowl repo https://github.com/org/repo --format sarif -o repo.sarif --log-format json
```

## See also

- [Scanning Files](Scanning-Files.md)
- [CI/CD Integration](CI-CD-Integration.md)
- [Security Model](Security-Model.md)
- [Home](README.md)
