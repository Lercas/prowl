# CI logs and artifact scanning

`prowl cicd` scans recent GitHub Actions or GitLab CI execution output with the same detector, rule,
ML, verification, reporting, and gating pipeline as every other Prowl source.

```sh
GITHUB_TOKEN=… prowl cicd github:owner/repo
GITLAB_TOKEN=… prowl cicd gitlab:group/project
```

The command is read-only. Credentials come from `GITHUB_TOKEN` or `GITLAB_TOKEN` only; there is no
token flag, so the value does not land in argv or shell history. `GITHUB_API` and `GITLAB_API` select
a GitHub Enterprise or self-hosted GitLab API. An internal API address still needs the explicit
`PROWL_ALLOW_PRIVATE_IPS=1` SSRF-guard opt-out.

## What is scanned

For GitHub, Prowl lists recent completed workflow runs, downloads the combined run-log ZIP, lists
non-expired artifacts for each run, and downloads their ZIP payloads. For GitLab, it lists recent
pipelines and jobs, then reads each job trace and downloadable artifact.

Archive content is streamed from memory into the scanner; it is never extracted onto the filesystem.
ZIP/JAR, TAR, TAR.GZ/TGZ, GZIP, and Office containers are opened recursively up to three levels deep.
Binary entries are skipped through the same text and encoding check as filesystem scanning. Finding
paths retain the forge, repository, run/pipeline, job, artifact, and entry names, while JSON/SARIF
findings link back to the run or job URL.

## Bounds and selection

| Flag | Effect | Default |
|---|---|---:|
| `--max-runs N` | most recent runs/pipelines | 20 |
| `--max-artifacts N` | artifact downloads across the scan | 100 |
| `--max-download SIZE` | compressed bytes per log/artifact download | 100 MB |
| `--max-size SIZE` | uncompressed bytes per scanned archive entry | 10 MB |
| `--branch REF` | only one branch/ref | all |
| `--logs-only` | skip artifact downloads | off |
| `--artifacts-only` | skip log/trace downloads | off |
| `--timeout DUR` | overall collection + scan deadline | none |

Archive entry count, expanded bytes, integer arithmetic, nesting depth, and path names are bounded
independently. A selected log/artifact that cannot be fetched or decoded marks the collection
incomplete: partial findings are still reported, but an otherwise-clean run exits non-zero instead of
claiming that no secrets exist.

## Redirect and secret safety

Forge download endpoints commonly redirect to a signed object-storage URL. Prowl stops the
authenticated API request at that redirect, validates the destination, and creates a new request
without `Authorization` or `PRIVATE-TOKEN`. Both requests use the SSRF-guarded HTTP transport.

Findings remain redacted by default. Use `--show-secrets` only for explicitly authorized triage.

## Examples

```sh
# Ten recent GitHub Actions runs; fail the gate on a high finding.
GITHUB_TOKEN=… prowl cicd github:acme/payments --max-runs 10 --fail-on high

# Only GitLab artifacts from main, JSON report.
GITLAB_TOKEN=… prowl cicd gitlab:platform/backend \
  --branch main --artifacts-only --format json -o ci-findings.json

# Apply ML noise filtering and confirm supported findings with provider APIs.
GITHUB_TOKEN=… prowl cicd github:acme/frontend --ml --verify --verified-only
```
