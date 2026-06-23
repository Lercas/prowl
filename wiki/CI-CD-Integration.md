# CI/CD Integration

Prowl is built to gate pipelines: a meaningful **exit code**, a `--fail-on` severity threshold, **SARIF** output for code-scanning dashboards, **baselines** to suppress accepted findings, and a `--staged` mode for pre-commit hooks.

```sh
# fail the build if any finding is high or above
prowl scan . --fail-on high
```

## Exit codes

`prowl scan` communicates its result purely through its exit code, which is ideal for CI:

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings, or no finding reached the `--fail-on` level (at or below threshold). Also returned after `--write-baseline`. |
| `1` | At least one finding is `>= --fail-on` level. |
| `2` | Error (bad detector/taxonomy load, git error, unreadable output file, bad flag value). |

Important details from the gate logic:

- **Without `--fail-on`, the scan never returns `1`.** It will report findings but exit `0`. Always set `--fail-on` in CI if you want the build to fail on secrets.
- The gate compares finding severity against the threshold using the order `info < low < medium < high < critical`. `--fail-on medium` fails on `medium`, `high`, and `critical` findings.
- `--write-baseline` snapshots findings and exits `0` without gating — it is a "record current state" run, not an enforcement run.

## `--fail-on LEVEL`

```sh
prowl scan . --fail-on critical   # only crash on critical secrets
prowl scan . --fail-on info       # crash on ANY finding
```

`LEVEL` is one of `info`, `low`, `medium`, `high`, `critical`. Exit `1` is returned if any finding's severity is at or above `LEVEL`. The default (`--fail-on` unset) reports but does not fail. You can also set `output.fail_on` in [Configuration](Configuration.md); the flag overrides it.

## SARIF for code scanning

Emit [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) and upload it to GitHub Code Scanning or GitLab so findings appear inline on PRs/MRs and in the security dashboard:

```sh
prowl scan . --format sarif -o report.sarif
```

`--format sarif` selects the SARIF writer; `-o`/`--output` writes to a file (file output is never coloured). See [Output Formats](Output-Formats.md) for `pretty`, `json`, and `sarif` details.

Run the scan and the gate independently when you still want the SARIF artifact uploaded on a failing build — see the workflow below, which writes SARIF and gates with `--fail-on` in the same step while keeping the upload on `always()`.

## Baselines

Baselines let you adopt Prowl on a repo that already has known/accepted findings without drowning in noise. Snapshot the current findings once, commit the baseline, then suppress those exact findings on every subsequent scan.

```sh
# 1. record the accepted findings (exits 0, no gating)
prowl scan . --write-baseline .prowl-baseline.json

# 2. commit it, then on later scans suppress everything in the baseline
prowl scan . --baseline .prowl-baseline.json --fail-on high
```

Baselines key on each finding's stable **fingerprint** (a hash over type + path + raw value, computed before redaction), so suppression survives a secret moving lines and two distinct secrets never collide.

Auto-discovery: if you do **not** pass `--baseline` and a file named `.prowl-baseline.json` exists in the working directory, Prowl loads it automatically. Commit it at the repo root and later scans pick it up with no flags. New secrets (not in the baseline) still surface and still trip `--fail-on`.

## Pre-commit hooks with `--staged`

`--staged` scans only the files staged in git (`git diff --cached`), which is exactly what a pre-commit hook wants — fast, and scoped to what is about to be committed. If nothing is staged, the scan exits `0` immediately.

```sh
prowl scan --staged --fail-on high
```

`.git/hooks/pre-commit`:

```sh
#!/usr/bin/env sh
# Block a commit that introduces a high-or-above secret.
prowl scan --staged --fail-on high --silence
status=$?
if [ "$status" -ne 0 ]; then
  echo "prowl: secret detected in staged changes — commit blocked" >&2
  exit "$status"
fi
```

Make it executable: `chmod +x .git/hooks/pre-commit`. To check the diff against a branch instead of the index, use `--since <rev>` (e.g. `--since origin/main`); to sweep all history blobs, use `--history`.

## CI mode: `-s` / `--silence`

In CI you usually want the exit code to be the only signal. `-s`/`--silence` prints **no output at all** — no report, no summary — so the step's pass/fail is determined entirely by the exit code:

```sh
prowl scan . --fail-on high --silence
```

Note that `--silence` suppresses stdout reporting but **not** `-o`/`--output`: you can be silent on the console and still write a SARIF/JSON artifact to a file. Related logging flags: `-q`/`--quiet` (warnings+errors only, still prints the report), `-v`/`--verbose` (debug), and `--log-format json` for structured logs you can aggregate.

## GitHub Actions

Build Prowl, scan, gate on `high`, and upload SARIF to Code Scanning. The SARIF upload runs even when the gate fails so findings still land on the PR.

```yaml
name: secret-scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required to upload SARIF

jobs:
  prowl:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: stable

      - name: Install prowl
        run: go install github.com/Lercas/prowl/cmd/prowl@latest

      - name: Scan for secrets
        run: prowl scan . --format sarif -o prowl.sarif --fail-on high

      - name: Upload SARIF
        if: always()   # upload findings even when the gate fails the build
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: prowl.sarif
```

For GitLab, write SARIF to a path declared as a `sast` report artifact in your `.gitlab-ci.yml` (`artifacts:reports:sast: prowl.sarif`) and gate the job with `--fail-on`.

## Scanning remote sources in CI

`prowl image`, `prowl org`, `prowl repo`, and `prowl bucket` gate exactly like `scan`: they run the same pipeline and exit through the same gate — `0` clean (or no finding reached `--fail-on`), `1` when a finding is `>= --fail-on`, `2` on error (bad ref, clone/listing/download failure, bad flag). The same caveat applies: **without `--fail-on` the command never returns `1`**, so always set a threshold to fail the build.

Gate a freshly-built image before you push it. `--fail-on high` fails the step on any high-or-critical finding across all layers and the image config:

```sh
prowl image "$IMAGE" --fail-on high
```

Nightly org-wide sweep. The token is read from the environment (never argv, never logged); the exit code is the **worst across every repo**, so one high finding anywhere fails the job:

```sh
GITHUB_TOKEN=$TOKEN prowl org github:my-org --fail-on high --format sarif -o org.sarif
```

`org` with `--format sarif` **streams one SARIF document per repo** to `org.sarif` (it does not merge them into a single run) — consume it as a stream of per-repo reports, or use `--format pretty` for a per-repo header. Same for `--format json`.

Scan a pull request's remote repo by URL. `repo` scans a **clone**, so diff against the PR's base with `--since` (there is no index to stage — `--staged` is for local pre-commit against `git diff --cached`, not a fresh checkout):

```sh
prowl repo "$REPO_URL" --since "$BASE_SHA" --fail-on medium
```

To sweep the clone's full blob history instead of a diff, use `--history` (a full clone); to scan a specific branch or tag, add `--branch NAME`. The clone is made in a temp dir and removed afterward.

Scan a cloud-storage prefix before it ships. `bucket` downloads the prefix with the runner's own `aws`/`gcloud` CLI (which must be installed and authenticated in the job) into a temp dir, scans it, and removes it; `--fail-on high` gates the step on any high-or-critical finding:

```sh
prowl bucket s3://my-artifacts/ --fail-on high
```

## See also

- [Scanning Files](Scanning-Files.md)
- [Output Formats](Output-Formats.md)
- [Configuration](Configuration.md)
- [Repository Scanning](Repository-Scanning.md)
- [Org Scanning](Org-Scanning.md)
- [Container Scanning](Container-Scanning.md)
- [Cloud Storage Scanning](Bucket-Scanning.md)
- [Security Model](Security-Model.md)
- [Server Mode](Server-Mode.md)
- [Home](README.md)
