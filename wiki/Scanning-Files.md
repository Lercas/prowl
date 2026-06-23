# Scanning Files

```
prowl scan [path...]
```

Scan files and directories for secrets. With no path, scans the current directory (`.`). Multiple paths are allowed:

```bash
prowl scan .
prowl scan src/ config/ deploy/
prowl scan ./app --exclude testdata --fail-on high
```

By default `scan` walks the filesystem. Three flags switch the input to git instead: `--staged`, `--since <rev>`, and `--history` (see [Git source modes](#git-source-modes)). A single `-` reads stdin, and piped input with no path is read automatically (see [Scanning stdin](#scanning-stdin)). These input modes are mutually exclusive — combining them is a usage error (see [One input at a time](#one-input-at-a-time)). To clone and scan a remote repository by URL, use [Repository Scanning](Repository-Scanning.md); to pull and scan a container image, use [Container Scanning](Container-Scanning.md).

## What gets scanned

The filesystem walk yields text files only. It automatically skips:

- Noise directories: `.git`, `node_modules`, `vendor`, `dist`, `build`, `.venv`, `__pycache__`, `target`, `.idea`, `.terraform`.
- Binary file extensions (images, archives, fonts, compiled objects, `.wasm`, `.exe`, ...) and any file whose first bytes look binary.
- Empty files and files larger than `--max-size`.
- Symlinks — they are never followed, so a link pointing outside the scanned root cannot escape scope.

Once the libraries are installed, `scan` auto-loads the rule templates from `~/.prowl/rules`; `--verify` auto-loads verifiers from `~/.prowl/verifiers`. No `--rules-dir` / `--verifiers` flags are needed for the default library.

## Core flags

Value flags accept both `--flag value` and `--flag=value`. Use the `=` form when a value itself begins with `--` (e.g. `--exclude=--generated/`).

| Flag | Description |
|------|-------------|
| `--format pretty\|json\|sarif` | Report format. Default `pretty`. |
| `--fail-on LEVEL` | Exit `1` if any finding is at least `LEVEL` (`info`, `low`, `medium`, `high`, `critical`). Default: no gate. |
| `--exclude PATTERN` | Skip matching paths. Repeatable. A pattern with glob metacharacters (`*`, `?`, `[`) is matched as a glob — including `**` doublestar across `/` (e.g. `*.go`, `**/vendor/**`); otherwise it is a plain substring (e.g. `testdata`). Globs are anchored to any path suffix, so `*.go` matches `a/b/c.go`. Same matching as `allowlist.paths`. |
| `--max-size BYTES` | Skip files larger than this. Default `10485760` (10 MiB). |
| `--workers N` | Concurrency. Default: number of CPUs. |
| `--timeout DUR` | Abort after a Go duration (e.g. `30s`, `5m`); partial results are still reported. |
| `-o`, `--output FILE` | Write the report to `FILE` instead of stdout (never colorized). |
| `--config FILE` | Load a config file explicitly instead of auto-discovering one. |

`--max-size`, `--workers`, `--fail-on`, and the format can also come from a config file; command-line flags win. See [Configuration](Configuration.md).

## Detection rules

| Flag | Description |
|------|-------------|
| `--taxonomy PATH` | Override the embedded built-in taxonomy with a YAML file. |
| `--rules FILE` | Import external rules. Repeatable. Auto-detects gitleaks `.toml`, trufflehog `.yaml`, or prowl YAML. |
| `--rules-only` | Use ONLY `--rules` files; disable the built-in taxonomy. Turns prowl into a pure gitleaks/trufflehog drop-in. |
| `--rules-dir DIR` | Load nuclei-style rule templates from `DIR`. Repeatable. Overrides the auto-loaded `~/.prowl/rules`. |

## Template filters

These narrow which rule templates run (whether auto-loaded or from `--rules-dir`). Values are comma-separated.

| Flag | Description |
|------|-------------|
| `--tags T1,T2` | Run only templates carrying any of these tags. |
| `--exclude-tags T1,T2` | Skip templates carrying any of these tags. |
| `--rule-severity S1,S2` | Run only templates of these severities. |

```bash
prowl scan src --rules-dir rules/ --tags aws,stripe
prowl scan . --exclude-tags experimental --rule-severity high,critical
```

## Cutting noise

These drop findings at report time — after detection, before the report is written — so they trim what you see without editing a `.prowl.yaml` or disabling a detector entirely. They apply to every finding, built-in or from `--rules-dir`.

| Flag | Description |
|------|-------------|
| `--min-confidence F` | Drop findings with confidence below `F` (a number in `0..1`). E.g. `--min-confidence 0.7` keeps only confident hits. |
| `--min-severity LEVEL` | Drop findings below `LEVEL` (`info`, `low`, `medium`, `high`, `critical`). Unlike `--rule-severity` — which only selects which `--rules-dir` templates run — this filters built-in findings too. |
| `--disable T1,T2` | Drop findings of these detector types (the `type` id, e.g. `generic_high_entropy`). Comma-separated. |
| `--no-dedupe` | Report every occurrence. Deduplication is **on by default**: the same secret found repeatedly in one file is reported once (collapsed by fingerprint). `--no-dedupe` shows each occurrence. |

```bash
prowl scan . --min-severity high                  # only high+ findings
prowl scan . --min-confidence 0.7                 # drop weak/low-confidence guesses
prowl scan . --disable generic_high_entropy       # silence one noisy detector type
prowl scan . --no-dedupe                          # show every occurrence, not one per file
```

`--min-confidence` / `--min-severity` / `--disable` only hide findings from the report; they do not stop detection (so a `--fail-on` gate sees the filtered set). For permanent, repo-wide suppression of a detector or a value, use a `.prowl.yaml` instead — see [Configuration](Configuration.md).

## Live verification

Verification confirms a candidate secret is actually live by calling the provider. See [Live Verification](Live-Verification.md).

| Flag | Description |
|------|-------------|
| `--verify` | Mark each finding live / not-live by querying the provider. |
| `--verified-only` | Report ONLY provider-confirmed-live secrets. Implies `--verify`. Strongest false-positive filter. |
| `--verifiers DIR` | Verifier YAML directory. Repeatable. Overrides the auto-loaded `~/.prowl/verifiers` (falls back to `./verifiers`). |

```bash
prowl scan . --verify
prowl scan . --verified-only --format sarif -o report.sarif
```

## Baselines

A baseline records known/accepted findings so subsequent scans report only what is new.

| Flag | Description |
|------|-------------|
| `--write-baseline FILE` | Write current findings to `FILE` as the baseline, then exit `0` (no gating). |
| `--baseline FILE` | Suppress any finding present in `FILE`. |

If neither flag is given and `.prowl-baseline.json` exists in the working directory, it is loaded automatically. When a baseline suppresses one or more findings, the number is logged (`baseline suppressed findings count=N`) so an auto-loaded baseline can't silently mask a new leak.

```bash
prowl scan . --write-baseline .prowl-baseline.json   # snapshot accepted state
prowl scan . --baseline .prowl-baseline.json         # report new findings only
```

## Git source modes

These replace the filesystem walk. They are mutually exclusive with each other (and `[path...]` is ignored when one is set). Renames and deletions are excluded; only added, copied, and modified files are scanned.

| Flag | Scans |
|------|-------|
| `--staged` | Files staged for commit (`git diff --cached`, filter `ACM`). The pre-commit target. |
| `--since <rev>` | Files changed since `<rev>` (`git diff <rev>`, filter `ACM`). Any branch, tag, or SHA. |
| `--history` | Every blob ever committed across all refs (`git rev-list --objects --all`). Catches secrets removed from `HEAD` but still in history. Oversize/binary blobs are skipped without buffering. |

```bash
prowl scan --staged --fail-on high                 # pre-commit / CI gate
prowl scan --since origin/main --fail-on medium    # PR diff in CI
prowl scan --history --format json -o history.json # full-history sweep
```

When `--staged` or `--since` finds no changed files, the scan exits `0` immediately.

## Scanning stdin

Pass a single `-` as the path to scan standard input as one item instead of walking the filesystem. The whole stream is read and scanned as a single document; its path is reported as `<stdin>`. This is for piping logs, command output, or rendered manifests straight into the scanner without writing a temp file.

```bash
kubectl get secret my-secret -o yaml | prowl scan -
journalctl -u my-service --no-pager | prowl scan -
terraform show -json | prowl scan - --format json
```

Stdin is also read automatically when input is piped and no path is given, so the `-` is optional in a pipe:

```bash
kubectl get secret my-secret -o yaml | prowl scan        # same as 'prowl scan -'
```

(With no path and no pipe — an interactive terminal — `scan` defaults to the current directory, `.`.)

All detection, verification, and reporting flags apply as usual. Stdin is one of the mutually-exclusive input modes (see below).

## One input at a time

`scan` takes exactly one input source. The filesystem walk (`[path...]`), the git modes (`--staged`, `--since`, `--history`), and stdin (`-`) are **mutually exclusive** — combining them is a usage error that exits `2` with a clear message, rather than silently letting one win and emitting a cryptic git error:

```console
$ prowl scan --staged ./src
ERROR scan input modes are mutually exclusive — use only one given=--staged + paths
```

## Output and logging

| Flag | Description |
|------|-------------|
| `-s`, `--silence` | No output at all; the exit code is the only signal. CI mode. |
| `-q`, `--quiet` | Only warnings and errors on the log stream (the report still prints). |
| `-v`, `--verbose` | Debug logging. |
| `--log-format console\|json` | Log stream format. Default `console`. Use `json` for CI/log aggregation. |
| `--no-color` | Disable ANSI color. Also honored via the `NO_COLOR` env var. |

Logging precedence is `--silence` > `--verbose` > `--quiet`. Logs go to stderr; the report goes to stdout (or `--output`), so you can pipe the report while still seeing progress.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed; no `--fail-on` gate tripped (or none set). |
| `1` | A finding met or exceeded the `--fail-on` level. |
| `2` | Usage error, bad flag, or a fatal error (e.g. git or detector load failure). |

Prowl fails loudly rather than reporting a misleading "no secrets found". The following all exit `2` instead of `0`:

- A scan path that does not exist (a typo'd path no longer silently scans nothing).
- `--history` outside a git repository (mirrors how `--staged` / `--since` already behaved).
- Mutually-exclusive input modes combined (see [One input at a time](#one-input-at-a-time)).
- A bad flag value, e.g. `--timeout` that is not a positive Go duration, `--min-confidence` outside `0..1`, or `--min-severity` that is not a known level.
- For `prowl domain`, an unreachable / typo'd host where nothing could be fetched.

`-o` is an alias of `--output`. When an auto-discovered `.prowl-baseline.json` (or an explicit `--baseline`) suppresses findings, the count is logged (`baseline suppressed findings count=N`) so a baseline can't quietly hide a regression.

## Worked examples

```bash
# Strict CI gate: SARIF artifact, JSON logs, fail on high+, only confirmed-live secrets
prowl scan . --verified-only --format sarif -o prowl.sarif \
  --fail-on high --log-format json

# Scan a PR diff with only the AWS and GCP rule families, excluding test fixtures
prowl scan --since origin/main --tags aws,gcp --exclude testdata --fail-on medium

# Pure gitleaks drop-in: your rules only, no built-in taxonomy
prowl scan . --rules-only --rules .gitleaks.toml --format json

# Time-boxed full-history sweep on a large repo, reporting whatever finished
prowl scan --history --timeout 5m --format json -o history.json

# Quiet pre-commit hook: gate on high, suppress the report, exit code only
prowl scan --staged --fail-on high -s
```

## See also

- [Quick Start](Quick-Start.md)
- [Configuration](Configuration.md)
- [Rules](Rules.md)
- [Live Verification](Live-Verification.md)
- [Output Formats](Output-Formats.md)
- [CI/CD Integration](CI-CD-Integration.md)
- [Home](README.md)
