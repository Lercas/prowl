# Quick Start

Copy-paste workflows for the most common tasks. Each assumes the binary is installed and the libraries are set up (`prowl rules update` / `prowl verifiers update`; see [Installation](Installation.md)).

## Scan the working tree

Walk the current directory and report findings. Binaries, large files, and noise dirs (`.git`, `node_modules`, `vendor`, ...) are skipped automatically.

```bash
prowl scan .
```

## Scan only git-staged files (pre-commit)

Scan exactly what is staged for commit — fast, and the natural pre-commit hook. Exits non-zero only if a finding meets the `--fail-on` threshold.

```bash
prowl scan --staged --fail-on high
```

## Scan a commit range

Scan files changed since a revision (any git ref: a branch, tag, or SHA). Ideal for CI on pull requests.

```bash
prowl scan --since origin/main --fail-on medium
```

## Verify findings are live

Drop everything except secrets the provider confirms are still active — the strongest false-positive filter.

```bash
prowl scan . --verified-only
```

## Write SARIF for CI

Emit a SARIF report to a file for GitHub code scanning or any SARIF-aware tool.

```bash
prowl scan . --format sarif -o prowl.sarif
```

## Gate CI on severity

Print the report and exit `1` if any finding is at least `high`, failing the pipeline. Combine with `-s` to suppress the report and use only the exit code.

```bash
prowl scan . --fail-on high          # report + non-zero exit on high+
prowl scan . --fail-on high -s       # exit code only, no output
```

## Create and use a baseline

Snapshot today's findings as accepted, then on later runs suppress everything in the baseline so only new secrets surface.

```bash
prowl scan . --write-baseline .prowl-baseline.json   # record current state, exit 0
prowl scan . --baseline .prowl-baseline.json         # report only new findings
```

A `.prowl-baseline.json` in the working directory is picked up automatically, so once it exists `prowl scan .` already suppresses known findings.

## Scan full git history

Stream every blob ever committed to catch secrets that were removed from `HEAD` but still live in history.

```bash
prowl scan --history --format json -o history.json
```

## See also

- [Scanning Files](Scanning-Files.md)
- [Live Verification](Live-Verification.md)
- [Output Formats](Output-Formats.md)
- [CI/CD Integration](CI-CD-Integration.md)
- [Configuration](Configuration.md)
- [Home](README.md)
