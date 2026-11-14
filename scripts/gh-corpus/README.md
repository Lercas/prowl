# GitHub corpus scan

Scan a sample of recent **public** GitHub repositories with Prowl and analyze the findings — to study
the detector's behavior on real-world code: what it surfaces, the false-positive type mix, verified vs
unverified, and noise distribution. This is the same kind of real-world signal the ML flywheel consumes.

## Use

```bash
# build a prowl binary once
go build -o ./prowl ../../tool/cmd/prowl

# end-to-end: collect 5000 recent repos, scan, analyze
PROWL=./prowl ./run.sh 5000

# or step by step
python3 collect.py -n 5000 -o repos.txt        # needs `gh auth login`
PROWL=./prowl WORKERS=8 ./scan.sh repos.txt     # -> findings/<owner__repo>.json
python3 analyze.py findings                      # -> type / FP / severity report
```

Knobs (env vars for `scan.sh`): `WORKERS` (parallel repos, default 8), `SCAN_FLAGS` (default `--ml`),
`SCAN_TIMEOUT` / `CLONE_TIMEOUT` (seconds), `MAXSIZE` (bytes/file). The scan is **resumable** — re-running
skips repos already in `findings/`, so a long run can be interrupted and continued.

## What it does

- `collect.py` — pages the GitHub Search API by most-recently-pushed (windowed past the 1000-result cap)
  for non-fork public repos above a size floor.
- `scan.sh` — shallow-clones each repo's HEAD, removes `.git`, runs `prowl scan --ml`, deletes the clone.
  Read-only, parallel, bounded by timeouts and `--max-size`.
- `analyze.py` — aggregates every `findings/*.json` into a report headlined by the **LIVE exposed
  secrets** (verified by the provider), then total findings, typed vs generic catch-all (the FP mix),
  by type / severity / extension, the verify breakdown, and the per-repo noise distribution.

The default `SCAN_FLAGS` is `--ml`: a redacted, no-network pass. For explicitly authorized live-secret
research, set `SCAN_FLAGS="--ml --verify --show-secrets"`; this adds post-detection provider validation
and writes raw secret values to the findings directory.

## Scope and responsibility

- Only **public** repositories, **read-only** (clone + static scan + delete). Use a `gh` token to respect
  GitHub rate limits and ToS.
- With an explicit `--verify --show-secrets` override the run validates credentials against their
  providers and writes **raw secret values** to `findings/`. Treat that output as sensitive: never
  commit it, and delete it when done.
- If a secret is genuinely **live**, **disclose it responsibly to the repo owner — never use it.**
  `--verify` only confirms validity; it must not be a step toward access.
