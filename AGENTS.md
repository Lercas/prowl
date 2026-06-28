# Prowl for AI agents

Prowl is a secret scanner with a 3-stage cascade: **L1** regex/checksum/entropy → **L2** ML
false-positive filter (`--ml`) → **L3** live verification (`--verify`). This guide is how an autonomous
agent drives it.

## MCP (preferred)

Prowl is an MCP server — register it once and call scans as tools:

```bash
claude mcp add prowl -- prowl mcp
```

Tools (each returns the JSON findings envelope as text):

| Tool | Required args | Optional | Use for |
|------|---------------|----------|---------|
| `prowl_scan` | `path` | `verify`, `ml`, `show_secrets` | a local file or directory |
| `prowl_domain` | `target`, `authorized` | `recon`, `verify` | a domain's public web surface |
| `prowl_mobile` | `path` | `ml` | an Android `.apk` / iOS `.ipa` |
| `prowl_repo` | `url` | `verify` | a git repository (tree + history) |

`prowl_domain` **refuses unless `authorized: true`** — set it only for a target you are authorized to
test (a bug-bounty scope, your own asset, an engagement). The same attestation gates the CLI's
`--authorized`.

## CLI (direct / scripting)

```bash
prowl scan ./src --ml --format json          # local tree, ML-denoised
prowl repo https://github.com/org/repo --verify
prowl domain example.com --authorized --recon --ml --format json
prowl mobile app.apk --ml --format json
prowl image registry/img:tag --format json   # container image layers
prowl bucket s3://bucket/prefix --format json
```

Key flags: `--format json|sarif|pretty`, `--ml` (L2), `--verify` (L3), `--show-secrets` (raw values for
authorized triage; default is redacted), `--verified-only` (drop everything L3 didn't confirm live),
`--max-size N` (bytes), `--fail-on SEV`.

## Output

JSON envelope: `{"findings": [...], "truncated": bool, ...}`. Each finding:

```jsonc
{ "type": "aws-access-key-id", "severity": "high", "path": "...", "line": 12,
  "redacted": "AKIA****WJX42K",        // full value when --show-secrets
  "verified": true,                     // true=LIVE, false=dead, null/absent=not checked
  "confidence": 0.9, "fingerprint": "..." }
```

Read `verified` first: **`true` = a live, exploitable secret** (the only kind worth a bug-bounty
report); `false` = dead/rotated; `null` = generic type with no verifier, judge by `type`/`confidence`.

## Decision guide

- **Want only real leaks?** add `--ml --verify`; for a noisy web/mobile target add `--verified-only`.
- **`--verify` hits the live provider** (validates the key). Fine for triage; never mass-exercise a key.
- **Generic findings** (`generic_password`, `generic_high_entropy`) are low-confidence and never
  verified — treat as candidates, not confirmed secrets. Typed findings (aws/stripe/google/jwt) are
  the signal.
- **`prowl_domain` / `prowl_mobile`** surface different things: web = source maps + bundles; mobile =
  `resources.arsc` + dex strings + `google-services.json` (often richer). Run both for full coverage.
