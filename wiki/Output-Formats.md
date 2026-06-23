# Output Formats

Prowl renders findings in three formats, selected with `--format`:

| Value | Purpose |
|-------|---------|
| `pretty` (default) | Human-readable terminal report, findings grouped by file |
| `json` | Machine-readable findings array with the full per-finding record |
| `sarif` | SARIF 2.1.0 for the GitHub / GitLab code-scanning tabs |

Every scanning command (`prowl scan`, `prowl domain`) accepts `--format`. By default the report goes to stdout; `-o`/`--output FILE` writes it to a file instead (and a file is never colorized).

```sh
prowl scan .                                  # pretty, to the terminal
prowl scan . --format json                    # JSON, to stdout
prowl scan . --format sarif -o out.sarif      # SARIF, to a file
```

### Deduplication

Across every format, the same secret found repeatedly in one file is reported **once** — deduplication is on by default, collapsing findings that share a `fingerprint` (`sha256` over `type | path | raw-value`). Pass `--no-dedupe` to report every occurrence instead. A finding with no stable fingerprint (an empty raw value) is never collapsed, so distinct hits are never lost. See [cutting noise](Scanning-Files.md#cutting-noise) for the related report-time filters (`--min-confidence`, `--min-severity`, `--disable`).

### Multi-target output

`prowl scan` / `repo` / `image` / `bucket` scan a single target and emit one report. `prowl org` scans many repos **concurrently** but still emits **one aggregate report** — every finding's path is prefixed `"<owner>/<repo>: "` so you can tell which repo it came from:

- `pretty` groups findings across the whole org by file.
- `json` / `sarif` is a single valid document spanning all repos (one JSON object / one SARIF run) — no stream-splitting needed.

The exit code reflects `--fail-on` over the merged findings of all repos (`1` if any repo trips the threshold); a repo that fails to clone is logged and skipped, and `2` is returned only if the listing fails or no repo could be scanned. See [Org Scanning](Org-Scanning.md).

## pretty

The default. Findings are grouped by file, worst file first (the file with the highest-severity finding leads); within a file, findings sort by severity then line. Each line shows a severity icon and label, the secret type, the `line:col`, and the value masked to its first four and last four characters. A trailing tag carries a live/dead verification result, a checksum-verified marker, or a low-confidence percentage. A summary footer closes the report.

```console
$ prowl scan .
INFO scan complete findings=5 critical=1 high=3 medium=1 low=0 took=2ms

  src/config/prod.ts
    ✖ critical  db_connection_string  3:17     post********5432
    ✖ high      aws_access_key_id     2:20     AKIA********DSYP

  .env.example
    ✖ high      github_pat_classic    2:14     ghp_********i3as  ✓ checksum

  deploy/id_rsa
    ✖ high      private_key_pem       1:1      RSA PRIVATE KEY [sha256:8bcac790] #753a0e0b

  docs/onboarding.md
    ⚠ medium    generic_password      1:43     Welc***123!  60%

  5 findings  1 critical · 3 high · 1 medium  in 4 files
```

Severity icons: `✖` critical/high, `⚠` medium, `•` low, `·` info.

The trailing tag is conditional, in priority order:

- With `--verify`, a confirmed-live secret is tagged `live` (bold red) and a provider-rejected one `dead` (dim). This is the strongest false-positive signal Prowl emits — see [Live Verification](Live-Verification.md).
- A **checksum-verified** hit — one whose value passed a structural checksum (stage `L1-checksum`: GitHub CRC, JWT structure, Luhn, etc.; confidence ~`0.99`) — is tagged `✓ checksum` (green). It marks a hit as structurally proven, not a regex guess, without printing a near-meaningless `99%`.
- Without verification or a checksum, a finding whose confidence is below `0.7` shows that confidence as a percentage (e.g. `60%`).
- High-confidence regex matches (`0.7`–`0.98`) carry no tag — a bare row already means a confident match.

### Private-key redaction

A PEM private key can't be usefully masked to "first four + last four" (every key begins `----- BEGIN` and ends `KEY -----`). Instead its redaction is the key **type plus a short hash** of the header, e.g. `RSA PRIVATE KEY [sha256:8bcac790]` (or `OPENSSH PRIVATE KEY [sha256:…]`). The hash is one-way, so it reveals no key material. In the pretty format a short fingerprint suffix (`#753a0e0b`) is appended too, so two distinct keys of the same type are told apart at a glance. This same `[sha256:…]` redaction appears in the JSON/SARIF `redacted` field.

A clean scan prints a single line:

```console
$ prowl scan .
✓ no secrets found
```

Color is automatic: ANSI styling turns on only when stdout is a TTY. It is suppressed by `--no-color` or by setting the `NO_COLOR` environment variable (any value), which is the right switch for CI logs. The `INFO scan complete …` summary line is a log record on stderr, separate from the report on stdout, and follows the logging flags (`-q`, `-s`, `--log-format`).

## json

`--format json` emits one object with a `findings` array and a `count`. Findings are sorted by severity (highest first), then path, then line. The fields are the [`model.Finding`](Architecture.md) record:

| Field | Type | Notes |
|-------|------|-------|
| `detector` | string | the detector/rule that fired (same as `type` for built-in cascade hits) |
| `type` | string | secret type id, e.g. `aws_access_key_id`, `generic_password` |
| `confidence` | number | 0–1; checksum-validated hits score highest |
| `severity` | string | `critical` \| `high` \| `medium` \| `low` \| `info` |
| `source` | string | origin class of the content: `code` for source code, `file` for a plain text/prose file (e.g. `.md`, `.txt`), plus `jira` \| `slack` \| `log` for the respective connectors. A plain `.md`/`.txt` file now reports `file` (an internal ML bucket label is no longer leaked here). |
| `path` | string | file path (or asset URL for `prowl domain`) |
| `line` | number | 1-based line |
| `col` | number | 1-based column |
| `redacted` | string | the masked value (first 4 + `*` + last 4); the raw secret never appears |
| `stage` | string | which cascade stage produced it, e.g. `L1-regex`, `L1-checksum`, `L1-context-pw`, `L1-entropy`, `L1-base64`, `rule` |
| `verified` | bool | present only under `--verify`; `true` = provider-confirmed live, `false` = rejected. Omitted when verification was not attempted or inconclusive |
| `rationale` | string | present only when set, e.g. `verified live via aws-sts`; omitted otherwise |
| `fingerprint` | string | sha256 over `type\|path\|raw-value`, a stable identity used for [baselining](Configuration.md) |

`verified`, `rationale`, and `fingerprint` are `omitempty`: they are absent from the object when empty. A scan without `--verify` therefore carries no `verified` or `rationale` key.

On a clean scan `findings` is always the empty array `[]`, never `null`, so consumers can iterate it unconditionally (`jq '.findings[]'`, a `for` loop) without a nil check:

```json
{
  "count": 0,
  "findings": []
}
```

```json
{
  "count": 4,
  "findings": [
    {
      "detector": "db_connection_string",
      "type": "db_connection_string",
      "confidence": 0.9,
      "severity": "critical",
      "source": "code",
      "path": "src/config/prod.ts",
      "line": 3,
      "col": 17,
      "redacted": "post********5432",
      "stage": "L1-regex",
      "fingerprint": "b2b63f8f78a3f82e37e6e6705f9ccea2b95ca4a2d4ada0a6d326ca5a40db8f9f"
    },
    {
      "detector": "github_pat_classic",
      "type": "github_pat_classic",
      "confidence": 0.99,
      "severity": "high",
      "source": "code",
      "path": ".env.example",
      "line": 2,
      "col": 14,
      "redacted": "ghp_********i3as",
      "stage": "L1-checksum",
      "fingerprint": "7832c5a1dd00c591dc835f41506b7806acb5d0d19f12860d7872129b7d600050"
    }
  ]
}
```

The `fingerprint` is computed over the FULL raw value before redaction, so two distinct secrets that share their first/last four characters (every AWS key starts `AKIA`) never collide. `line`/`col` are excluded from it, so the identity survives a secret moving lines.

## sarif

`--format sarif` emits SARIF 2.1.0, the format the GitHub and GitLab Security tabs ingest. The run carries one `rule` per distinct secret type and one `result` per finding. Severity maps to a SARIF level: critical/high → `error`, medium → `warning`, low/info → `note`. Each result's message records the type, severity, confidence, stage, and redacted value; its location carries the file URI plus `startLine`/`startColumn`.

Two fields make the results rank and de-duplicate correctly in code-scanning UIs:

- **`security-severity`** — a `0`–`10` CVSS-style score on each rule's `defaultConfiguration.properties` (critical `9.0`, high `8.0`, medium `5.0`, low `3.0`, info `2.0`). GitHub and GitLab use it to sort and filter alerts, so a critical leak ranks above a high one instead of all hits landing at the same level.
- **`partialFingerprints`** — a stable `{"prowl/v1": "<fingerprint>"}` per result. It gives each alert a durable identity, so a finding that simply moved lines is recognized as the same alert rather than resurfacing as a new one (and a fixed one stays closed). It is omitted only when a finding has no stable fingerprint.

```sh
prowl scan . --format sarif -o results.sarif
# then upload results.sarif via github/codeql-action/upload-sarif
```

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "prowl",
          "informationUri": "https://github.com/Lercas/prowl",
          "rules": [
            {
              "id": "db_connection_string",
              "name": "db_connection_string",
              "shortDescription": { "text": "db_connection_string secret" },
              "defaultConfiguration": {
                "level": "error",
                "properties": { "security-severity": "9.0" }
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "db_connection_string",
          "ruleIndex": 0,
          "level": "error",
          "message": { "text": "db_connection_string secret (critical, conf 0.90, L1-regex): post********5432" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "src/config/prod.ts" },
                "region": { "startLine": 3, "startColumn": 17 }
              }
            }
          ],
          "partialFingerprints": { "prowl/v1": "b2b63f8f78a3f82e37e6e6705f9ccea2b95ca4a2d4ada0a6d326ca5a40db8f9f" },
          "properties": { "confidence": 0.9, "stage": "L1-regex" }
        }
      ]
    }
  ]
}
```

## Exit codes and gating

Output format is independent of the exit code. By default Prowl exits `0` even with findings; `--fail-on <severity>` makes it exit `1` when any finding is at or above the given level, which is the CI gate:

```sh
prowl scan --staged --fail-on high            # block a commit on a high+ finding
```

See [Scanning Files](Scanning-Files.md) for source modes (`--staged`, `--since`, `--history`) and [Configuration](Configuration.md) for baselines and the `.prowl.yaml` `output.format` / `output.fail_on` defaults.

## See also

- [Scanning Files](Scanning-Files.md)
- [Live Verification](Live-Verification.md)
- [Configuration](Configuration.md)
- [Architecture](Architecture.md)
- [Home](README.md)
