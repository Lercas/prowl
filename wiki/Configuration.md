# Configuration

Prowl reads an optional `.prowl.yaml` from the current directory to set excludes, toggle detectors, define allowlists, and pick output and performance defaults. CLI flags always win over the file, which wins over built-in defaults.

```yaml
# .prowl.yaml
version: 1

exclude:
  - vendor/**
  - "**/*.min.js"
  - testdata/

detectors:
  disable:
    - generic-api-key          # noisy in this repo
  custom:
    - id: internal-token
      regex: 'INT-[A-Z0-9]{20}'
      category: auth

allowlist:
  paths:
    - test/fixtures
  values:
    - AKIAIOSFODNN7EXAMPLE      # the documented AWS sample key
  regexes:
    - 'EXAMPLE[0-9A-Z]+'
  stopwords:
    - example
    - dummy

output:
  format: pretty               # pretty | json | sarif
  fail_on: high                # exit non-zero at or above this severity
  redact: true

performance:
  max_size: 5242880            # 5 MiB; skip files larger than this
  workers: 8
```

Discovery looks for `.prowl.yaml`, then `.prowl.yml`, then `prowl.yaml` in the working directory. See [Scanning Files](Scanning-Files.md) for the scan flags these defaults back.

## Fields

Every field of the config (from `internal/config/config.go`). All are optional.

### Top level

| Field | Type | Meaning |
|---|---|---|
| `version` | int | schema version |
| `exclude` | list of glob/substring | paths to skip; appended to any `--exclude` flags |

`exclude` (and `allowlist.paths`, below) match a path one of two ways, decided per entry:

- contains a glob metacharacter (`*`, `?`, `[`) → matched as a **glob**: `*.go`, `**/vendor/**`, `**/*.min.js`. `**` is doublestar (matches across `/`), and a relative pattern is also tried against every trailing path segment, so `*.go` matches `a/b/c.go` and `vendor/**` matches `x/vendor/lib.js`.
- no glob metacharacter → plain **substring** match (legacy behaviour): `testdata/` matches any path containing `testdata/`.

An empty list entry never matches (it is a no-op, not match-all).

### detectors

| Field | Type | Meaning |
|---|---|---|
| `detectors.enable` | list of string | if set, run **only** these detector type ids |
| `detectors.disable` | list of string | turn off these detector type ids |
| `detectors.custom` | list | user-defined regex detectors |

A custom detector is `{ id, regex, category }`. `category` drives its severity (defaults to `generic` when empty); an invalid regex is reported as a config issue, not silently dropped. `enable` and `disable` interact as: a disabled id is always off; if `enable` is non-empty, only ids in it run (and not also disabled).

An **empty or match-everything regex** (`""`, `.*`, `.+`, `(?i).*`, and other `.*`-equivalents) is **rejected at load** — Prowl refuses to start rather than flag every line in the tree as a critical finding. Fix the pattern or remove the rule. `prowl config validate` (below) surfaces the same problem without running a scan.

```yaml
detectors:
  enable:                      # whitelist mode: ONLY these run
    - aws-access-key-id
    - stripe-secret-key
  custom:
    - id: internal-token
      regex: 'INT-[A-Z0-9]{20}'
      category: auth
```

### allowlist

Suppresses findings. A finding is dropped if **any** allowlist rule matches it.

| Field | Type | Match |
|---|---|---|
| `allowlist.paths` | list of glob/substring | match against the finding's path — glob if it has `*`/`?`/`[`, else substring (same rule as `exclude`) |
| `allowlist.values` | list of string | exact value to ignore |
| `allowlist.regexes` | list of regex | ignore values matching any pattern |
| `allowlist.stopwords` | list of string | ignore values **containing** any word (case-insensitive) |

```yaml
allowlist:
  paths: [test/fixtures, docs/, "**/*_test.go"]
  values: [AKIAIOSFODNN7EXAMPLE]
  regexes: ['EXAMPLE[0-9A-Z]+']
  stopwords: [example, dummy, placeholder]
```

An invalid allowlist regex is surfaced as a config issue rather than dropped.

### output

| Field | Type | Meaning |
|---|---|---|
| `output.format` | string | `pretty` \| `json` \| `sarif` |
| `output.fail_on` | string | exit non-zero when a finding at or above this severity is present |
| `output.redact` | bool | redact secret values in output (pointer: only applied when explicitly set) |

`format` only overrides the default — an explicit `--format` flag still wins.

### performance

| Field | Type | Meaning |
|---|---|---|
| `performance.max_size` | int (bytes) | skip files larger than this |
| `performance.workers` | int | concurrent scan workers |

Both apply only when the corresponding flag is unset (`--max-size` default is 10 MiB; `--workers` default is auto).

## prowl config validate

`prowl config validate [FILE]` lints a `.prowl.yaml` (default `./.prowl.yaml`) and reports the problems a plain load silently swallows:

- **unknown / typo'd keys** — a stray `allowlsit:` or `detctors:` is dropped by the YAML loader without error, so the setting under it never takes effect. Validate flags unrecognized top-level keys (with a "did you mean" hint) and unrecognized keys nested under `detectors` / `allowlist`.
- **an empty or match-everything custom-detector regex** (`""`, `.*`, and `.*`-equivalents) — this is fatal at load, but `validate` surfaces it without running a scan.
- **an unrecognized custom-rule category** — an unknown `category` silently downgrades the rule to severity `medium`; validate lists the known categories.

Exit code is 0 when the file is clean, 1 when problems are found, 2 on a usage or I/O error.

```sh
prowl config validate                 # lint ./.prowl.yaml
prowl config validate ci/.prowl.yaml  # lint a specific file
```

```
ci/.prowl.yaml: 2 problem(s)
  - custom rule "my_rule": regex ".*" matches everything (empty or .*-equivalent); refusing to load (it would flag every line as a critical finding)
  - unknown top-level key "allowlsit" (did you mean one of: allowlist, detection, detectors, exclude, limits, output, performance, version?)
```

A clean file prints `<file>: ok`. Run it in CI before a scan to catch a config mistake that would otherwise pass silently.

## Untrusted config security

A `.prowl.yaml` shipped **inside a scanned tree** is attacker-controlled when you scan someone else's code — a fork's PR, a vendored dependency. A malicious one could disable detectors or add allowlist rules to silently blind the scan.

So when Prowl **auto-discovers** a config in the working directory, it prints a warning — but only when that config uses a channel that actually **hides a secret a detector found**: a `detectors.disable` entry, or any `allowlist.*` rule (`paths`, `values`, `regexes`, `stopwords`):

```
WARN  in-repo .prowl.yaml suppresses detection — review if scanning untrusted code
      path=.prowl.yaml disabled_detectors=1 allowlist_rules=3
```

The warning is **scoped to those suppression channels** so it is not noisy on a team's own repo: a discovered config that only sets `exclude` (path scoping), `enable` (run-only-these — a precision feature), or `output` / `performance` does **not** trigger it. Those are common in a project's own `.prowl.yaml`, and a malicious one is anyway visible as "0 files / few detectors scanned".

To vouch for a config and silence the warning even when it does suppress, pass it explicitly:

```sh
prowl scan . --config .prowl.yaml          # I trust this config
prowl scan ./vendor/dep --config ci/prowl.yaml
```

An explicitly passed `--config` is trusted and never triggers the warning. So is a discovered config that only sets excludes / enable / output / performance.

## Inline suppression

Suppress a single source line by adding a pragma comment to it. Prowl honors several markers for compatibility with gitleaks and detect-secrets:

- `prowl:allow`
- `gitleaks:allow`
- `pragma: allowlist secret`
- `noqa: secret`

```python
API_KEY = "AKIAZZ11YY22XX33WW44"  # prowl:allow
token    = "ghp_xxxxxxxxxxxxxxxxxxxx"  # gitleaks:allow
```

Any finding whose location falls on a line containing one of these markers (case-insensitive) is dropped.

## Environment variables

Every environment variable Prowl honors, what it does, and its default.

| Variable | Effect | Default |
|---|---|---|
| `PROWL_HOME` | install dir for rules/verifiers. Overrides the two paths below | unset → `~/.prowl` |
| `XDG_CONFIG_HOME` | when `PROWL_HOME` is unset, the install dir is `$XDG_CONFIG_HOME/prowl` | unset → `~/.prowl` |
| `PROWL_ALLOW_PRIVATE_IPS` | if set (non-empty), opts out of the SSRF guard so `--verify` and `prowl domain` may connect to private / loopback / link-local IPs — for internal verifiers and self-hosted targets | unset (guard on) |
| `GITHUB_TOKEN` | auth for `prowl org` against GitHub — required to list private repos and to raise the API rate limit | unset (public, unauthenticated) |
| `GITLAB_TOKEN` | auth for `prowl org` against GitLab — required for private groups/projects | unset (public, unauthenticated) |
| `BITBUCKET_TOKEN` | auth for `prowl org` against Bitbucket — required for private workspaces | unset (public, unauthenticated) |
| `GITHUB_API` | override the GitHub API host for `prowl org` — point at GitHub Enterprise | `https://api.github.com` |
| `GITLAB_API` | override the GitLab API host for `prowl org` — point at a self-hosted GitLab | `https://gitlab.com/api/v4` |
| `NO_COLOR` | if set (any value), disables ANSI colour in the report and the logs — identical to `--no-color` | unset (colour when stdout is a TTY) |

Resolution order for the install dir is `PROWL_HOME` → `$XDG_CONFIG_HOME/prowl` → `~/.prowl`. Installed rules go in `<home>/rules`, verifiers in `<home>/verifiers`.

The `org` tokens and API hosts only affect repository listing — `prowl org` reads `GITHUB_TOKEN` / `GITLAB_TOKEN` / `BITBUCKET_TOKEN` to enumerate repos, then the per-repo `git clone` uses your normal git credentials (ssh keys / credential helper). See [Org Scanning](Org-Scanning.md). `PROWL_ALLOW_PRIVATE_IPS` is the documented opt-out for the [Security Model](Security-Model.md) SSRF guard; set it only when you trust the verifier endpoints / domain targets, as it relaxes the guard for the whole process.

## Flags

Flags accept either a separate value or an `=`-joined value: `--format json` and `--format=json` are equivalent. The `=` form is also the escape for a value that itself begins with `--` (a bare `--flag --x` errors, so write `--flag=--x`). `--workers 0` (the default) means auto — Prowl uses `runtime.NumCPU()`.

## gitleaks compatibility

Prowl is a drop-in for several gitleaks conventions:

- The `gitleaks:allow` inline pragma is honored (alongside `prowl:allow`).
- gitleaks `.toml` rulesets import unchanged via `--rules` (`--rules-only` for a pure drop-in). See [Rules](Rules#importing-gitleaks-and-trufflehog-rulesets).
- trufflehog `.yaml` rulesets import the same way.

## See also

- [Scanning Files](Scanning-Files.md)
- [Rules](Rules.md)
- [Verifiers](Verifiers.md)
- [Live Verification](Live-Verification.md)
- [Architecture](Architecture.md)
- [Home](README.md)
