# Doctor and Troubleshooting

## prowl doctor

`prowl doctor` self-diagnoses an install end to end: it loads the taxonomy, exercises the checksum validators, runs representative detections, confirms example filtering, validates the active config, and checks for git. It exits `0` when nothing failed (warnings are tolerated) and `1` if any critical check fails — suitable as a smoke test in CI.

```console
$ prowl doctor
prowl doctor
  ✓ taxonomy                   31 detectors loaded
  ✓ regex RE2 compatibility    all detector regexes compile
  ✓ checksum validators        github CRC + jwt structural pass
  ✓ detection self-test        5/5 representative secrets detected
  ✓ example/placeholder filter known example/placeholder values ignored
  ✓ config                     valid (or none — using defaults)
  ✓ git                        available (git source modes enabled)
  ! aws CLI                    not found — 'prowl bucket s3://…' unavailable (install & configure credentials)
  ! gcloud CLI                 not found — 'prowl bucket gs://…' unavailable (install & authenticate)
  ✓ docker config              ~/.docker/config.json present ('prowl image' can reach your private registries)
  ! forge tokens               none set — 'prowl org' scans public repos only (set GITHUB_TOKEN/GITLAB_TOKEN/BITBUCKET_TOKEN for private repos & rate limits)
  ✓ runtime                    go1.24.3, 16 CPU (default --workers)

all checks passed — scanner is healthy
```

The `!` rows above are **warnings, not failures** — `doctor` still exits `0`. The four optional-tooling checks (`aws CLI`, `gcloud CLI`, `docker config`, `forge tokens`) each cover one source mode, so a warning means "configure this before using that source," not a broken install.

What each check verifies:

| Check | Pass condition | Fail / warn meaning |
|-------|----------------|---------------------|
| `taxonomy` | at least one detector compiled | `FAIL` if no detectors loaded |
| `regex RE2 compatibility` | every detector regex compiles under RE2 | `WARN` lists how many rules were skipped as non-RE2 |
| `checksum validators` | GitHub CRC accepts a known-good token and rejects a bad one; JWT structural check accepts a valid token | `FAIL` if any validator misbehaves |
| `detection self-test` | all built-in sample secrets (AWS key, DB URI, PEM, JWT, GitHub PAT) are detected | `FAIL` names which samples were missed |
| `example/placeholder filter` | `AKIAIOSFODNN7EXAMPLE` is NOT reported | `FAIL` if a documentation example leaked through |
| `config` | the resolved `.prowl.yaml` parses and its custom rules compile | `FAIL` lists the config issues |
| `git` | `git` is on `PATH` | `WARN`: `--staged`/`--since`/`--history` are unavailable |
| `aws CLI` | `aws` is on `PATH` | `WARN` (optional): `prowl bucket s3://…` is unavailable until you install & configure the AWS CLI |
| `gcloud CLI` | `gcloud` is on `PATH` | `WARN` (optional): `prowl bucket gs://…` is unavailable until you install & authenticate `gcloud` |
| `docker config` | `~/.docker/config.json` exists | `WARN` (optional): `prowl image` can still pull **public** images, but **private** registries need `docker login` |
| `forge tokens` | at least one of `GITHUB_TOKEN` / `GITLAB_TOKEN` / `BITBUCKET_TOKEN` is set | `WARN` (optional): `prowl org` sees only **public** repos and lower rate limits; the row names which tokens are set |
| `runtime` | informational | Go version and CPU count (the default `--workers`) |

The last four checks are **optional source tooling/auth** — each is needed only for one source mode, so they only ever `WARN`, never `FAIL`. They double as a quick answer to *"how do I authenticate source X?"*: run `prowl doctor` and read the row for the source you want — `aws CLI`/`gcloud CLI` for [bucket scanning](Bucket-Scanning.md), `docker config` for private-registry [image scanning](Container-Scanning.md), `forge tokens` for private-repo [org scanning](Org-Scanning.md).

`doctor` honors `--config FILE` and `--rules`/`--taxonomy`, so you can diagnose a specific configuration rather than the auto-discovered one.

## prowl detectors

`prowl detectors` lists the active detector types — the id, its category, and a `[checksum]` tag on types that carry a verifiable checksum.

```console
$ prowl detectors
aws_access_key_id          cloud
aws_secret_access_key      cloud
github_pat_classic         vcs            [checksum]
github_token_oauth         vcs            [checksum]
github_pat_fine_grained    vcs            [checksum]
gitlab_pat                 vcs
openai_api_key             ai
stripe_secret_key          payment
slack_token                messaging
telegram_bot_token         messaging
private_key_pem            pki
jwt                        auth           [checksum]
db_connection_string       db
generic_api_key            generic
generic_password           generic
generic_high_entropy       generic
...
```

This lists the built-in taxonomy only. Rule templates installed by `prowl rules update` or loaded with `--rules-dir` are listed by `prowl rules list` — see [Rules](Rules.md).

---

## Troubleshooting

### "No secrets found, but I expected some"

Most often the rule library is not installed. A fresh binary ships the built-in taxonomy (run `prowl doctor` — `taxonomy` should report dozens of detectors), but the full nuclei-style rule set lives outside the binary and is fetched on first use:

```sh
prowl rules update          # fetch + validate + install ~/.prowl/rules
prowl version               # shows binary + installed rule/verifier versions
```

`prowl version` reporting `rules: not installed` confirms this is the cause.

Second, check for a kill-switch config. A `.prowl.yaml` in the scanned tree can disable detectors or add an allowlist that suppresses your finding. Prowl warns when an auto-discovered config suppresses detection:

```console
WARN in-repo .prowl.yaml suppresses detection — review if scanning untrusted code path=.prowl.yaml disabled_detectors=1 allowlist_rules=3
```

If you see that line, inspect the file's `detectors.disable` and `allowlist` sections (see [Configuration](Configuration.md)). Inline `prowl:allow` / `gitleaks:allow` pragmas and a `.prowl-baseline.json` in the working directory also suppress findings.

Finally, confirm the file was scanned at all: files above `--max-size` (default 10485760 bytes / 10 MiB) are skipped, and `--exclude` / config `exclude` paths are skipped.

### "My internal verifier returns 'blocked address'"

`--verify` and `prowl domain` refuse to connect to private, loopback, and link-local addresses by default (the [SSRF guard](Security-Model.md)). A verifier pointed at an internal or self-hosted endpoint is blocked at dial time and reported as the safe category `blocked address`. Opt out explicitly:

```sh
PROWL_ALLOW_PRIVATE_IPS=1 prowl scan . --verify
```

Set this only when you trust your verifier endpoints — it disables the guard for the whole process. See [Live Verification](Live-Verification.md).

### "prowl org finds no/few repos or returns 401/403"

`prowl org` lists a platform's repositories over its REST API before cloning. Unauthenticated, it sees only public repos and hits a low API rate limit (a `401`/`403` is the symptom). Set the matching token:

```sh
GITHUB_TOKEN=ghp_…    prowl org github:my-org      # private repos + higher rate limit
GITLAB_TOKEN=glpat-…  prowl org gitlab:my-group     # private groups/projects
BITBUCKET_TOKEN=…     prowl org bitbucket:my-workspace
```

For a self-hosted install, also override the API host (the token alone still points at the public host):

```sh
GITHUB_API=https://github.example.com/api/v3 GITHUB_TOKEN=… prowl org github:my-org   # GitHub Enterprise
GITLAB_API=https://gitlab.example.com/api/v4 GITLAB_TOKEN=… prowl org gitlab:my-group  # self-hosted GitLab
```

These affect listing only; the per-repo `git clone` uses your normal git credentials. See [Org Scanning](Org-Scanning.md) and [Configuration](Configuration.md).

### "prowl image fails to pull / unauthorized"

`prowl image` pulls through the default Docker keychain (`~/.docker/config.json`). A private registry returns an auth error until you log in; public images need no credentials. Authenticate first, then scan:

```sh
docker login ghcr.io                 # or your registry host
prowl image ghcr.io/org/app:latest
```

`prowl image alpine:latest` (a public image) works with no login.

### "prowl image reports password findings from system files (openssl.cnf, ssl certs)"

`prowl image` scans every layer's files, which includes the OS packages baked into a base image. The generic detectors fire on stock config files like `openssl.cnf` or bundled `ssl` certs — these are low/medium **generic** findings from the distro, not real secrets. Suppress them with an allowlist in `.prowl.yaml`:

```yaml
allowlist:
  paths:
    - etc/ssl/          # distro cert bundles
    - openssl.cnf       # stock OpenSSL config
```

(`allowlist.paths` is a substring match on the finding's path; image findings are pathed `layer<i>:<file>`.) Disabling `generic_password` / `generic_api_key` under `detectors.disable` removes the whole class if you don't need it — see [Configuration](Configuration.md). Note `--rule-severity` only filters imported `--rules-dir` **templates**, not these built-in generic detectors, so it won't drop them; and `--fail-on` only sets the exit code, it does not remove low/medium findings from the report. The high/critical findings (live cloud keys, private keys, tokens) are the ones worth gating on with `--fail-on`.

### "An in-repo .prowl.yaml is suppressing detections"

By design, a `.prowl.yaml` discovered inside a scanned tree is treated as untrusted: when you scan code you don't own (a fork's PR, a dependency), that config is attacker-controlled, so a config that disables detectors or adds allowlist rules prints the warning above instead of silently blinding the scan. To vouch for a config explicitly and silence the warning, pass it yourself:

```sh
prowl scan . --config ./.prowl.yaml
```

An explicit `--config` is trusted; an auto-discovered one is not. See [Security Model](Security-Model.md).

### "Large files are skipped"

Files larger than `--max-size` bytes are not read (default 10485760 = 10 MiB). Raise it for big bundles or minified assets:

```sh
prowl scan . --max-size 52428800     # 50 MiB
```

The same limit applies to git blob and staged-file modes. A `.prowl.yaml` `performance.max_size` sets the default.

### "Color shows up (or is garbled) in CI logs"

Prowl colorizes only when stdout is a TTY, so most CI runners get plain output automatically. If your runner reports a pseudo-TTY, force plain output:

```sh
NO_COLOR=1 prowl scan .
# or
prowl scan . --no-color
```

`NO_COLOR` (any value) and `--no-color` both disable ANSI styling, for the report and the logs. For fully structured CI logs use `--log-format json`; for exit-code-only mode use `-s`/`--silence`.

### "Some rules were skipped"

`doctor`'s `regex RE2 compatibility` check warns when an imported rule's regex is not RE2-compatible (e.g. a gitleaks `.toml` using backreferences). Those rules are dropped and the rest load normally. Run `prowl rules validate <dir>` to see which templates fail and why.

## See also

- [Configuration](Configuration.md)
- [Live Verification](Live-Verification.md)
- [Rules](Rules.md)
- [Security Model](Security-Model.md)
- [Home](README.md)
