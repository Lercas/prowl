# Rules

Prowl detection rules are nuclei-style YAML templates: one file per provider, an `info` block, `matchers` combined with AND/OR, and `extractors` that pull the secret out of the match. Templates live **outside the binary** in `~/.prowl/rules` and are installed from [github.com/Lercas/prowl-templates](https://github.com/Lercas/prowl-templates) via `prowl rules update`. The default library ships ~159 templates across cloud, payment, messaging, AI, VCS, SaaS, DB, observability, auth, and CI categories.

```sh
prowl rules update                 # install/refresh the template library into ~/.prowl/rules
prowl rules list                   # every rule, grouped by category, with severity + tags
prowl rules show stripe-secret-key # one rule's matchers, regex, severity, reference
prowl rules search aws             # find rules (built-in + template) by id / tag / name / description
prowl rules test 'key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"'  # which rules fire on a sample
prowl rules validate rules/        # lint templates (parse / RE2 / fields)
prowl rules stats rules/           # counts by category / severity / tag
```

Templates supplement the built-in detector taxonomy. They run during a scan only when you point at a directory with `--rules-dir`, or automatically when installed in `~/.prowl/rules`. See [Scanning Files](Scanning-Files.md) for how rules feed the scan and [Architecture](Architecture.md) for the pipeline.

## prowl rules workflow

`prowl rules <subcommand>`. Most subcommands take an optional `DIR` positional that defaults to `./rules`; `show`, `test`, and `search` read the working-directory `rules/` if present, otherwise the installed `~/.prowl/rules` — and additionally consult the **built-in detector taxonomy** compiled into the binary, so a built-in like `aws_access_key_id` or `stripe_secret_key` is reachable without any installed templates.

| Subcommand | Synopsis | What it does |
|---|---|---|
| `list` | `list [DIR] [--tags T] [--rule-severity S]` | Rules grouped by category, severity-coloured, with tags |
| `show` | `show <rule-id>` | One rule's full detail — works for **built-in detector ids** and templates |
| `test` | `test <text\|@file>` | Reports which rules fire — **built-ins + templates** — on a sample; near-miss hints on no match |
| `search` | `search <term>` | Find rules by id / tag / name / description across **built-ins + templates** |
| `validate` | `validate [DIR]` | Lints templates; exit 1 on any error |
| `stats` | `stats [DIR]` | Breakdown by category, severity, and the top tags |
| `update` | `update [--source SRC] [--check]` | Install/refresh templates into `~/.prowl/rules` |
| `export` | `export -o FILE` | Write the built-in detector taxonomy to an editable file |

### list

Groups templates by category (largest first), sorts each group by descending severity, and prints `severity  rule-id  tags`. A trailing count goes to stderr.

```sh
prowl rules list rules/
prowl rules list --tags ai            # only templates tagged "ai"
prowl rules list --rule-severity critical,high
```

```
  cloud (25)
    critical  aws-secret-access-key               aws, cloud, credentials
    high      aws-access-key-id                   aws, cloud, credentials
    ...
  payment (25)
    critical  stripe-secret-key                   stripe, payment, credentials
    ...

159 templates in 10 categories
```

`--tags` keeps templates carrying **any** of the listed tags; `--rule-severity` keeps **only** the listed severities. Both take comma-separated values.

### show

Looks the id up in the template library first; if no template matches, it falls back to the **built-in detector taxonomy**, so a cascade detector id (not just a template) resolves. Each block tags its `source:` as `template` or `built-in`.

```sh
prowl rules show stripe-secret-key
```

```
  critical  stripe-secret-key  payment
  source: template
  Stripe Live Secret Key
  Stripe live mode secret API key (sk_live_) granting full account access.
  tags: stripe, payment, credentials
  ref:  https://docs.stripe.com/keys
  match (and):
    word     sk_live_
    regex    \bsk_live_[0-9a-zA-Z]{24,}\b
    entropy  >= 3.5
```

For a built-in id, `show` prints the detector's regex, its category→severity mapping, and any checksum / entropy / charset gate:

```sh
prowl rules show aws_access_key_id
```

```
  high  aws_access_key_id  cloud
  source: built-in
  AWS Access Key ID
  category cloud → severity high
  match:
    regex    \b((?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16})\b
    charset  base32
```

Exits 2 if the id is neither a template nor a built-in.

### test

Runs the sample through **both** detection paths — the built-in cascade detector (the same engine `prowl scan` uses) *and* every loaded template — and reports the rules that fire, with the matched value redacted. Each hit is tagged `built-in` or `template`. This is the inner loop when authoring a rule.

The argument is a literal string, `@FILE` to test a real sample file, or `-` to read stdin:

```sh
prowl rules test 'key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"'   # literal string
prowl rules test @sample.env                                  # a real file's contents
```

```
  ✓  built-in  critical  stripe_secret_key  matched sk_l********p7dc
  ✓  template  critical  stripe-secret-key  matched sk_l********p7dc

2 match(es) (31 built-in detectors, 159 templates)
```

On **no match**, instead of a bare "no rule matched" it prints near-miss hints for the template(s) closest to firing — how far each got (anchor word present? regex matched? a later entropy/group gate rejected it?) — so you can see *why* a rule did not fire:

```sh
prowl rules test 'export AWS_KEY=AKIA_not_valid'
```

```
  no rule matched
  closest: aws-access-key-id (anchor present, regex did not match)
  closest: airtable-personal-access-token (anchor present, regex did not match)
  closest: aws-secret-access-key (anchor present, regex did not match)
0 matches (31 built-in detectors, 159 templates)
```

Exit 0 when at least one rule matched, 1 when none did (2 on an unreadable `@FILE`).

### search

Finds rules whose id, tags, name, or description contain `<term>` (case-insensitive), across **both** the built-in detector taxonomy and the external templates. Results are grouped by category like `rules list`, and each row is tagged `[built-in]` or `[template]` so you can tell the two libraries apart.

```sh
prowl rules search aws
```

```
  cloud (6)
    critical  aws-secret-access-key  [template]  aws, cloud, credentials
    high      aws-access-key-id      [template]  aws, cloud, credentials
    high      aws-mws-auth-token     [template]  aws, amazon, cloud, credentials
    high      aws-session-token      [template]  aws, cloud, credentials
    high      aws_access_key_id      [built-in]
    high      aws_secret_access_key  [built-in]

6 rule(s) match "aws" in 1 categories
```

Exit 0 when at least one rule matched, 1 when none did. Use `search` to discover an id, then `show` it for the full matcher detail.

### validate

Parses every template and checks RE2 compilation, required fields, and pre-filter soundness. Errors (bad regex, missing id, no matchers) fail with exit 1; warnings (e.g. an anchor word that never appears in any regex, so the keyword pre-filter could hide a match) are reported but do not fail.

```sh
prowl rules validate rules/
```

```
  WARN  rules/vcs/github-oauth-client-secret.yaml (github-oauth-client-secret): anchor word "client_secret" not found in any regex — pre-filter may hide matches

159 templates, 0 error(s), 35 warning(s)
```

### stats

```sh
prowl rules stats rules/
```

```
159 templates
  category  cloud 25 · payment 25 · messaging 24 · ai 22 · vcs 18 · saas 15 · db 14 · observability 11 · auth 3 · ci 2
  severity  high 121 · critical 29 · medium 7 · low 2
  top tags  credentials 159 · token 62 · cloud 25 · messaging 25 · payment 25 · ai 22 · ...
```

### update

Fetches templates from the canonical repo (`https://github.com/Lercas/prowl-templates.git`, its `rules/` subdir), validates them, and installs into `~/.prowl/rules`. With `--source` you can point at a different git URL or a local directory. If the default repo is unreachable, Prowl falls back to the snapshot bundled alongside the binary.

```sh
prowl rules update                       # from the canonical templates repo
prowl rules update --check               # show what would change, install nothing
prowl rules update --source ./my-rules   # install from a local dir
prowl rules update --source https://github.com/you/your-templates.git
```

Output reports the delta and the resulting manifest version:

```
rules installed: +12 ~3 -0 (version 1.0.0, 159 total) -> /Users/you/.prowl/rules
```

`prowl version` prints the installed rule count, manifest version, and install path.

### export

Writes the **built-in detector taxonomy** (not the templates) to a YAML file you can edit and feed back with `--taxonomy`. This is separate from the template system.

```sh
prowl rules export -o taxonomy.yaml
```

## Template schema

Authoritative schema (from `internal/rules/template.go` and `rules/SCHEMA.md`). One YAML file is one rule, or several rules separated by `---`. Drop files under `rules/<category>/`.

| Field | Required | Type | Notes |
|---|---|---|---|
| `id` | yes | string | kebab-case, globally unique |
| `info.name` | yes | string | human-readable name |
| `info.author` | no | string | e.g. `prowl` |
| `info.severity` | yes | string | `info` \| `low` \| `medium` \| `high` \| `critical` |
| `info.description` | no | string | one sentence on what it detects |
| `info.reference` | no | list | URLs documenting the format |
| `info.tags` | yes | string | comma-separated, lowercase (nuclei convention) |
| `category` | no | string | Prowl category override: `cloud` `vcs` `ai` `payment` `db` `messaging` `comms` `ci` `saas` `pki` `auth` `generic` |
| `matchers-condition` | no | string | `and` (default) \| `or` — combines the matcher list |
| `matchers` | yes | list | at least one matcher |
| `extractors` | no | list | what to report; defaults to the regex matchers |

### matchers

Each matcher has a `type`. An empty/omitted `type` defaults to `regex`. The top-level `matchers-condition` combines matchers (nuclei default is **AND**); the per-matcher `condition` combines the words/regexes **within** one matcher (default `or`).

| Matcher field | Applies to | Meaning |
|---|---|---|
| `type` | all | `word` \| `regex` \| `entropy` |
| `words` | word | substrings, matched case-insensitively |
| `regex` | regex | RE2 patterns (list) |
| `condition` | word, regex | `and` \| `or` over this matcher's items (default `or`) |
| `min` | entropy | Shannon-entropy floor the extracted value must meet |
| `negative` | all | invert: the matcher passes when it does **not** match |

- **word** — cheap pre-filter. Its words become Aho-Corasick anchors so the template is skipped on files that lack them. Always include one with the rule's anchor token (`sk_live_`, `AKIA`, `ghp_`, `xoxb-`).
- **regex** — **RE2 only**: no backreferences, no lookahead/behind. `(?:...)`, `[A-Z0-9]`, `\b`, bounded `{24,48}` are fine; `(?=...)`, `(?<=...)`, `\1` are not.
- **entropy** — gates by the extracted value's Shannon entropy (`min: 3.0`–`3.5` cuts placeholders).

### extractors

Pull the secret value out of the matched text. If you omit `extractors`, Prowl reports the spans of the regex matchers.

| Extractor field | Meaning |
|---|---|
| `type` | `regex` |
| `regex` | RE2 patterns (list) |
| `group` | capture group to report. **Unset → group 1**; explicit `group: 0` → the whole match |

The `group` applies per-regex and falls back to the whole match when a regex has fewer groups, so an extractor may mix a captured-group regex with a bare-token one. Validation rejects a group only when it exceeds the capture count of **every** regex.

### Example

A real template from the default library (`rules/payment/stripe-secret-key.yaml`):

```yaml
id: stripe-secret-key
info:
  name: Stripe Live Secret Key
  author: prowl
  severity: critical
  description: Stripe live mode secret API key (sk_live_) granting full account access.
  reference:
    - https://docs.stripe.com/keys
  tags: stripe,payment,credentials
category: payment
matchers-condition: and
matchers:
  - type: word
    words:
      - sk_live_
    condition: or
  - type: regex
    regex:
      - '\bsk_live_[0-9a-zA-Z]{24,}\b'
  - type: entropy
    min: 3.5
extractors:
  - type: regex
    regex:
      - '\bsk_live_[0-9a-zA-Z]{24,}\b'
```

A context-anchored rule using a capture group:

```yaml
id: generic-bearer-token
info:
  name: Bearer Token in Authorization Header
  author: prowl
  severity: medium
  description: A bearer token assigned in an Authorization header or config.
  tags: generic,auth,token
category: auth
matchers-condition: and
matchers:
  - type: word
    words: [bearer, authorization]
    condition: or
  - type: regex
    regex:
      - '(?i)bearer\s+([A-Za-z0-9._\-]{20,})'
  - type: entropy
    min: 3.5
extractors:
  - type: regex
    regex:
      - '(?i)bearer\s+([A-Za-z0-9._\-]{20,})'
    group: 1
```

### Authoring guidelines

- Always include a `word` matcher with the anchor token — it is the speed pre-filter; without it the regex runs on every file.
- Use `matchers-condition: and` so a hit needs the anchor word **and** the regex (precision).
- Add an `entropy` matcher (`min: 3.0`–`3.5`) for high-entropy tokens to drop placeholders.
- Prefer specific prefixes and bounded lengths over generic `[A-Za-z0-9]+`.
- One provider concept per file, named `rules/<category>/<provider>-<thing>.yaml`.

Safety limits guard untrusted templates: 512 KiB per document, 4 KiB per regex source, and a maximum `{n}`/`{n,m}` repetition bound of 100000.

## Filtering rules

Both `prowl rules list` and `prowl scan` filter the active template set by tag and severity. The scan path additionally supports excluding tags.

| Flag | Where | Effect |
|---|---|---|
| `--tags T1,T2` | `rules list`, `scan` | keep templates with **any** of these tags |
| `--exclude-tags T1,T2` | `scan` | drop templates with **any** of these tags |
| `--rule-severity S1,S2` | `rules list`, `scan` | keep **only** templates of these severities |

```sh
prowl scan src --rules-dir rules/ --tags aws            # AWS rules only
prowl scan src --rules-dir rules/ --exclude-tags test   # skip test-key rules
prowl scan src --rules-dir rules/ --rule-severity critical,high
```

## Importing gitleaks and trufflehog rulesets

Existing gitleaks `.toml` and trufflehog `.yaml` rulesets import **unchanged** — no rewriting required. They load into the detector taxonomy (alongside the built-in types), not the template engine.

| Flag | Effect |
|---|---|
| `--rules FILE` | (repeatable) import an external ruleset — gitleaks `.toml`, trufflehog `.yaml`, or prowl yaml. Format is auto-detected; any embedded allowlist is merged in |
| `--rules-only` | use **only** the `--rules` files, dropping the built-in taxonomy — a pure gitleaks/trufflehog drop-in |
| `--rules-dir DIR` | (repeatable) load nuclei-style **templates** from a directory |

```sh
prowl scan . --rules gitleaks.toml                  # built-ins + gitleaks rules
prowl scan . --rules trufflehog.yaml --rules-only   # trufflehog rules alone
prowl scan . --rules-dir rules/ --tags aws          # extra templates, AWS only
```

`prowl rules list` labels each active rule by provenance (built-in / gitleaks / trufflehog / template).

## Authoring loop

```
write rules/<category>/<provider>-<thing>.yaml
  → prowl rules test @sample.env           # does it fire? right value extracted? (near-miss hints if not)
  → prowl rules validate rules/            # RE2, fields, pre-filter soundness
  → prowl rules update --source ./rules    # install into ~/.prowl/rules
```

Iterate `test` against a real sample file until the rule fires and stays quiet on placeholders (entropy floor) — the near-miss hints tell you whether the anchor word, regex, or an entropy gate is blocking it. Then `validate` to catch RE2/field mistakes, then `update` to install. Contribute finished rules back to [prowl-templates](https://github.com/Lercas/prowl-templates).

## See also

- [Scanning Files](Scanning-Files.md)
- [Configuration](Configuration.md)
- [Verifiers](Verifiers.md)
- [Live Verification](Live-Verification.md)
- [Architecture](Architecture.md)
- [Home](README.md)
