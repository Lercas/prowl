# Verifiers

A verifier is a YAML file that describes **how to confirm a secret is live**: an HTTP request with the secret interpolated in, plus conditional matchers on the response. Verifiers are data — AppSec teams author them and drop them in a directory, with no recompile and nothing hard-coded in Go. They power [`--verify`](Live-Verification.md).

```yaml
# verifiers/github.yaml
id: github
info:
  name: GitHub
  author: prowl
  reference: https://docs.github.com/en/rest/users/users#get-the-authenticated-user
match: [github, ghp_, gho_, ghs_, ghu_, ghr_]
requests:
  - method: GET
    url: https://api.github.com/user
    headers:
      Authorization: "token {{secret}}"
      User-Agent: prowl-verify
    matchers:
      - type: status
        status: [200]
```

A finding is verified **live** if any of the verifier's requests matches. Here, a `200` from `https://api.github.com/user` means the token is valid.

## Schema

| Field | Required | Meaning |
|-------|----------|---------|
| `id` | yes | Unique verifier id. |
| `info.name` / `info.author` / `info.reference` | no | Human metadata; `name` appears in the live rationale. |
| `match` | yes | List of detector/rule type ids **or** secret-value prefixes this verifier applies to. Matched as a case-insensitive substring against `typeID\x00value`, so a provider-prefix token (e.g. `ghp_…`) is verified even when the detector only labeled it generic. |
| `extract` | no | `name: regex` map. Each regex is run over the finding's surrounding context; the first match is bound as an interpolation variable (used for multi-part credentials, e.g. an AWS id+secret pair). |
| `sign` | no | Signer name for request signing (currently `awsv4`). |
| `sign_params` | no | Signer arguments (e.g. `region`, `service`). |
| `requests` | yes | One or more HTTP probes; the secret is live if **any** request matches. |

### Request

| Field | Default | Meaning |
|-------|---------|---------|
| `method` | `GET` | HTTP method (`GET`, `POST`, …). |
| `url` | — | Target URL; interpolated. |
| `headers` | — | Header map; values interpolated. |
| `body` | — | Request body; interpolated. |
| `matchers-condition` | `and` | How to combine this request's matchers: `and` (every matcher) or `or` (any). |
| `matchers` | — | Response checks (below). |

### Matcher

| Field | Default | Meaning |
|-------|---------|---------|
| `type` | `status` | `status` (response code in `status:` list), `word` (substring present), or `regex` (RE2 pattern matches). |
| `status` | — | List of acceptable status codes (`type: status`). |
| `words` | — | Substrings to look for (`type: word`). |
| `regex` | — | RE2 patterns (`type: regex`). |
| `part` | `body` | Where to look: `body` or `header`. |
| `condition` | `or` | Combine the `words`/`regex` list with `or` or `and`. |
| `negative` | `false` | Invert the matcher result. |

A request with **no matchers** treats any `2xx` as live. If every request errors at the transport layer, the result is **inconclusive** — the finding is kept and left unverified; only an explicit provider rejection marks it `verified: false`.

## Interpolation

Templates in `url`, `headers`, and `body` are expanded before the request is sent:

| Token | Expands to |
|-------|-----------|
| `{{secret}}` | The raw detected value. |
| `{{name}}` | An `extract`ed variable (e.g. `{{aws_access_key_id}}`). |
| `{{base64(EXPR)}}` | Base64 of `EXPR`, with each variable name (including `secret`) substituted inside `EXPR` first. |

`{{base64(EXPR)}}` is how HTTP Basic auth is expressed without hard-coding credentials:

```yaml
# Stripe: the key as the Basic username (key + empty password)
headers:
  Authorization: "Basic {{base64(secret:)}}"
```

```yaml
# Mailgun: Basic api:<key>
headers:
  Authorization: "Basic {{base64(api:secret)}}"
```

Some tokens go straight into the path:

```yaml
# Telegram bot token
url: https://api.telegram.org/bot{{secret}}/getMe
matchers:
  - type: word
    part: body
    words: ['"ok":true']
```

> A verifier that interpolates `{{secret}}` into the request **URL** (like Telegram above) is flagged by the unsigned-set exfil-guard, so it is not shipped in the published template set `prowl verifiers update` installs. Telegram still ships inside the binary's bundled set; load it with a signed verifier dir or `--allow-unsigned`.

## Signing (AWS SigV4, bearer, basic)

Bearer and Basic auth are just header interpolation — no signer needed. For schemes that interpolation can't express, set `sign:`. The only built-in signer is `awsv4` (AWS Signature Version 4):

```yaml
# verifiers/aws.yaml
id: aws
info:
  name: AWS (STS GetCallerIdentity)
  reference: https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
match: [aws, akia, asia]
extract:
  aws_access_key_id: '(?:AKIA|ASIA)[0-9A-Z]{16}'
  aws_secret_access_key: '[A-Za-z0-9/+]{40}'
sign: awsv4
sign_params:
  service: sts
  region: us-east-1
requests:
  - method: POST
    url: https://sts.amazonaws.com/
    headers:
      Content-Type: "application/x-www-form-urlencoded; charset=utf-8"
    body: "Action=GetCallerIdentity&Version=2011-06-15"
    matchers:
      - type: status
        status: [200]
```

`awsv4` pulls the access-key-id and secret-access-key from `extract`ed context (`aws_access_key_id`, `aws_secret_access_key`, optional `aws_session_token`), falling back to the detected value for the secret, and signs the request. `service` and `sign_params.region` default to `sts` / `us-east-1`. The signer set is a Go map (`signers`) — adding a new scheme is the one case that needs a code change; everything else is data.

## Managing verifiers

```sh
prowl verifiers list [DIR]       # providers, type-id matches, and endpoints loaded
prowl verifiers validate [DIR]   # parse + regex-compile check; exit 1 on error
prowl verifiers update [DIR]     # install/refresh the bundled set into ~/.prowl/verifiers
```

- **`list`** prints each verifier's id, its `match` list, and its first endpoint. With no DIR it discovers the installed set (`~/.prowl/verifiers`, then `./verifiers`).
- **`validate`** loads every YAML, compiles all matcher/extract regexes, and reports errors with file + verifier id. Exit 1 on any error — wire it into CI. One bad file never disables the rest: invalid files are collected as errors *after* the valid ones load.
- **`update`** installs the bundled verifier set (or `--source <dir|git-url>`) into the installed directory. `--check` reports whether an update is available without writing.

Verifier files are discovered recursively (`*.yaml` / `*.yml`); multiple documents per file are supported (split on `\n---`). A YAML doc missing `id`, `match`, or `requests` is silently ignored, so verifiers and rule templates can share a directory.

## Adding live verification without touching Go

To support a new provider, AppSec writes one YAML file:

1. Find the provider's read-only identity/validate endpoint (`/user`, `/account`, `whoami`, …) — never a mutating one.
2. Set `match` to the detector type id and/or the secret's value prefix.
3. Express auth with `{{secret}}` / `{{base64(...)}}` headers, or `sign: awsv4` for SigV4.
4. Add matchers that distinguish a live credential (a `200`, a `"login"` field) from a dead one.
5. `prowl verifiers validate ./verifiers`, drop it in `~/.prowl/verifiers` (or ship via `verifiers update --source`), and `--verify` picks it up.

No recompile, no Go. `prowl verifiers update` installs 78 provider verifiers (GitHub, AWS, Stripe, Slack, OpenAI, Anthropic, and more) — read any of them under `verifiers/` for a working template.

## See also

- [Live Verification](Live-Verification.md) — the `--verify` / `--verified-only` flags and output
- [Rules](Rules.md) — the detector type ids that `match` refers to
- [Security Model](Security-Model.md) — SSRF guard, redirect policy, secret-safe error reporting
- [Configuration](Configuration.md)
- [Home](README.md)
