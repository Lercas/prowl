# Verifier schema: pluggable live-credential checks (data-driven, like rules)

A verifier is a YAML file describing HOW to confirm a secret is live: an HTTP request (with the
secret interpolated) plus conditional matchers on the response. AppSec teams author these and drop
them in a directory, with **no recompile and nothing hard-coded**. Run with `prowl scan . --verify`
(loads `./verifiers` by default, or `--verifiers DIR`).

```yaml
id: github                              # REQUIRED, unique
info:
  name: GitHub
  author: appsec
  reference: https://docs.github.com/en/rest/users/users
match: [github, ghp_, gho_]             # REQUIRED: detector/rule type ids OR secret-value prefixes
                                        #   this verifier applies to (substring, case-insensitive)
requests:                               # REQUIRED: probe(s); the secret is LIVE if ANY request matches
  - method: GET                         # GET (default) | POST | …
    url: https://api.github.com/user
    headers:
      Authorization: "token {{secret}}" # interpolation: {{secret}} | {{base64(EXPR)}}
    body: ""
    matchers-condition: and             # and (default) | or
    matchers:
      - type: status                    # status | word | regex
        status: [200]
      - type: word                      # optional extra conditions
        part: body                      # body (default) | header
        words: ['"login"']
        condition: or                   # or (default) | and  (combines words/regex)
        negative: false
```

## Interpolation

| token | expands to |
|-------|-----------|
| `{{secret}}` | the raw detected value |
| `{{base64(EXPR)}}` | base64 of `EXPR` with the literal `secret` replaced by the value |

`{{base64(secret:)}}` → HTTP Basic with the key as the username (Stripe). `{{base64(api:secret)}}`
→ Basic `api:<key>` (Mailgun).

## Matching

- `status`: response code is in the list.
- `word`: substring present in `body` (default) or `header`.
- `regex`: RE2 pattern matches `body`/`header`.

`matchers-condition: and` (default) needs every matcher; `or` needs one. `negative: true` inverts a
matcher. A request with **no matchers** treats any `2xx` as live. If every request errors (network),
the result is *inconclusive* (the finding is kept, marked unverified); only an explicit provider
rejection marks it `verified: false`.

## Safety

Verification is **opt-in** (`--verify`), uses read-only identity/validate endpoints (no mutations),
**skips example/placeholder values**, caches by value (each secret is checked once), and never logs
the secret. `--verified-only` reports just provider-confirmed-live secrets, the strongest
false-positive filter.

## Lifecycle

```sh
prowl verifiers list [DIR]       # which providers, type ids, and endpoints are loaded
prowl verifiers validate [DIR]   # parse + regex compile check; exit 1 on error
```
