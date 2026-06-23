# AI prompt: generate a Prowl VALIDATION rule (live-credential verifier)

Paste the block below into any capable LLM and replace `{{PROVIDER}}`. The output is one ready-to-drop
`verifiers/<provider>.yaml` that passes `prowl verifiers validate`, or an explicit `SKIP:` line.

---

You are a live-credential verifier author for the **Prowl** scanner. A verifier confirms a detected
secret is **live** by calling the provider's own **read-only** identity/validate endpoint. Produce
**one** data-driven verifier in YAML for: **{{PROVIDER}}**.

## Output schema (emit ONLY YAML, no prose)

```yaml
id: provider                          # REQUIRED, unique
info:
  name: Provider Name
  author: prowl
  reference: https://provider.example/docs/identity-endpoint   # the REAL endpoint's docs
match: [provider, tok_prefix]         # REQUIRED: detector/rule type ids OR secret-value prefixes
requests:                             # REQUIRED: live if ANY request's matchers pass
  - method: GET                       # GET (default) | POST
    url: https://api.provider.example/v1/me
    headers:
      Authorization: "Bearer {{secret}}"   # interpolation, see below
    body: ""
    matchers-condition: and
    matchers:
      - type: status                  # status | word | regex
        status: [200]
```

### Interpolation tokens
- `{{secret}}`: the detected value.
- `{{base64(EXPR)}}`: base64 of `EXPR` with `secret` substituted; e.g. `{{base64(secret:)}}` for HTTP
  Basic with the key as the username, `{{base64(api:secret)}}` for `api:<key>`.
- `{{name}}`: a value pulled from context by an `extract:` entry (see signing).

### Matchers
`status` (code in list) · `word` (substring in `part: body`|`header`) · `regex` (RE2 on body/header).
`matchers-condition: and` (default) needs all; `or` needs one; `negative: true` inverts.
**Use a `word` matcher, not `status`, for APIs that return HTTP 200 with an error body** (e.g.
`words: ['"ok":true']`).

### Signed requests (AWS SigV4 and compatible, incl. Yandex Object Storage)
For providers that require AWS Signature V4, pull the key pair from the finding's context and sign:

```yaml
match: [aws, akia]
extract:
  aws_access_key_id: '(?:AKIA|ASIA)[0-9A-Z]{16}'
  aws_secret_access_key: '[A-Za-z0-9/+]{40}'
sign: awsv4
sign_params: { service: sts, region: us-east-1 }   # service: s3 for object storage
requests:
  - method: POST
    url: https://sts.amazonaws.com/
    headers: { Content-Type: "application/x-www-form-urlencoded; charset=utf-8" }
    body: "Action=GetCallerIdentity&Version=2011-06-15"
    matchers: [{ type: status, status: [200] }]
```

## Hard rules
1. **Use ONLY a real, documented, read-only identity/validate endpoint** (e.g. "get current
   user/account", "validate token"). **Never invent an endpoint or auth header.** No mutating calls.
2. **If the provider can't be verified, output exactly one line:** `SKIP: <reason>`, and stop.
   Skip when it needs: request signing other than `awsv4` (GCP/Azure JWT), an account
   subdomain/tenant/region in the URL you can't derive, a key **pair** where only one half is the
   secret, or an OAuth token-exchange step.
3. **Correct auth scheme** per provider: `Bearer`, raw token, `Token token=…`, `PRIVATE-TOKEN`,
   `X-…-Token`, Basic via `{{base64(...)}}`, or token-in-URL-path (e.g. Telegram).
4. **RE2 only** for any `regex`/`extract` pattern (no lookaround/backreferences).
5. `match:` must list the provider's detector type-id substrings **and** its value prefixes so it
   routes even when the cascade labeled the finding generic.

## Before you answer: self-check
- The endpoint and auth header are real and read-only (cite the docs URL in `info.reference`).
- For a 200-with-error-body API you used a `word` matcher, not bare `status`.
- Any regex compiles under RE2.
- If signing/subdomain/pair/OAuth is required and unavailable, you returned `SKIP:` instead of a guess.

Output the YAML (or the `SKIP:` line) only.
