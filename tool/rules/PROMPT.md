# AI prompt: generate a Prowl secret-DETECTION rule

Paste the block below into any capable LLM and replace `{{PROVIDER}}`. The output is one ready-to-drop
`rules/<category>/<name>.yaml` template that passes `prowl rules validate`.

---

You are a secret-detection rule author for the **Prowl** scanner. Produce **one** detection rule
template in YAML that detects credentials for: **{{PROVIDER}}**.

(If you know several distinct secret shapes for this provider, output several YAML documents separated
by a line containing only `---`.)

## Output schema (emit ONLY YAML, no prose)

```yaml
id: provider-secret-name              # REQUIRED, kebab-case, globally unique
info:
  name: Human Readable Name           # REQUIRED
  author: prowl
  severity: high                      # REQUIRED: info | low | medium | high | critical
  description: One sentence on what this detects.
  reference:
    - https://provider.example/docs    # the page documenting the token format
  tags: provider,category,credentials  # REQUIRED, comma-separated, lowercase
category: cloud                        # REQUIRED: cloud|vcs|ai|payment|db|messaging|comms|ci|saas|pki|auth|observability|generic
matchers-condition: and
matchers:
  - type: word                         # REQUIRED anchor: literal token(s) that appear in the regex
    words: [sk-, secret]
    condition: or
  - type: regex
    regex:
      - '\bsk-[A-Za-z0-9]{32,48}\b'
  - type: entropy                      # for random/high-entropy tokens
    min: 3.2
extractors:
  - type: regex
    regex:
      - '\bsk-[A-Za-z0-9]{32,48}\b'
    group: 0                           # 0 = whole match (default), 1 = capture group 1
```

## Hard rules (a violation = an unusable rule)

1. **RE2 only.** Go's `regexp` has **no backreferences** (`\1`) and **no lookahead/lookbehind**
   (`(?=)`, `(?!)`, `(?<=)`, `(?<!)`). Use `\b`, character classes, `(?:...)`, `(?i)`, and **bounded**
   quantifiers `{16,40}`. If you can't express it without lookaround, rewrite it.
2. **Always include a `word` matcher** whose literal anchor (e.g. `ghp_`, `AKIA`, `xoxb-`) appears
   **verbatim inside the regex**. It is the speed pre-filter; without it the regex runs on every file.
3. **`matchers-condition: and`** so a hit needs the anchor AND the regex (precision).
4. **Add an `entropy` matcher** (`min` 3.0 to 3.5) for random tokens; omit it only for human passwords.
5. **Bound the length and prefer a specific prefix** over generic `[A-Za-z0-9]+`.
6. **Severity by blast radius**: live cloud/db/payment/private-key → critical/high; API keys →
   high/medium; webhooks/low-impact → medium/low.
7. **Pick `category` from the allowed list above**; tags = provider + category + `credentials`/`token`.
8. **Use a capture group + `group: 1`** when the secret is embedded (e.g. the password inside a DB URI,
   or a value after `key=`).

## Before you answer: self-check
- Every regex compiles under RE2 (no lookaround/backref); quantifiers are bounded.
- The `word` anchor string occurs literally in at least one regex.
- Required fields present; `severity`/`category` from the allowed sets.
- The pattern matches a realistic sample token and rejects an obvious placeholder.

Output the YAML only.
