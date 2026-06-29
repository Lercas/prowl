# Live Verification

Most scanners stop at "this looks like a secret." Live verification goes further: it calls the provider's own read-only identity endpoint and reports whether the credential is **actually live**. This is the strongest false-positive filter prowl offers — a confirmed-live secret is not a guess.

```bash
# Tag each finding live / dead by calling the provider
prowl scan . --verify

# Report ONLY provider-confirmed-live secrets (drops everything unconfirmed)
prowl scan . --verified-only

# Works the same on a domain scan
prowl domain example.com --authorized --verify

# Point at a specific verifier directory
prowl scan . --verify --verifiers ./verifiers
```

## Flags

| Flag | Effect |
|------|--------|
| `--verify` | Confirm findings are LIVE by calling the provider. Each finding is tagged live, dead, or left unverified. Nothing is dropped. |
| `--verified-only` | Report **only** provider-confirmed-live secrets. Implies `--verify`. The strongest false-positive filter. |
| `--verifiers DIR` | Verifier YAML directory (repeatable). Defaults to the installed set at `~/.prowl/verifiers`, then `./verifiers`. |

Once you have run `prowl verifiers update`, `--verify` auto-loads `~/.prowl/verifiers` — no `--verifiers` flag needed. `PROWL_HOME` overrides that directory.

### `--verify` with no verifiers is a hard error

If `--verify` (or `--verified-only`, which implies it) is on but **no verifiers can be loaded** — none installed and none in any `--verifiers DIR` — prowl **exits non-zero (exit code `2`) with an error**; it does *not* silently fall back to a plain, unverified scan:

```console
$ prowl scan . --verify
ERROR verify setup failed err=--verify needs verifiers, but none are installed — run 'prowl verifiers update' (or pass --verifiers DIR)
```

This is deliberate. A silent fall-back would leave every finding unverified, and `--verified-only` (which keeps only confirmed-live findings) would then drop **everything** — a green, empty report that looks like "no secrets" when in fact nothing was checked. Failing loudly forces you to fix the setup. Install the verifier set once:

```sh
prowl verifiers update          # fetch + install ~/.prowl/verifiers
```

or point `--verifiers DIR` at a directory that actually contains verifier YAML. The same hard error applies when the directory exists but loads to an empty set.

## How it works

For each finding, prowl selects a verifier by matching the detector type id **or** the secret value's prefix (so a `ghp_…` token is verified even if the detector only labeled it generic). It then sends the verifier's HTTP probe with the secret interpolated in, and inspects the response:

- The provider **accepts** it (e.g. `200` from `https://api.github.com/user`) → **live**.
- The provider **rejects** it (e.g. `401`) → **dead** (revoked or fake).
- The request **errors** (timeout, DNS, blocked) → **inconclusive**; the finding is kept and left unverified.
- The provider **rate-limits** the check (`429` / `503`) → **inconclusive**, never *dead*. prowl honors `Retry-After` for one bounded retry, then leaves the finding unverified rather than mislabel a throttled key as revoked. Re-run to resolve any left inconclusive.

Verifiers target read-only identity/validate endpoints only (`/user`, `/account`, `whoami`, `validate`) — never anything that mutates state. Results are cached by value, so each distinct secret is checked exactly once even if it appears many times.

## Blast radius — what the key unlocks

Confirming a secret is *live* answers "is it real?"; it does not answer "how bad is it?" A live key that unlocks a dozen Google products is a different incident from one scoped to a single read-only endpoint. With `--verify`, a verifier can go beyond live/dead and report **what the credential actually unlocks** — its blast radius.

A verifier declares one or more **capability probes**: extra read-only requests that each name a concrete capability the key grants. prowl runs them after the key is confirmed live, and folds the ones that succeed into the finding's rationale. So instead of a bare `verified live`, the rationale reads e.g.:

```text
verified live: Google API key — unlocks: Firebase Identity Toolkit, Maps Geocoding
```

This is purely additive: the probes are the same kind of read-only requests as the base verification (no state is mutated), they run through the same SSRF-guarded client, and a probe that fails or errors simply isn't listed — it never downgrades a confirmed-live finding to dead.

### The shipped `google-api-key` verifier

prowl ships a `google-api-key` verifier that demonstrates the model. A bare Google API key (`AIza…`) carries no scope in its shape, so live/dead alone is uninformative — the question is *which* Google APIs it has been left enabled for. The verifier probes a set of read-only Google endpoints — **Identity Toolkit** (Firebase auth), **Gemini** (Generative Language), and **Maps** (Geocoding) — and reports each one the key successfully reaches as an unlocked capability, turning a generic "live Google key" into an actionable blast-radius summary.

## Trust and safety model

Verification makes outbound requests carrying real secrets, so the safety properties matter:

- **Verifiers are data, authored by AppSec.** A verifier is a declarative YAML file — an HTTP request plus response matchers — not code. Your security team adds and reviews them; see [Verifiers](Verifiers.md). There is no arbitrary code execution path.
- **The secret is never logged or leaked.** prowl redacts before output, and verification runs on the raw value *before* redaction. Crucially, on a transport error prowl never surfaces the underlying error string — a `*url.Error` embeds the full request URL, which contains the interpolated secret. Instead it reports a fixed, secret-free category (`timeout`, `DNS error`, `connection refused`, `blocked address`, `TLS error`, …).
- **SSRF guard.** The verifier HTTP client refuses to connect to internal address space (loopback, link-local incl. `169.254.169.254`, RFC 1918, IPv6 ULA), checked on the resolved IP to defeat DNS rebinding. Cross-host redirects are refused so a redirect can't forward a secret-bearing header to a third party.
- **Request-smuggling defense.** Before sending, prowl rejects any interpolated value containing control characters (CR/LF/NUL) in URL or header positions and re-parses the final URL, so a crafted secret can't split the request or inject headers.
- **Example/placeholder values are skipped.** Obvious test/dummy values are never sent to a provider.

### Self-hosted / internal endpoints

To verify against an internal or self-hosted endpoint (a private GitLab, an on-prem registry), opt out of the private-IP guard explicitly:

```bash
PROWL_ALLOW_PRIVATE_IPS=1 prowl scan . --verify
```

Leave it unset when scanning untrusted code or targets.

## Example output

`pretty` output appends a tag to each verified finding — `live` (bold red) or `dead` (dimmed):

```text
  config/prod.env
    critical  aws_access_key       12       AKIA…7Q=Q   live
    high      stripe_secret_key    20       sk_li…4f2   dead
    high      github_pat           34       ghp_…a1b    live
```

The scan summary breaks out the counts:

```text
scan complete  findings=3 critical=1 high=2 ... verified_live=2 rejected=1
```

In `--format json`, findings gain `verified` (a tri-state: `true`, `false`, or absent when inconclusive/unsupported) and a `rationale`:

```json
{
  "type": "github_pat",
  "severity": "high",
  "path": "config/prod.env",
  "redacted": "ghp_…a1b",
  "verified": true,
  "rationale": "verified live via github"
}
```

A rejected credential reads `"verified": false, "rationale": "provider rejected the credential (stripe)"`; an inconclusive one omits `verified` and reads e.g. `"rationale": "verification inconclusive: timeout"`. When a verifier ran [capability probes](#blast-radius--what-the-key-unlocks), the `rationale` names what the key unlocks — e.g. `"verified live: Google API key — unlocks: Firebase Identity Toolkit, Maps Geocoding"`.

## See also

- [Verifiers](Verifiers.md) — the data-driven YAML format AppSec authors
- [Scanning Files](Scanning-Files.md) — the scan command and its flags
- [Domain Scanning](Domain-Scanning.md) — verify findings from a live site
- [Security Model](Security-Model.md) — the SSRF guard and secret-handling guarantees
- [Configuration](Configuration.md)
- [Home](README.md)
