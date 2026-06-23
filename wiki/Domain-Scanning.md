# Domain Scanning

`prowl domain <host>` scans a live site for exposed secrets: it fetches the host's own HTML, extracts inline SSR/hydration state blobs, and pulls the JavaScript bundles and source-maps the page references — then runs the full detector over everything. It does **not** enumerate subdomains unless you ask for it with `--recon`.

```bash
# Scan a site you own or are authorized to test
prowl domain example.com --authorized

# Deep sweep: add subdomain enumeration (crt.sh) + Wayback history
prowl domain example.com --authorized --recon --format json

# Cap the number of fetched assets
prowl domain example.com --authorized --max-assets 100
```

This is for **authorized use only**. The scan makes real outbound requests to the target's published pages and assets. Run it against your own properties, or with explicit written authorization (a bug-bounty scope, a pentest engagement). `--authorized` is a hard consent gate — see below.

## `--authorized` is required

Without `--authorized`, prowl refuses to run and exits non-zero:

```text
refusing: pass --authorized to confirm you are authorized to scan example.com
(the scan fetches the domain's published pages/JS).
```

There is no config or environment override. You must pass the flag on every invocation. It is an explicit attestation that you are permitted to fetch the target.

## What it extracts by default

A default scan (no `--recon`) is focused on the host itself. For the apex and `www` host (https first, http fallback) prowl fetches and scans:

- **The HTML** of the landing page(s).
- **Inline state / config blobs** embedded in the page. These are SSR/hydration payloads that routinely leak API keys, tokens, and runtime config. prowl recognizes:
  - `__NEXT_DATA__`, `__NUXT_DATA__`, `window.__NUXT__` (Next.js / Nuxt)
  - `window.__INITIAL_STATE__`, `window.__PRELOADED_STATE__` (Redux-style)
  - `window.__APOLLO_STATE__` (Apollo)
  - `window.__remixContext`, `__sveltekit_*`, `window.___gatsby`
  - `window.env` family: `__ENV__`, `__RUNTIME_CONFIG__`, `runtimeConfig`, `ENV`, `env`, `CONFIG`, `_config`, `appConfig`
  - `<script type="application/json">` JSON islands, suspicious inline scripts (those mentioning `key`/`token`/`secret`/`config`/`apikey`/`env`), and `<meta>` token values
  - Blob contents are HTML-entity-decoded and JS-unescaped (`\/`, `\"`, `\uXXXX`) before scanning, so a key whose `/` appears as `\/` inside `__NEXT_DATA__` is still matched.
- **Referenced JavaScript and source-maps.** prowl resolves `src`/`href` references to `.js`, `.json`, `.map`, `.env`, `.cfg`, `.config` assets on the same registrable host, then fetches them. For every `*.js` it also probes the adjacent `*.js.map` — a classic source of leaked keys when source-maps ship to production.

Asset fetching is bounded: 4 MB per asset, a per-host circuit breaker (3 failures opens it for 30s), retries with backoff on 429/5xx, and a total asset budget (`--max-assets`).

## `--recon` (deep sweep)

`--recon` opts into a broader, slower sweep on top of the default. It adds:

- **Subdomain enumeration** via Certificate Transparency logs (`crt.sh`).
- **Historical assets** from the Wayback Machine (`web.archive.org`) — old JS, `.env`, `.json`, config files that may still expose live keys.
- **Common misconfiguration path probes** against discovered subdomains (e.g. `/.env`, `/.env.production`, `/config.json`, `/.git/config`, `/.npmrc`, `/swagger.json`, `/firebase-config.js`, `/appsettings.json`, source-map paths).

`--recon` fetches third-party and attacker-influenceable URLs (CT/Wayback results), which is exactly why the SSRF guard below is load-bearing.

## `--max-assets N`

Caps the total number of fetched assets across the whole scan (politeness + bounded work). Default `300`. Must be a positive integer. Once the budget is exhausted, discovery stops emitting new fetches.

## SSRF guard

Every outbound connection goes through a hardened HTTP client that refuses to connect to **internal address space**: loopback, link-local (incl. `169.254.169.254`), RFC 1918 private ranges, IPv6 ULA (`fc00::/7`), unspecified, and multicast. The check runs on the **resolved IP** right before connect, so it also defeats DNS rebinding (a hostname that resolves public, then internal). Redirects are capped and any cross-host redirect is refused so secret-bearing headers never leak to a third party.

To scan an **internal or self-hosted target** (a staging host on a private IP, localhost), opt out explicitly:

```bash
PROWL_ALLOW_PRIVATE_IPS=1 prowl domain internal.corp.example --authorized
```

Leave this unset in any context where the target host is untrusted.

## Output

`domain` honors the same reporting flags as [Scanning Files](Scanning-Files.md): `--format pretty|json|sarif`, `--output FILE`, `--fail-on <level>` (exit 1 if any finding meets the level), and the verification flags from [Live Verification](Live-Verification.md).

```bash
# Machine-readable, gate CI on anything high or worse
prowl domain example.com --authorized --format json --fail-on high

# Only keep secrets the provider confirms are live (see Live Verification)
prowl domain example.com --authorized --verify --verified-only
```

Findings carry the fetched URL as their path; state blobs are tagged with a `#<blob-name>` suffix (e.g. `https://example.com#__NEXT_DATA__`).

## See also

- [Live Verification](Live-Verification.md) — confirm domain findings are live credentials
- [Scanning Files](Scanning-Files.md) — the filesystem scan and shared flags
- [Rules](Rules.md) — what the detector matches
- [Security Model](Security-Model.md) — the SSRF guard and threat model in depth
- [Configuration](Configuration.md)
- [Home](README.md)
