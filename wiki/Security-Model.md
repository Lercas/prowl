# Security Model

A secret scanner runs against attacker-influenced input: code you don't own, configs shipped inside a repo, URLs in a verifier template, third-party assets fetched by `prowl domain`. That makes the scanner itself a potential attack surface. This page describes what Prowl does to avoid becoming one — its SSRF guard, its config trust boundary, its secret handling, the supply-chain hardening of `rules update`, and the authorized-use gate on `prowl domain`.

## SSRF guard (the dial control)

Live verification (`--verify`) and `prowl domain` make outbound HTTP requests to URLs that an attacker can influence — a verifier template's endpoint, a `<script src>` on a scanned page. Left open, that is a server-side request forgery primitive: a crafted target could make the scanner probe internal services (cloud metadata at `169.254.169.254`, `localhost` admin panels, RFC1918 hosts).

Prowl blocks this at the socket. The HTTP client installs a `net.Dialer` control hook that fires **after DNS resolution, with the concrete IP the socket is about to connect to**, and refuses the connection when the target is internal. Because it vets the resolved IP rather than the hostname, it defeats DNS rebinding (a name that resolves public, then internal). The guard rejects:

- loopback (`127.0.0.0/8`, `::1`),
- link-local, including the cloud-metadata address `169.254.169.254` (and link-local multicast),
- private RFC1918 ranges and IPv6 ULA (`fc00::/7`),
- the unspecified address and the `0.0.0.0/8` "this host" range,
- multicast,

and it applies the same block to the IPv4-mapped form of those addresses. A blocked attempt surfaces as the safe category `blocked address`, never an error string that could leak the target.

The same client also **refuses cross-host redirects**: a redirect that changes scheme, host, or port would re-send the request — including any custom secret-bearing header like `X-Api-Key` — to an origin the operator never targeted, so the host change is rejected outright (Go strips `Authorization`/`Cookie` on cross-host hops, but not arbitrary custom headers). Redirect depth is capped.

The guard is on by default. Operators who run verifiers against an internal or self-hosted endpoint opt out for the whole process:

```sh
PROWL_ALLOW_PRIVATE_IPS=1 prowl scan . --verify
```

Set it only when the verifier endpoints are trusted. See [Live Verification](Live-Verification.md).

## The .prowl.yaml trust boundary

A `.prowl.yaml` at a repo root configures Prowl — it can disable detectors and extend the allowlist. That is exactly the power an attacker wants when you scan code you don't own: a config committed to a fork's PR or a dependency could ship a kill switch that silently blinds the scan.

Prowl treats config provenance as a trust boundary:

- A config **auto-discovered inside the scanned tree is untrusted.** If it disables detectors or adds allowlist rules, Prowl prints a warning rather than applying it silently:

  ```console
  WARN in-repo .prowl.yaml suppresses detection — review if scanning untrusted code path=.prowl.yaml disabled_detectors=1 allowlist_rules=3
  ```

- A config you pass **explicitly with `--config FILE` is trusted** — you vouch for it, and no warning is printed.

This keeps a malicious in-repo config from quietly suppressing detection while still letting your own project config work without friction. See [Configuration](Configuration.md) and [Doctor and Troubleshooting](Doctor-and-Troubleshooting.md).

## Scanning remote sources safely

`prowl repo`, `prowl org`, `prowl image`, and `prowl bucket` point the scanner at input it fetches from elsewhere — a clone URL, a platform's repo list, a registry image, a cloud-storage prefix. Each fetch is hardened so the act of scanning an untrusted source can't be turned against the operator.

- **Clone transport hardening (`repo`/`org`).** Cloning applies the **same transport hardening as `rules update`**. The URL must use an explicit, non-RCE transport — `https://`, `http://`, `ssh://`, `git://`, or scp-like `git@host:path` — and a bare `.git` suffix is deliberately not enough, because that would let git's remote-ext helper (`ext::sh -c …`) through and execute arbitrary commands. Clones run with `-c protocol.ext.allow=never` (and a restricted `protocol.file.allow=user`), disabling the `ext:`/`file:` remote helpers, and a `--` separator terminates option parsing so a hostile URL can't pose as a flag. The net effect: a malicious clone URL cannot run commands. Private repos authenticate through your **existing git credentials** (ssh keys, the credential helper) or a token you embed in the URL — Prowl never places credentials on its own command line.

- **A scanned repo cannot suppress its own findings (`repo`/`org`).** A clone is an untrusted tree, so `repo`/`org` run with `noAutoConfig`: they **do not auto-discover the scanned repo's `.prowl.yaml`** at all. Where a plain `scan .` would discover an in-repo config and warn about it (see the trust boundary above), `repo`/`org` skip discovery entirely, so a remote repo can't ship a kill switch that disables detectors or extends the allowlist to blind its own scan. Only a config you pass **explicitly with `--config FILE` is trusted** here.

- **Platform tokens come from the environment, never argv (`org`).** Listing an org/group/workspace reads its API token from the environment — `GITHUB_TOKEN`, `GITLAB_TOKEN`, or `BITBUCKET_TOKEN` (with `GITHUB_API`/`GITLAB_API` to override the API host) — and sends it only as a request `Authorization`/`PRIVATE-TOKEN` header. The token is never passed on the command line and is never logged.

- **Image pulls use the Docker keychain, in memory (`image`).** `image` pulls through the default Docker keychain (`~/.docker/config.json`) — public images need no credentials, private registries authenticate via your existing Docker login — so registry credentials never appear on the command line. Nothing is written to disk: layers and the image config are **streamed and scanned in memory**.

- **Bucket downloads use your cloud CLI's configured credentials (`bucket`).** `bucket` shells out to the operator's own `aws` (`s3://`) or `gcloud` (`gs://`) CLI to sync the prefix into a temp dir, so it reuses your **configured cloud credentials, region, and role** — no credentials are ever placed on prowl's command line. The downloaded prefix is untrusted, so `bucket` runs with `noAutoConfig`: a `.prowl.yaml` inside the download is **not auto-discovered** and cannot disable detectors or extend the allowlist to suppress findings in its own contents. Only an explicit `--config FILE` is trusted. The temp dir is removed after the scan.

See [Repository Scanning](Repository-Scanning.md), [Org Scanning](Org-Scanning.md), [Container Scanning](Container-Scanning.md), and [Cloud Storage Scanning](Bucket-Scanning.md).

## Secret handling

The raw secret has the shortest possible lifetime and never egresses to a log or a model.

- **Redaction everywhere.** Every report — pretty, JSON, SARIF — carries only the masked value (first 4 + last 4 characters; short values are fully starred). The raw secret is used in-process only to compute entropy/checksums, the stable fingerprint, and an optional live check, then the finding stores the redacted form.
- **Fingerprints don't leak the value.** The `fingerprint` is a sha256 over `type | path | raw-value`. It is a one-way identity for [baselining](Configuration.md); the value cannot be recovered from it, and distinct secrets never collide.
- **Verification never egresses the raw secret to a log or LLM.** Verification is opt-in, and the code path never logs the secret. Critically, it never surfaces a transport error's text: a `*url.Error` embeds the full request URL, which carries the interpolated secret, so on failure Prowl reports only a **fixed, secret-free category** — `timeout`, `blocked address`, `connection refused`, `TLS error`, `DNS error`, `cross-host redirect blocked`, and so on — derived by inspecting error *values* (`errors.As`), never error strings.
- **Request-smuggling defense.** Before a secret is interpolated into a verifier URL or header, Prowl rejects control characters (CR/LF/NUL/DEL) and re-parses the URL, so a value containing newlines can't split the request line or inject extra headers.

## rules update supply-chain hardening

`prowl rules update` fetches rule templates from a local directory or a git URL and installs them under `~/.prowl/rules` (verifier templates are installed separately by `prowl verifiers update`). Since the source can be remote, the fetch and install paths are hardened against turning a template feed into code execution or a path-traversal write:

- **Scheme allow-list.** Only `https://`, `http://`, `git://`, `ssh://`, and scp-like `git@host:path` URLs are accepted as git sources. A bare `.git` suffix is deliberately **not** enough — that would let git's remote-ext helper (`ext::sh -c …`) through and execute arbitrary commands.
- **No ext/file transport.** Clones run with `-c protocol.ext.allow=never` (and a restricted `protocol.file.allow`), disabling the transport helpers that turn a clone URL into command execution. `--` terminates option parsing so a hostile URL can't pose as a flag.
- **Validate before install.** A fetched set is validated first; an update that contains rule errors is refused, so a broken or malicious template set never replaces a working one.
- **Symlink and path-traversal refusal.** Installing a tree from an untrusted source **refuses any symlink** in the source, and refuses any entry whose resolved path escapes the target directory. Files are written with `O_NOFOLLOW`, so a symlink planted at the destination by an earlier attack fails the write instead of being followed through.

## Authorized-use gate on prowl domain

`prowl domain` fetches a live site's published pages, inline state blobs, JavaScript bundles, and source maps. Scanning a domain you don't control can be unauthorized activity, so the command **requires an explicit `--authorized` acknowledgment** and refuses to run without it:

```console
$ prowl domain https://example.com
refusing: pass --authorized to confirm you are authorized to scan https://example.com (the scan fetches the domain's published pages/JS).
```

```sh
prowl domain https://example.com --authorized
```

Deep reconnaissance (subdomain enumeration via crt.sh, wayback history) is a separate opt-in (`--recon`) and is off by default — the base scan stays focused on the host itself. All of these fetches go through the SSRF-guarded client described above.

## See also

- [Live Verification](Live-Verification.md)
- [Configuration](Configuration.md)
- [Doctor and Troubleshooting](Doctor-and-Troubleshooting.md)
- [Rules](Rules.md)
- [Repository Scanning](Repository-Scanning.md)
- [Org Scanning](Org-Scanning.md)
- [Container Scanning](Container-Scanning.md)
- [Cloud Storage Scanning](Bucket-Scanning.md)
- [Architecture](Architecture.md)
- [Home](README.md)
