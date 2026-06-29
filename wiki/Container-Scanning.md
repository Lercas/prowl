# Container Image Scanning

```
prowl image <ref | tarball | oci-dir | ->
```

Scan a container image for secrets — **every layer's files plus the image config**, not just the flattened final filesystem. The argument is any OCI/Docker reference **or a local image**:

```bash
prowl image alpine:latest                      # pull from a registry
prowl image ghcr.io/org/app:1.4
prowl image myregistry.io/team/api@sha256:abc…
prowl image ./app.tar                          # a local docker-save / OCI tarball
prowl image ./oci-layout-dir                   # a local OCI image-layout directory
docker save app:1.4 | prowl image -            # a tar stream on stdin
```

Remote refs are pulled with [go-containerregistry](https://github.com/google/go-containerregistry), so **no Docker daemon is required** — prowl talks to the registry directly. It works against any registry: Docker Hub, GHCR, GCR, Amazon ECR, or a self-hosted/on-prem registry. Local inputs touch no network at all.

> To scan source from a git host, see [Repository Scanning](Repository-Scanning.md); to download & scan an S3 / GCS prefix, see [Cloud Storage Scanning](Bucket-Scanning.md).

`prowl image` accepts every [`prowl scan`](Scanning-Files.md) flag — `--verify`, `--fail-on`, `--format`, `--rules-dir`, `--tags`, `--baseline`, `--max-size`, and the rest. The notes below cover only what is specific to images.

## Inputs

prowl auto-detects the input by inspecting the argument: `-` is stdin, an existing **directory** is an OCI image-layout, an existing **file** is a tarball, and anything else is a remote reference. Force the interpretation with `--image-input`:

| `--image-input` | Meaning |
|------|------|
| `auto` (default) | Detect by `stat` as described above. |
| `ref` | Always treat the argument as a remote registry reference. |
| `tar` | A local `docker save` / OCI tarball. |
| `oci-dir` | A local OCI image-layout directory. |
| `stdin` | A tar stream on stdin (the argument must be `-`). |

Local tarballs and stdin work without a registry or daemon — handy in an air-gapped CI runner that builds an image, `docker save`s it, and pipes it straight into prowl.

## Scanning multiple images

Pass several arguments to scan them in one invocation:

```bash
prowl image app:1.4 sidecar:2.0 ghcr.io/org/api:latest
```

Each image's findings are prefixed with that image's label so they never collide. The exit code is the worst across all images, and a single anti-bomb budget is shared across the batch.

## What gets scanned

Two things: the files inside **every layer**, and the **image config**. Every finding's path is prefixed with the image it came from:

```
<image>|layerN:<file>          e.g.  alpine:latest|layer3:app/.env
<image>|image:config/<field>   e.g.  alpine:latest|image:config/env
```

`N` is the layer index (`layer0`, `layer1`, …). When several images are scanned at once, the prefix is `<image>#<index>` so two images with the same ref-less name stay distinct.

### Every layer's files

prowl walks each layer's tar and scans every regular text file it contains — e.g. `layer3:app/.env` or `layer0:etc/credentials.json`. Binary files, empty files, and files larger than `--max-size` are skipped, exactly as in a filesystem scan.

### The image config

The config is a prime, non-filesystem hiding place for secrets — environment variables, labels, and the build commands baked into the image. prowl scans all of it, each field under its own synthetic path:

| Path | Contents |
|------|----------|
| `image:config/env` | Environment variables (`ENV` / `-e` baked into the config), one `KEY=value` per line. |
| `image:config/labels` | Labels, as sorted `key=value` lines (deterministic across runs). |
| `image:config/entrypoint`, `…/cmd` | The entrypoint and default command. |
| `image:config/healthcheck` | The healthcheck command (a `curl -H "Authorization: …"` probe leaks here). |
| `image:config/onbuild` | `ONBUILD` triggers. |
| `image:config/user`, `…/workingdir`, `…/stopsignal` | The remaining config strings. |
| `image:config/history/N` | Build-history instruction `N` (`CreatedBy`) — every `RUN`/build command, one synthetic path each so a leaked `ARG` token is attributed to the exact step. |

Each config field is charged against the same anti-bomb budget and capped by `--max-size`, so a crafted multi-megabyte env value can't blow up the scan.

## Does the leak survive into the running image? (`in_final_image`)

A container image is a stack of layers; the running container sees only the *flattened* result, but every layer is preserved and independently pullable. The classic leak:

```dockerfile
COPY id_rsa /root/.ssh/id_rsa      # layer 4 — secret added
RUN ... && rm /root/.ssh/id_rsa    # layer 6 — secret "removed"
```

The file is gone from the final filesystem, so a flattened scan (or `docker run … cat`) finds nothing — but the secret is **fully recoverable** from layer 4, where it persists. prowl scans every layer, so it catches the secret in `layer4:root/.ssh/id_rsa` even though a later layer deleted it. This "COPY a secret, `RM` it later" pattern is one of the most common ways credentials leak in published images, and a flattened scan misses it entirely.

To tell the two cases apart, every finding carries an **`in_final_image`** field (in `--format json`):

- `true` — the secret is still present in the flattened image a `docker pull` deploys. Highest urgency.
- `false` — a later layer whiteouted/overwrote it; it lives only in image history, recoverable by anyone who pulls the layers but not in the running container.
- *omitted* (unknown) — prowl couldn't determine it (a cancelled or anti-bomb-degraded scan); never assume "safe".

prowl computes this by replaying the OCI whiteout rules (`.wh.<name>`, opaque `.wh..wh..opq`, last-writer-wins) across the layer stack. Use it to triage: a `true` is a live exposure in what you ship; a `false` is still a real leak (rotate the key) but reachable only by someone who pulls the historical layers.

## Layer → Dockerfile instruction

Each layer finding also carries the **`instruction`** field (in `--format json`): the Dockerfile build instruction (`CreatedBy`) that produced that layer, so you can map a leak straight back to the line in the Dockerfile that introduced it.

## Authentication

- **Public images** need no credentials — `prowl image alpine:latest` just works.
- **Private registries** authenticate through the **default Docker keychain**: your existing `docker login` credentials in `~/.docker/config.json` (and the platform credential helpers it references). If `docker pull <ref>` works in your shell, `prowl image <ref>` works. There is no prowl-specific credential flag.

## In-memory streaming

Nothing is written to disk. Layers are pulled and their tars are **streamed in memory**, one file at a time, straight into the detector — there is no `docker save`, no temp extraction directory, and no flattened image on disk to clean up afterwards. (A stdin stream is spooled to a temp file only because a tar index needs random access, and that spool is removed when the scan ends.)

## Fingerprint dedup

The same file — and therefore the same secret — frequently appears across several layers (a base layer carries it, a later layer re-copies it). prowl **deduplicates findings by content fingerprint**, so an identical secret seen in multiple layers is reported once rather than once per layer. You get the leak, not a pile of duplicates.

## Flags

Every [`prowl scan`](Scanning-Files.md) flag applies unchanged: detection (`--rules-dir`, `--tags`, `--exclude-tags`, `--rule-severity`, `--rules`), verification (`--verify`, `--verified-only`), gating and output (`--fail-on`, `--format`, `-o`/`--output`), baselines (`--baseline`, `--write-baseline`), sizing/concurrency (`--max-size`, `--workers`, `--timeout`), and the logging flags.

`--exclude SUBSTR` is honored against the clean in-layer path (without the `<image>|` prefix), so the same pattern behaves identically to a filesystem scan:

```bash
# Skip stock distro config/cert paths while scanning the image
prowl image ghcr.io/org/app:1.4 --exclude etc/ssl/ --exclude usr/share/doc/
```

## Examples

```bash
# Public image from Docker Hub — every layer + config
prowl image alpine:latest

# Local tarball built in CI, gate on any high-or-worse finding, JSON report
docker save app:1.4 | prowl image - --fail-on high --format json -o image.json

# Several images at once, confirm hits are live against the provider
prowl image app:1.4 sidecar:2.0 --verify

# Private registry (Docker keychain), only secrets that survive into the deployed image
prowl image myregistry.io/team/api@sha256:abc… --format json | jq '.findings[] | select(.in_final_image == true)'
```

## See also

- [Repository Scanning](Repository-Scanning.md)
- [Org-Wide Scanning](Org-Scanning.md)
- [Scanning Files](Scanning-Files.md)
- [Security Model](Security-Model.md)
- [Home](README.md)
