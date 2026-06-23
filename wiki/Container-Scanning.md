# Container Image Scanning

```
prowl image <ref>
```

Pull a container image and scan it for secrets — **every layer's files plus the image config**, not just the flattened final filesystem. The `<ref>` is any OCI/Docker reference:

```bash
prowl image alpine:latest
prowl image ghcr.io/org/app:1.4
prowl image myregistry.io/team/api@sha256:abc…
```

The image is pulled with [go-containerregistry](https://github.com/google/go-containerregistry), so **no Docker daemon is required** — prowl talks to the registry directly. It works against any registry: Docker Hub, GHCR, GCR, Amazon ECR, or a self-hosted/on-prem registry.

> To scan source from a git host, see [Repository Scanning](Repository-Scanning.md); to download & scan an S3 / GCS prefix, see [Cloud Storage Scanning](Bucket-Scanning.md).

`prowl image` accepts every [`prowl scan`](Scanning-Files.md) flag — `--verify`, `--fail-on`, `--format`, `--rules-dir`, `--tags`, `--baseline`, `--max-size`, and the rest. See [Scanning Files](Scanning-Files.md) for the full flag reference; the notes below cover only what is specific to images.

## What gets scanned

Two things: the files inside **every layer**, and the **image config**.

### Every layer's files

prowl walks each layer's tar and scans every regular text file it contains. Each finding's path is reported as:

```
layerN:<file>
```

where `N` is the layer index (`layer0`, `layer1`, …) and `<file>` is the path inside that layer — e.g. `layer3:app/.env` or `layer0:etc/credentials.json`. Binary files, empty files, and files larger than `--max-size` are skipped, exactly as in a filesystem scan.

### The image config

The config is a prime, non-filesystem hiding place for secrets — environment variables, labels, and the build commands baked into the image. prowl scans all three, each under its own synthetic path:

| Path | Contents |
|------|----------|
| `image:config/env` | The image's environment variables (`ENV` / `-e` baked into the config), one `KEY=value` per line. |
| `image:config/labels` | The image's labels, as sorted `key=value` lines (deterministic across runs). |
| `image:config/history` | The build history — every `RUN`/build command (`CreatedBy`) from the layer history, one per line. A `RUN curl -H "Authorization: Bearer …"` or an `ARG`-leaked token shows up here. |

## Why scan every layer, not just the final filesystem

A container image is a stack of layers. The running container sees only the *flattened* result, but each layer is preserved and independently pullable. The classic leak:

```dockerfile
COPY id_rsa /root/.ssh/id_rsa      # layer 4 — secret added
RUN ... && rm /root/.ssh/id_rsa    # layer 6 — secret "removed"
```

The file is gone from the final filesystem, so a scan of the flattened image (or `docker run … cat`) finds nothing — but the secret is still **fully recoverable** from layer 4, where it persists. Anyone who pulls the image can extract it. Because prowl scans every layer, it catches the secret in `layer4:root/.ssh/id_rsa` even though a later layer deleted it. This "COPY a secret, `RM` it later" pattern is one of the most common ways credentials leak in published images, and a flattened-filesystem scan misses it entirely.

## Authentication

- **Public images** need no credentials — `prowl image alpine:latest` just works.
- **Private registries** authenticate through the **default Docker keychain**: your existing `docker login` credentials in `~/.docker/config.json` (and the platform credential helpers it references). If `docker pull <ref>` works in your shell, `prowl image <ref>` works. There is no prowl-specific credential flag.

## In-memory streaming

Nothing is written to disk. Layers are pulled and their tars are **streamed in memory**, one file at a time, straight into the detector — there is no `docker save`, no temp extraction directory, and no flattened image on disk to clean up afterwards. This keeps the scan fast and leaves no image artifacts behind.

## Fingerprint dedup

The same file — and therefore the same secret — frequently appears across several layers (a base layer carries it, a later layer re-copies it, and so on). prowl **deduplicates findings by content fingerprint**, so an identical secret seen in multiple layers is reported once rather than once per layer. You get the leak, not a pile of duplicates.

## Flags

Every [`prowl scan`](Scanning-Files.md) flag applies unchanged: detection (`--rules-dir`, `--tags`, `--exclude-tags`, `--rule-severity`, `--rules`), verification (`--verify`, `--verified-only`), gating and output (`--fail-on`, `--format`, `-o`/`--output`), baselines (`--baseline`, `--write-baseline`), sizing/concurrency (`--max-size`, `--workers`, `--timeout`), and the logging flags. Unlike `prowl org`, an image has no scanned source tree, so there is no in-image `.prowl.yaml` to defend against — your own `--config` applies normally.

`--exclude SUBSTR` is honored here too: a layer file whose path (the `layerN:<file>` form) contains the substring is skipped before it is scanned. Use it to drop a noisy distro path baked into a base image:

```bash
# Skip stock distro config/cert paths while scanning the image
prowl image ghcr.io/org/app:1.4 --exclude etc/ssl/ --exclude usr/share/doc/
```

## Examples

```bash
# Public image from Docker Hub — every layer + config
prowl image alpine:latest

# GHCR image, gate CI on any high-or-worse finding
prowl image ghcr.io/org/app:1.4 --fail-on high

# Private registry (Docker keychain), confirm hits are live against the provider
prowl image myregistry.io/team/api@sha256:abc… --verify

# Machine-readable report for a pipeline / dashboard
prowl image ghcr.io/org/app:1.4 --format json -o image.json
```

## See also

- [Repository Scanning](Repository-Scanning.md)
- [Org-Wide Scanning](Org-Scanning.md)
- [Scanning Files](Scanning-Files.md)
- [Security Model](Security-Model.md)
- [Home](README.md)
