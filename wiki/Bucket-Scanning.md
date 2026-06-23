# Cloud Storage Scanning

```
prowl bucket <s3://bucket/prefix | gs://bucket/prefix> [flags]
```

Download a cloud-storage prefix and scan it for secrets. Prowl syncs the prefix into a temporary directory using **the platform's own CLI**, scans the download like any directory, and removes it afterwards — nothing is left on disk.

> To scan source from a git host instead, see [Repository Scanning](Repository-Scanning.md); to scan a built container image, see [Container Scanning](Container-Scanning.md).

The download shells out to your installed cloud CLI rather than bundling a cloud SDK — exactly as [`prowl repo`](Repository-Scanning.md) shells out to `git`. This keeps heavy SDKs out of the binary (zero new Go dependencies) and means the sync reuses **your existing cloud credentials, regions, and roles** with no prowl-specific configuration.

`prowl bucket` accepts every [`prowl scan`](Scanning-Files.md) flag (verification, fail-on gating, output format, rule selection, tags, …); the notes below cover only what is specific to buckets.

## URI schemes

The target is a single `s3://` or `gs://` URI. The scheme selects the CLI used to download it:

| URI | Storage | Downloaded with |
|-----|---------|-----------------|
| `s3://bucket/prefix` | Amazon S3 | `aws s3 sync` (the AWS CLI) |
| `gs://bucket/prefix` | Google Cloud Storage | `gcloud storage rsync --recursive` (the gcloud CLI) |

Azure Blob Storage is **not supported yet**. Any other scheme is rejected.

## The CLI must be installed and authenticated

The matching CLI — `aws` for `s3://`, `gcloud` for `gs://` — must be on your `PATH` and already authenticated. Prowl runs the same `aws`/`gcloud` you would run by hand, so it inherits whatever credentials, default region, and assumed role that CLI is configured with (environment variables, `~/.aws/config`, an SSO/instance profile, an `gcloud auth` login, etc.). There is no prowl-specific credential flag: if `aws s3 sync <uri> .` (or `gcloud storage rsync --recursive <uri> .`) works in your shell, `prowl bucket <uri>` works.

If the CLI is missing, Prowl fails fast with a clear error rather than silently scanning nothing:

```console
$ prowl bucket s3://my-logs/2026/
ERROR bucket download failed err="the AWS CLI (\"aws\") is required to scan this bucket but is not on PATH; install it and configure your cloud credentials"
```

A download failure (missing CLI, bad credentials, unreachable bucket, no such prefix) exits `2`.

## Download, scan, clean up

`prowl bucket` is a download-then-scan model:

1. A temporary directory is created (`prowl-bucket-*`).
2. The whole prefix is synced into it with the platform CLI.
3. The download is scanned as a directory tree — the same filesystem walk as `prowl scan <dir>`, so file paths in findings are relative to the prefix root.
4. The temporary directory is removed when the scan finishes (including on error).

Because the entire prefix is downloaded to local disk before scanning, **mind large buckets**: a wide prefix can pull a lot of data and use significant disk and network. Scope the scan with a narrow prefix (`s3://logs/2026/06/` rather than `s3://logs/`) to keep the download bounded.

## The bucket cannot suppress its own findings

A downloaded bucket is untrusted input, so `prowl bucket` runs with `noAutoConfig`: it **does not auto-discover a `.prowl.yaml` inside the download**. A `.prowl.yaml` that happens to sit under the prefix cannot disable detectors or extend the allowlist to blind the scan of its own contents. This matches the trust boundary `repo`/`org` apply to a cloned tree. Only a config you pass **explicitly with `--config FILE` is trusted**. See [Security Model](Security-Model.md).

## Flags

Every [`prowl scan`](Scanning-Files.md) flag applies unchanged: detection (`--rules-dir`, `--rules`, `--tags`, `--exclude-tags`, `--rule-severity`), verification (`--verify`, `--verified-only`), gating and output (`--fail-on`, `--format`, `-o`/`--output`), baselines (`--baseline`, `--write-baseline`), sizing/concurrency (`--max-size`, `--workers`, `--timeout`), and the logging flags. The bucket is a single scan target, so it emits **one report**, exactly like `scan`/`repo`/`image`. See [Output Formats](Output-Formats.md).

## Examples

```bash
# S3 prefix — gate CI on any high-or-worse finding
prowl bucket s3://my-logs/2026/ --fail-on high

# GCS prefix — machine-readable report for a pipeline / dashboard
prowl bucket gs://my-backups/db/ --format json -o findings.json

# S3 prefix with a team rule set and only AWS/Stripe rules, confirm hits are live
prowl bucket s3://my-artifacts/build-42/ --rules-dir ./team-rules --tags aws,stripe --verify

# Keep the download bounded — scope to a narrow prefix
prowl bucket s3://logs/2026/06/19/ --fail-on critical
```

## See also

- [Container Scanning](Container-Scanning.md)
- [Repository Scanning](Repository-Scanning.md)
- [Scanning Files](Scanning-Files.md)
- [Security Model](Security-Model.md)
- [Home](README.md)
