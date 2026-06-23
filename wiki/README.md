# Prowl

Prowl is a fast, configurable secret scanner. It reads a codebase, git history, a live web page, or a stream of text and reports leaked credentials — API keys, tokens, database URIs, private keys, passwords in prose — with the line, column, and a confidence score. The design goal is high recall without a flood of false positives.

This wiki documents every feature, command, and flag.

## Quick start

```sh
go install github.com/Lercas/prowl/tool/cmd/prowl@latest
prowl rules update          # install the detection library into ~/.prowl
prowl scan .                # scan the working tree
```

```console
$ prowl scan .

  src/config/prod.ts
    ✖ critical  aws_access_key_id      42:18   AKIA••••DSYP    live
  .env.example
    ✖ high      github_pat             3:11    ghp_••••a1b2

  2 findings  1 critical · 1 high  in 2 files
```

## Pages

### Getting started
- [Installation](Installation.md) — Go, Docker, binary, source; first-run setup
- [Quick Start](Quick-Start.md) — the common workflows, copy-paste

### Scanning
- [Scanning Files](Scanning-Files.md) — `prowl scan`, git modes, every flag
- [Repository Scanning](Repository-Scanning.md) — clone & scan a remote repo by URL
- [Org-Wide Scanning](Org-Scanning.md) — clone & scan every repo in an org/group/workspace
- [Container Scanning](Container-Scanning.md) — pull & scan an OCI/Docker image
- [Cloud Storage Scanning](Bucket-Scanning.md) — download & scan an S3 / GCS prefix
- [Domain Scanning](Domain-Scanning.md) — `prowl domain`, authorized web recon
- [Live Verification](Live-Verification.md) — `--verify`, confirming a secret is live

### Detection
- [Rules](Rules.md) — the nuclei-style template library and authoring loop
- [Verifiers](Verifiers.md) — data-driven live-credential verifiers
- [Architecture](Architecture.md) — the three-stage detection cascade
- [Data Flywheel](Data-Flywheel.md) — the self-improving ML false-positive filter and its retrain loop

### Integrate
- [CI/CD Integration](CI-CD-Integration.md) — exit codes, SARIF, baselines, pre-commit
- [Server Mode](Server-Mode.md) — `prowl serve`, the HTTP scan API
- [Editor Integration (LSP)](Editor-Integration-LSP.md) — in-editor highlighting

### Reference
- [Configuration](Configuration.md) — `.prowl.yaml` fields, pragmas, environment variables
- [Output Formats](Output-Formats.md) — pretty, JSON, SARIF
- [Security Model](Security-Model.md) — how Prowl avoids becoming an attack surface
- [Doctor & Troubleshooting](Doctor-and-Troubleshooting.md) — `prowl doctor` and common issues

## Project

- Source — https://github.com/Lercas/prowl
- Detection library — https://github.com/Lercas/prowl-templates
- Benchmark — https://github.com/Lercas/prowlbench
- License — PolyForm Noncommercial 1.0.0 (free for non-commercial use)
