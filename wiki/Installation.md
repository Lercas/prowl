# Installation

Prowl is a single static Go binary with no runtime dependencies. Pick whichever install method fits your environment, then run the one-time library setup.

```bash
# Go toolchain (recommended)
go install github.com/Lercas/prowl/cmd/prowl@latest

# install the rule + verifier libraries (writes to ~/.prowl)
prowl rules update
prowl verifiers update

# confirm the install
prowl version
```

## Install methods

### go install

Requires Go 1.25+. Installs the `prowl` binary into `$(go env GOPATH)/bin` (ensure it is on your `PATH`).

```bash
go install github.com/Lercas/prowl/cmd/prowl@latest
```

### Docker

The image bundles the rule and verifier libraries, so it works offline with no `update` step. Mount the directory you want to scan and pass it as the scan path.

```bash
docker run --rm -v "$PWD:/src" ghcr.io/lercas/prowl scan /src
```

Any scan flag works the same way inside the container:

```bash
docker run --rm -v "$PWD:/src" ghcr.io/lercas/prowl \
  scan /src --format sarif -o /src/prowl.sarif --fail-on high
```

### Prebuilt binary

Download the archive for your OS/arch from the [releases page](https://github.com/Lercas/prowl/releases), extract it, and put `prowl` somewhere on your `PATH`.

```bash
tar -xzf prowl_*.tar.gz
sudo install prowl /usr/local/bin/
prowl version
```

### From source

Requires Go 1.25+. The `Makefile` builds a trimmed, stripped binary into the current directory.

```bash
git clone https://github.com/Lercas/prowl.git
cd prowl/tool
make build      # -> ./prowl
./prowl version

# or install into $GOPATH/bin
make install
```

## First-run setup

The detection rules and live-credential verifiers are versioned independently of the binary and live outside it. Install them once:

```bash
prowl rules update        # detection rule templates -> ~/.prowl/rules
prowl verifiers update    # live-credential verifiers  -> ~/.prowl/verifiers
```

Both pull from the template library at `github.com/Lercas/prowl-templates`. If the remote is unreachable, each command falls back to the snapshot bundled alongside the binary, so setup also works offline. Pass `--check` to preview what an update would change without installing, or `--source <dir|git-url>` to install from an alternate location.

Once installed, `scan` auto-loads `~/.prowl/rules` and `--verify` auto-loads `~/.prowl/verifiers` — no `--rules-dir` / `--verifiers` flags required.

`prowl version` reports the binary version plus the installed library versions and their on-disk location:

```text
prowl 0.1.0 (MVP)
rules:     412 installed (version 2026.06.01) at /Users/you/.prowl/rules
verifiers: 38 installed (version 2026.06.01) at /Users/you/.prowl/verifiers
```

Before setup, the `rules` / `verifiers` lines instead read `not installed — run 'prowl rules update'`.

## Install directory

The rule and verifier libraries are stored under the prowl home directory, resolved in this order:

| Precedence | Source | Resulting home dir |
|------------|--------|--------------------|
| 1 | `PROWL_HOME` env var | the value verbatim |
| 2 | `XDG_CONFIG_HOME` env var | `$XDG_CONFIG_HOME/prowl` |
| 3 | default | `~/.prowl` |

Rules live in `<home>/rules`, verifiers in `<home>/verifiers`. Set `PROWL_HOME` to share one library across machines or to pin a per-project location:

```bash
PROWL_HOME=/opt/prowl prowl rules update
PROWL_HOME=/opt/prowl prowl scan .
```

## No external services

Prowl is fully self-contained. Detection runs locally; the only network calls are the optional `rules`/`verifiers` updates and `--verify` live checks against the credential providers themselves. There is no prowl backend, database, or account to configure — the detection cascade ships in the binary and library.

## See also

- [Quick Start](Quick-Start.md)
- [Scanning Files](Scanning-Files.md)
- [Configuration](Configuration.md)
- [Rules](Rules.md)
- [Live Verification](Live-Verification.md)
- [Home](README.md)
