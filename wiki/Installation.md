# Installation

Prowl is a single static Go binary with no runtime dependencies. В 1.4.0 правила, верификаторы и ML уже встроены; дополнительная установка библиотек не требуется.

```bash
# Go toolchain (recommended)
go install github.com/Lercas/prowl/tool/cmd/prowl@latest

# необязательно: обновить внешние библиотеки (writes to ~/.prowl)
prowl rules update
prowl verifiers update

# confirm the install
prowl version
```

## Install methods

### go install

Requires Go 1.25+. Installs the `prowl` binary into `$(go env GOPATH)/bin` (ensure it is on your `PATH`).

```bash
go install github.com/Lercas/prowl/tool/cmd/prowl@latest
```

### Docker

The image bundles the rule and verifier libraries, so it works offline with no `update` step. Mount the directory you want to scan and pass it as the scan path.

```bash
docker run --rm -v "$PWD:/src" ghcr.io/lercas/prowl scan /src
```

Any scan flag works the same way inside the container:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" ghcr.io/lercas/prowl \
  scan /src --strict --format sarif -o /src/prowl.sarif --fail-on high
```

### Prebuilt binary

В canonical release 1.4.0 скачайте `prowl-OS-ARCH` (Windows: `.exe`) со [страницы releases](https://github.com/Lercas/prowl/releases), проверьте `checksums.txt` и поместите бинарник в PATH.

```bash
chmod +x prowl-linux-amd64
sudo install prowl-linux-amd64 /usr/local/bin/prowl
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

## Обновление библиотек

В 1.4.0 первый скан и `--ml` работают автономно. Встроенные библиотеки
проверяются по manifest. Отдельная установка нужна для обновления или своих
наборов правил; установленный набор имеет приоритет перед встроенным:

```bash
prowl rules update        # detection rule templates -> ~/.prowl/rules
prowl verifiers update    # live-credential verifiers  -> ~/.prowl/verifiers
```

Both pull from the template library at `github.com/Lercas/prowl-templates`. Для обычного скана сеть не нужна. Offline fallback самой команды update требует набора файлов рядом с бинарником; встроенный scan не зависит от успеха update. Pass `--check` to preview what an update would change without installing, or `--source <dir|git-url>` to install from an alternate location.

Once installed, `scan` auto-loads `~/.prowl/rules` and `--verify` auto-loads `~/.prowl/verifiers` — no `--rules-dir` / `--verifiers` flags required.

`prowl version` reports the binary version plus the installed library versions and their on-disk location:

```text
prowl 1.0.2
rules:     159 installed (version 1.0.0) at /Users/you/.prowl/rules
verifiers: 78 installed (version 1.0.0) at /Users/you/.prowl/verifiers
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
