# MCP Server

`prowl mcp` runs Prowl as a **Model Context Protocol server over stdio**, so an AI agent — Claude Code, Claude Desktop, or any MCP client — can drive scans as tools. It speaks newline-delimited JSON-RPC on stdin/stdout; there is no port to open and no network listener. Each tool call runs a scan and returns the same JSON findings envelope the CLI produces.

```sh
prowl mcp
```

Where [Server Mode](Server-Mode.md) exposes an HTTP API for content you push at it, `prowl mcp` exposes the *commands* (scan a path, a domain, a mobile app, a repo, or CI artifacts) as agent-callable tools over a single stdio pipe.

## Registration

Register Prowl once with your MCP client and it stays available across sessions:

```bash
claude mcp add prowl -- prowl mcp
```

The `-- prowl mcp` after the name is the command the client launches and talks to over stdio. Any MCP-capable client works the same way — point it at `prowl mcp` as a stdio server.

The full agent-facing guide — flag reference, output shape, and a triage decision tree — lives in [`AGENTS.md`](https://github.com/Lercas/prowl/blob/main/AGENTS.md) at the repo root.

## Tools

Each tool runs the corresponding scan and returns the JSON findings envelope as text (`{"findings": [...], "truncated": bool, ...}`; see [Output Formats](Output-Formats.md)).

| Tool | Required args | Optional | Use for |
|------|---------------|----------|---------|
| `prowl_scan` | `path` | `verify`, `verified_only`, `ml`, `ocr`, `show_secrets`, `reconstruct` | a local file or directory |
| `prowl_domain` | `target`, `authorized` | `recon`, `verify`, `verified_only`, `reconstruct` | a domain's public web surface |
| `prowl_mobile` | `path` | `ml`, `reconstruct` | an Android `.apk` / iOS `.ipa` |
| `prowl_repo` | `url` | `verify`, `verified_only`, `ocr`, `reconstruct` | a git repository |
| `prowl_cicd` | `target` | `verify`, `verified_only`, `ml`, `reconstruct` | GitHub Actions / GitLab CI logs and artifacts |

The optional args map to the CLI flags of the same name: `verify` → [`--verify`](Live-Verification.md)
(post-detection provider validation), `ml` → `--ml` (the [L2 ML candidate filter](Data-Flywheel.md)),
`ocr` → `--ocr` (the configured local [image/PDF OCR](OCR-Scanning.md)), `show_secrets` →
`--show-secrets` (raw values for authorized triage), `recon` → `--recon` (the
[domain deep sweep](Domain-Scanning.md)).

`reconstruct` включает ограниченную статическую реконструкцию JS/TS, без исполнения
кода. `verified_only` включает live verification с последующей фильтрацией;
его семантика совпадает с CLI `--verified-only`, включая сохранение некоторых
high/critical типов без верификатора. Полное описание — [Live Verification](Live-Verification.md).
Путь `path` сохраняется буквально, включая начальные и конечные пробелы.
Неизвестные аргументы и значения неверного типа отклоняются до запуска сканера.

## Протокол и жизненный цикл

Сохранены версии транспорта из выпущенного 1.4.0: initialization-based
`2024-11-05`, `2025-03-26`, `2025-06-18` и запросы `2026-07-28` с `_meta`
`io.modelcontextprotocol/protocolVersion` и `io.modelcontextprotocol/clientCapabilities`.
Для последнего варианта доступен `server/discover`; неподдерживаемая версия даёт
ошибку с перечнем поддерживаемых значений. Modern-ответы содержат `resultType`
и server info. Это контракт реализации Prowl, проверяемый локальными тестами.

Отчёт доступен и как text content, и как `structuredContent`; schemas инструментов
объявляют форму результата. `isError` поднимается при неполноте, truncation или
ошибке процесса; RPC-успех сам по себе не означает complete scan.
Ошибки запуска не раскрывают содержимое stderr дочернего процесса.

Одновременно выполняются не более двух сканов, каждый ограничен пятью минутами
и 32 МиБ stdout. Входное JSON-RPC сообщение ограничено 16 МиБ. `ping` не ждёт
завершения скана. `notifications/cancelled` отменяет активный request ID;
для modern-вызова отменённый результат не отправляется. EOF отменяет оставшиеся
сканы и дожидается завершения дочерних процессов. Повтор активного ID отклоняется.
Дубли полей и lossy Unicode отклоняются строгим JSON-декодером.

`prowl mcp` запускается без scan flags; параметры передаются в `tools/call`.
`bundled: true` в `tools/call` выбирает встроенные rules/verifiers релиза,
сохраняя текущие конфигурацию и identity key. `strict` и `semantic` остаются
отдельными пунктами миграции и сейчас не рекламируются.

Локальная проверка: `python3 scripts/check_mcp_contract.py /path/to/prowl`.
Матрица использует отдельный PROWL_HOME, только собственные файлы/APK и stdio;
не вызывает live-провайдеров, domain, clone или CI API. Отмена активных вызовов,
пределы concurrency/output и ошибки транспорта отдельно покрыты Go/race-тестами.

## The `authorized` gate

`prowl_domain` **refuses to run unless `authorized: true` is set** in the tool call. This is the same hard consent gate as the CLI's `--authorized` flag — an explicit attestation that you are permitted to fetch the target's published pages and assets. There is no config or environment override; the agent must set it on every `prowl_domain` call. Set it only for a target you are authorized to test: your own asset, a bug-bounty scope, or an explicit engagement.

`prowl_scan`, `prowl_mobile`, and `prowl_repo` operate on artifacts you already hold. `prowl_cicd`
uses the read-only forge token already configured in the MCP server environment. They have no
additional attestation gate.

## See also

- [Server Mode](Server-Mode.md) — `prowl serve`, the stateless HTTP scan API
- [Domain Scanning](Domain-Scanning.md) — the `--authorized` consent gate in depth
- [Mobile Scanning](Mobile-Scanning.md) — `prowl mobile`, the APK/IPA target
- [CI Artifact Scanning](CI-Artifact-Scanning.md) — `prowl cicd`, logs and ZIP artifacts
- [Live Verification](Live-Verification.md) — `--verify` and the blast-radius report
- [Data Flywheel](Data-Flywheel.md) — the `--ml` filter behind the `ml` arg
- [Output Formats](Output-Formats.md) — the JSON findings envelope each tool returns
- [Home](README.md)
