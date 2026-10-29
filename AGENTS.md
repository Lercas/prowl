# Prowl for AI agents

Prowl is a secret scanner with a layered runtime pipeline: **L1** regex/checksum/entropy candidate
detection → optional **L2** ML false-positive filtering (`--ml`) → optional post-detection live
verification (`--verify`). This guide is how an autonomous agent drives it.

## 1.4.0 contract

- `--staged` читает Git index; `--strict` даёт код 2 при неполном скане.
- `--staged` и `--since` ограничены текущей директорией; для всего repository
  запускай из его корня. Конфликт index делает staged-скан неполным;
  пустая выборка всё равно возвращает JSON/SARIF envelope.
- JSON содержит `schema_version: "1.4"`, `complete`, `scope`, `filtered`,
  `secrets_revealed`, `stats`, `diagnostics`. Не трактуй пустой неполный отчёт как clean.
- `--reconstruct` восстанавливает ограниченные константные JS/TS-выражения.
- `--semantic` создаёт новые кандидаты через локальный endpoint и требует
  буквальных source spans; кандидаты не являются подтверждёнными LIVE.
- `--ml` работает и в статических сборках без Python/sidecar.
- `--verify-all` и `--fail-on-verified` проверяют до ML и сохраняют LIVE.
- `identity init`, `correlate`, `remediation-check`, `selftest --ml` описаны в
  [релизе 1.4.0](wiki/Release-1.4.0.md). Отсутствие секрета не доказывает отзыв.
- `correlate` сообщает `links_truncated` и `complete: false` при обрезке графа;
  достижение глубины вложенных архивов также делает скан неполным.
- MCP поддерживает `strict`, `reconstruct`, `semantic`, structuredContent и отмену.
- LSP использует общий pipeline находок CLI, включая pragmas и устранение дублей;
  редактор не подключает ML или live verifiers. Отдельные source spans одного
  секрета сохраняются как разные occurrences.
- Текущая политика детекции `noise-10` входит в scope, даже для пустого скана.
  Одинаковый номер 1.4.0 не делает отчёты с разными политиками сопоставимыми.
- Base64 ищется независимо от generic entropy: до четырёх слоёв, typed-only,
  каждый blob ≤8192 символов, общий бюджет всех ветвей/слоёв ≤8 MiB.
  `base64_limit` делает скан неполным при превышении работы, размера или глубины.
  Primary range покрывает исходные encoding quanta конкретного occurrence;
  evidence хранит исходные spans всех слоёв. Повторения одного token не сливаются.
- HMAC occurrence ID учитывает исходные proof paths: разные logical occurrences
  через один alias сохраняют отдельные IDs и verification verdicts. Evidence
  содержит только исходные координаты/transform names, без decoded context.
- В YAML plain/quoted/block scalars получают значение закреплённого parser до
  identity, ML и verification. Aliases и merge сохраняют definition/use evidence
  и локальный companion context; overrides не создают неактивные use sites.
  `!!binary` декодируется с исходными Base64 spans. Anchors ограничены документом;
  cycles, неизвестные tags/complex keys/duplicates и лимиты делают скан неполным
  через `yaml_*`. Вход ≤1 MiB, scalar ≤4096 bytes, ≤100000 physical nodes,
  ≤10000 inventory entries, разворачивание ≤100000 visits/8 MiB; глубина ≤64.
  Комментарии и presentation identifiers сканируются отдельно. Allow directives
  распознаются только в комментариях, с logical line boundaries YAML parser.
- Во всех валидных JSON строковые значения канонизируются до ML,
  identity и verification. Повторные поля сохраняют occurrences; evidence ссылается
  на исходную строку. Companion context ограничен непосредственным объектом.
  Повторные имена полей делают объект неоднозначным (`json_literal_duplicate`):
  occurrences сохраняются, verification для объекта отключена, strict возвращает 2.
  Вход ≤1 MiB, значение ≤4096 bytes, ≤100000 tokens/10000 strings, глубина ≤64; ошибки/лимиты
  дают `json_literal_*` и неполный скан. Лексический fallback остаётся доступен.
- В TOML basic/literal и многострочные строки получают значение закреплённого
  parser до identity, ML и verification. Комментарии и ключи сохраняются;
  companion context ограничен table/inline object и конкретным array-of-tables
  instance. UTF-8 BOM сохраняет координаты. Вход ≤1 MiB, значение ≤4096 bytes,
  до parser expansion qualified key ≤8192 bytes/64 segments, общий qualified-key
  work ≤8 MiB; превышение даёт `toml_literal_limit` и неполный lexical fallback.
  ≤100000 tokens/10000 inventory entries, глубина ≤64; ошибки/лимиты дают
  `toml_literal_*` и неполный скан. Нормализация не исполняет шаблоны.
- Allow pragmas читаются из комментариев поддерживаемого source format;
  Окончания строк LF/CR/CRLF сохраняют координаты CLI/LSP и границы комментариев.
  обычные JSON/TOML строки с `prowl:allow` не подавляют находки. JSON не имеет
  комментариев. Операторская allowlist остаётся отдельной явной настройкой.
- `--semantic` сохраняется при нормализации строк; generated wrappers не являются
  source spans. Кандидат ссылается на каноническое значение и исходное evidence.
- JWT получает `L1-structure`, а не checksum proof: header/payload JSON проверены,
  подпись и действительность не подтверждены. CRC GitHub token — best-effort
  проверка формата; она также не доказывает аутентичность или LIVE.
- `doctor` загружает выбранные rules/verifiers без provider requests: повреждённый
  набор даёт отказ, installed overrides показываются предупреждением.
- LSP без installed rules использует все bundled templates; повреждённый overlay
  не позволяет запустить editor pipeline. `lsp --bundled` явно выбирает встроенные
  templates; остальные scan flags для LSP не поддержаны.
- HTTP worker поддерживает L1/rules и redaction. Неподдержанные стадии дают startup
  exit 2; повреждённый rules set также блокирует запуск. `/capabilities` описывает
  контракт. Intake требует явный string `content`, отказывает на null/duplicates/
  unknown fields/trailing JSON. Scope описывает только переданный клиентом контент.
- `--bundled` выбирает embedded rules/verifiers без изменения PROWL_HOME, config или
  identity.key. Доступен в scan/source commands, doctor, version, serve и lsp;
  в MCP передавай boolean `bundled` в tool call, а не как startup flag.
  Конфликт с --rules-only/--rules-dir/--verifiers даёт отказ.

## MCP (preferred)

Prowl is an MCP server — register it once and call scans as tools:

```bash
claude mcp add prowl -- prowl mcp
```

Tools (each returns the JSON findings envelope as text):

| Tool | Required args | Optional | Use for |
|------|---------------|----------|---------|
| `prowl_scan` | `path` | `verify`, `ml`, `ocr`, `show_secrets` | a local file, directory, archive, document, or mail export |
| `prowl_domain` | `target`, `authorized` | `recon`, `verify` | a domain's public web surface |
| `prowl_mobile` | `path` | `ml` | an Android `.apk` / iOS `.ipa` |
| `prowl_repo` | `url` | `verify`, `ocr` | a git repository (tree + history) |
| `prowl_cicd` | `target` | `verify`, `ml` | GitHub Actions / GitLab CI logs and artifacts |

`prowl_domain` **refuses unless `authorized: true`** — set it only for a target you are authorized to
test (a bug-bounty scope, your own asset, an engagement). The same attestation gates the CLI's
`--authorized`.

## CLI (direct / scripting)

```bash
prowl scan ./src --ml --format json          # local tree, ML-denoised
prowl scan incident.pdf deployment.eml       # PDF text layers + decoded MIME attachments
prowl scan screenshots/ scan.pdf --ocr       # local VLM OCR for images + image-only PDF pages
prowl repo https://github.com/org/repo --verify
prowl cicd github:org/repo --ml --format json
prowl domain example.com --authorized --recon --ml --format json
prowl mobile app.apk --ml --format json
prowl image registry/img:tag --format json   # container image layers
prowl bucket s3://bucket/prefix --format json
```

Key flags: `--format json|sarif|pretty`, `--ml` (L2 candidate filter), `--verify` (post-detection
provider validation), `--show-secrets` (raw values for authorized triage; default is redacted),
`--verified-only` (keep only provider-confirmed live findings), `--ocr` (local image/PDF OCR),
`--max-size N` (bytes), `--fail-on SEV`.

## Output

JSON envelope: `{"findings": [...], "truncated": bool, ...}`. Each finding:

```jsonc
{ "type": "aws-access-key-id", "severity": "high", "path": "...", "line": 12,
  "redacted": "AKIA****WJX42K",        // full value when --show-secrets
  "verified": true,                     // true=LIVE, false=provider rejection
  "confidence": 0.9, "fingerprint": "..." }
```

Read `verified` first: **`true` = provider-confirmed credential** (impact and bug-bounty eligibility require separate evidence); `false` = provider rejection, not proof of revocation; `null` = unsupported, not checked or inconclusive, inspect `verification.status`.

## Decision guide

- **Want only real leaks?** add `--ml --verify`; for a noisy web/mobile target add `--verified-only`.
- **`--verify` hits the live provider** (validates the key). Fine for triage; never mass-exercise a key.
- **Generic password and semantic findings** are unconfirmed and never sent to a provider.
  `generic_high_entropy` can use a verifier only when its value starts with an explicit provider
  prefix; a provider name buried in a value does not qualify. Treat unsupported findings as candidates.
- **OCR is opt-in.** `--ocr` sends PNG/JPEG/WebP and PDF pages without a text layer to the local
  OpenAI-compatible endpoint at `127.0.0.1:8080`. A remote endpoint requires
  `--ocr-allow-remote` plus HTTPS because documents can contain the very secrets being scanned.
- **`prowl_domain` / `prowl_mobile`** surface different things: web = source maps + bundles; mobile =
  `resources.arsc` + dex strings + `google-services.json` (often richer). Run both for full coverage.
