# 🐱 Prowl - fast, configurable secret scanner (Go)

> *purr* + *purloin* (to filch) - finds purloined/leaked secrets.

Сканер секретов на Go: один статический бинарь, конкурентный, high-precision (checksum-валидация +
отсев example/placeholder + base64-размаскировка), с **внешней разведкой по домену**, **LSP-подсветкой
в редакторе** и лёгкой интеграцией в CI/CD. Использует таксономию и ML-каскад проекта `secrets_ml`.
Архитектура: [`docs/design/tool_architecture.md`](../docs/design/tool_architecture.md).

## Сборка
```bash
cd tool && go build -o prowl ./cmd/prowl     # таксономия встроена (embed)
# или: docker build -t prowl .
```

## Команды
```bash
# Файлы / директории
prowl scan .                                   # текущая директория
prowl scan --format sarif --output out.sarif --fail-on high src/
prowl scan --format defectdojo -o dd.json .    # DefectDojo Generic Findings Import
prowl scan --ml .                              # + ML-фильтр ложных срабатываний (L2)

# Мобильные приложения (Android APK / iOS IPA)
prowl mobile app.apk                           # распаковка ZIP + скан ресурсов + strings из бинарей
prowl mobile app.ipa --ml --verify             # google-services.json/GoogleService-Info.plist и т.п.
prowl mobile https://cdn.acme.com/app.apk      # URL качается SSRF-защищённым клиентом во временную папку

# MCP-сервер (AI-агенты драйвят сканы как инструменты)
prowl mcp                                       # Model Context Protocol по stdio (JSON-RPC построчно)
# регистрация: claude mcp add prowl -- prowl mcp

# Git (для pre-commit и CI на PR)
prowl scan --staged                            # только staged-файлы (быстро)
prowl scan --since origin/main                 # diff с веткой (CI на PR)
prowl scan --history                           # все блобы git-истории

# Домен (нужен --authorized)
prowl domain acme.com --authorized             # HTML + __NEXT_DATA__/state + referenced JS + maps
prowl domain acme.com --authorized --recon     # + поддомены (crt.sh) + wayback
prowl domain --targets hosts.txt --authorized  # список хостов (по строке) через worker-pool
prowl org acme --gists                          # публичные gists github-юзера вместо репозиториев
prowl scan --show-secrets .                     # печатать ПОЛНОЕ незамаскированное значение + строку-контекст (триаж)

# Jira / Confluence (многоверсионно - каждая версия issue/страницы с самой первой)
prowl jira https://acme.atlassian.net          # Cloud (env: ATLASSIAN_EMAIL + ATLASSIAN_API_TOKEN)
prowl jira https://jira.acme.com --project OPS  # Server/DC (env: ATLASSIAN_PAT), один проект
prowl confluence https://wiki.acme.com --current-only  # только текущая версия (быстро, без истории)

# Редактор (LSP - подсветка секретов на лету)
prowl lsp                                       # запускается как Language Server (stdio)

# Baseline (заглушить принятые находки)
prowl scan --write-baseline .prowl-baseline.json
prowl scan                                      # авто-подхват baseline -> подавляет известные

prowl detectors                                 # список типов
```

## Конфигурация - `.prowl.yaml` (авто-обнаружение или `--config`)
```yaml
version: 1
exclude: ["node_modules", ".min.", "vendor"]
detectors:
  disable: [generic_high_entropy]                  # выключить шумные
  custom:                                           # свои детекторы (как gitleaks)
    - {id: acme_token, regex: 'acme_[A-Za-z0-9]{20}', category: vcs}
allowlist:
  paths:   ["**/test/**"]                           # substring-match по пути
  values:  ["AKIAIOSFODNN7EXAMPLE"]                 # конкретные значения
  regexes: ['(?i)example|dummy']
output:  {format: sarif, fail_on: high, redact: true}
performance:
  max_size: 10485760            # макс. размер файла
  workers: 0                    # 0 = по числу CPU
  verify_concurrency: 8         # параллельных live-verify запросов
  verify_timeout: 8s            # таймаут одного verifier'а
  ml_threshold: 0.3             # порог ML-фильтра (--ml-threshold переопределяет)
detection:                      # пороги детекции (0 = встроенный дефолт)
  generic_entropy_min: 3.5      # мин. энтропия для generic_high_entropy
  placeholder_max_entropy: 4.2  # ниже - значение с placeholder-словом считается заглушкой
  max_matches_per_file: 50000   # DoS-кап на число матчей в одном файле
limits:                         # операционные лимиты (0/"" = дефолт)
  org_max_pages: 200            # макс. страниц API при обходе org/группы
  clone_timeout: 5m             # таймаут git clone для repo/org-сканов
```
Все значения опциональны; пропущенное/нулевое берёт встроенный дефолт. Где есть одноимённый флаг
(`--ml-threshold`, `--max-size`, `--workers`), он переопределяет config. Inline-подавление в коде:
`API_KEY = "..."  # prowl:allow` (совместимо с `pragma: allowlist secret`).

## CI/CD (шаблоны в `ci/`)
- **GitHub Actions**: `ci/github-workflow.yml` (или `uses: Lercas/prowl@v1` через `action.yml`); SARIF в Security tab.
- **GitLab CI**: `ci/gitlab-ci.yml` (артефакт SAST).
- **pre-commit**: `ci/.pre-commit-hooks.yaml` (`id: prowl`, сканирует staged-файлы).
- **Docker**: `Dockerfile` (distroless, ~немного МБ). Exit-код 1 при находках ≥ `--fail-on`.

## Реализовано
- **Каскад L0+L1**: regex по таксономии + **checksum** (GitHub CRC32, JWT) + entropy-гейт +
  **отсев example/placeholder** + **base64-размаскировка** (секреты внутри base64-блобов).
- **Источники**: filesystem (concurrent), **git** (staged/since/history), **domain** (HTML +
  `__NEXT_DATA__`/`__NUXT__`/`__INITIAL_STATE__`/... state-блобы с декодом escape'ов + referenced JS +
  source-maps; опц. crt.sh+wayback), **mobile** (APK/IPA как ZIP: ресурсы/JSON/plist/XML - в т.ч.
  `google-services.json`/`GoogleService-Info.plist` с Google API-ключами + project id - сканируются сырыми;
  бинарные entry `.dex`/`resources.arsc`/`.so`/Mach-O проходят чисто-Go printable-strings - 8-bit ASCII +
  UTF-16LE - так ключи из string-таблиц всплывают; флаги `--no-strings`, `--min-run N` + все scan-флаги; без Android SDK),
  **LSP** (didOpen/didChange дают diagnostics).
- **MCP-сервер** (`prowl mcp`): Model Context Protocol по stdio (построчный JSON-RPC) - AI-агенты
  (Claude Code/Desktop, любой MCP-клиент) драйвят сканы как инструменты. Tools: `prowl_scan` (path),
  `prowl_domain` (target + обязательный `authorized:true`), `prowl_mobile` (apk/ipa), `prowl_repo` (git url) -
  каждый возвращает JSON-конверт находок. Полный гайд для агентов - `AGENTS.md` в корне репо.
- **Post**: baseline-подавление, inline-pragma, allowlist (path/value/regex), dedup перекрытий.
- **L2 ML-фильтр** (`--ml`): встроенная sklearn HistGradientBoosting-модель (`model_binary.json`, go:embed,
  49 фич) отсеивает ложные срабатывания generic-детекторов. Переобучена на реальных hard-negatives с гейтом
  на held-out данных. Также подключается через sidecar (`--ml-url`) или внешним файлом (`--ml-model`).
- **Live-верификация** (`--verify`): 79 верификаторов бьют в read-only identity-эндпоинты провайдеров.
- **Verified blast radius** (`--verify`): live-находка сообщает, ЧТО ключ открывает, а не только live/dead -
  verifier объявляет `capability`-пробы, и rationale читается как «verified live: Google API key - unlocks:
  Firebase Identity Toolkit, Maps Geocoding». В комплекте `google-api-key`-verifier (Identity Toolkit / Gemini / Maps).
- **Меньше ложных срабатываний**: generic-детекторы (`generic_high_entropy`, `generic_password`,
  `generic_api_key`, `basic_auth_header`) отсеивают code module-пути, фрагменты минифицированного JS,
  license-key-формы, `\uXXXX`-юникод-строки, hash-дайджесты и URL-парсящие regex'ы - сохраняя реальные секреты
  (кавычные пароли, backslash-DSN, ключи без цифр). ML-стейдж (`--ml`) теперь скорит и плотные минифицированные
  бандлы. Private-key-детектор требует тела ключа (одинокий PEM-заголовок больше не срабатывает).
- **Вывод**: pretty / JSON / **SARIF 2.1** / **DefectDojo**; severity по категории; **redaction**; exit-gate; `--output` в файл.
- **Конфиг**: `.prowl.yaml` (exclude/disable/custom/allowlist/output/performance). Self-contained бинарь.

## Дальше (L3 энкодер)
L2 (GBM) уже в продакшене (см. выше). Следующий слой - стейдж-3 трансформер-энкодер
([`Podric/prowl-secret-encoder`](https://huggingface.co/Podric/prowl-secret-encoder)) как опциональный
тяжёлый L2 через sidecar - для generic-секретов в многоязычной прозе. См. `MODEL_INTEGRATION.md`.
Также: верификация (liveness), Hyperscan (cgo), больше источников (S3/Docker/Slack), tree-sitter-контекст.
