# CI logs and artifact scanning

`prowl cicd` scans recent GitHub Actions or GitLab CI execution output with the same detector, rule,
ML, verification, reporting, and gating pipeline as every other Prowl source.

```sh
GITHUB_TOKEN=… prowl cicd github:owner/repo
GITLAB_TOKEN=… prowl cicd gitlab:group/project
```

The command is read-only. Credentials come from `GITHUB_TOKEN` or `GITLAB_TOKEN` only; there is no
token flag, so the value does not land in argv or shell history. `GITHUB_API` and `GITLAB_API` select
a GitHub Enterprise or self-hosted GitLab API. An internal API address still needs the explicit
`PROWL_ALLOW_PRIVATE_IPS=1` SSRF-guard opt-out.

## What is scanned

For GitHub, Prowl lists recent completed workflow runs, downloads the combined run-log ZIP, lists
artifacts for each run, and downloads their available ZIP payloads. For GitLab, it lists recent
pipelines and jobs, then reads each job trace and downloadable artifact.

Archive content is streamed from memory into the scanner; it is never extracted onto the filesystem.
ZIP/JAR, TAR, TAR.GZ/TGZ, GZIP, and Office containers are opened recursively up to three levels deep.
Binary entries are skipped through the same text and encoding check as filesystem scanning. Finding
paths retain the forge, repository, run/pipeline, job, artifact, and entry names, while JSON/SARIF
findings link back to the run or job URL.

## Bounds and selection

| Flag | Effect | Default |
|---|---|---:|
| `--max-runs N` | most recent runs/pipelines | 20 |
| `--max-artifacts N` | artifact downloads across the scan | 100 |
| `--max-download SIZE` | compressed bytes per log/artifact download | 100 MB |
| `--max-size SIZE` | uncompressed bytes per scanned archive entry | 10 MB |
| `--branch REF` | only one branch/ref | all |
| `--logs-only` | skip artifact downloads | off |
| `--artifacts-only` | skip log/trace downloads | off |
| `--timeout DUR` | overall collection + scan deadline | none |

Archive entry count, expanded bytes, integer arithmetic, nesting depth, and path names are bounded
independently. A selected log/artifact that cannot be fetched or decoded marks the collection
incomplete: partial findings are still reported, but an otherwise-clean run exits non-zero instead of
claiming that no secrets exist.

## Полнота и provenance в 1.5.0

Acquisition scope `cicd` фиксирует репозиторий, API base URL, branch/ref, лимиты
runs/artifacts/download/item и выбранные logs/artifacts. Token не входит в digest
политики. Это описание выбранного окна CI; оно не доказывает отсутствие секрета
во всей истории репозитория. `remediation-check` пока не использует remote CI scope
как доказательство отсутствия в неизменном наборе источников.

Находки получают `commit` из `head_sha`/`sha`, `run_id` и GitHub `artifact_id`.
В `digest` записывается SHA-256 исходных байтов конкретного лога или члена архива,
до преобразования кодировки; digest родительского контекста его не заменяет.
Для повреждённого ответа это digest доступного префикса; неполнота остаётся в envelope.
`source_url` и ссылка находки очищаются от URL credentials, query и fragment.
Некорректный revision не становится immutable provenance. Имена длиннее 256 байт
заменяются меткой `run-ID`; URL длиннее 2048 байт не включается в metadata.

Expired artifact не скачивается и делает выбранное окно неполным. Штатный пропуск
бинарного члена отмечается `ci_policy_skipped` без потери полноты, если другие
текстовые items успешно получены. Отсутствие всех текстовых items даёт `ci_empty`.
Неуспешная загрузка, ошибка чтения/закрытия, превышение лимитов и некорректный
листинг дают неполный JSON/SARIF, код `2` и запрещают обновление baseline.
Доступные находки и читаемый префикс повреждённого ответа сохраняются.

JSON API ограничен 32 МиБ и одной завершённой JSON-структурой; duplicate keys,
повреждённый Unicode, отсутствующая/`null` обязательная коллекция и повторные или
неположительные ID отклоняются. Страница содержит до 100 строк (`per_page=100`),
что проверяется до выделения typed API arrays. На один сбор допускается до 4096
вызовов API/download, включая отдельный вызов signed URL. Достижение этого предела
даёт `ci_request_limit`; для большого CI следует сузить runs или branch.
Стандартные redirect limits HTTP-клиента действуют отдельно.

Локальная матрица CLI JSON/SARIF ±L2 и MCP четырёх версий проходит 192/192 проверки
на собственных GitHub/GitLab-shaped API и asset server. Forge headers не переходят
на signed download. Реальные forge, права токена и live verification не проверялись.
Воспроизведение: `python3 scripts/check_cicd_contract.py /path/to/prowl`.
Evidence: `wiki/evidence/1.5.0-cicd-contract-20261114.json`.

## Redirect and secret safety

Forge download endpoints commonly redirect to a signed object-storage URL. Prowl stops the
authenticated API request at that redirect, validates the destination, and creates a new request
without `Authorization` or `PRIVATE-TOKEN`. Both requests use the SSRF-guarded HTTP transport.

Findings remain redacted by default. Use `--show-secrets` only for explicitly authorized triage.

## Examples

```sh
# Ten recent GitHub Actions runs; fail the gate on a high finding.
GITHUB_TOKEN=… prowl cicd github:acme/payments --max-runs 10 --fail-on high

# Only GitLab artifacts from main, JSON report.
GITLAB_TOKEN=… prowl cicd gitlab:platform/backend \
  --branch main --artifacts-only --format json -o ci-findings.json

# Apply ML noise filtering and confirm supported findings with provider APIs.
GITHUB_TOKEN=… prowl cicd github:acme/frontend --ml --verify --verified-only
```
