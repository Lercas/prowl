# Jira & Confluence Scanning

`prowl jira <base-url>` and `prowl confluence <base-url>` scan an Atlassian instance for leaked secrets across the **full version history** of every issue and page — not just current content. A token that was pasted into a ticket description or a wiki page and later removed still lives in the changelog / an older page version, so prowl walks every version from the first and runs the detector over each.

Both commands work against **Atlassian Cloud, Server, and Data Center** — prowl detects the deployment and selects the right API surface automatically (the Cloud and Server/DC REST paths differ).

```bash
# Cloud (auth from env — see below)
ATLASSIAN_EMAIL=you@acme.com ATLASSIAN_API_TOKEN=xxxx prowl jira https://acme.atlassian.net

# Server / Data Center, a single project, JSON output
ATLASSIAN_PAT=xxxx prowl jira https://jira.acme.com --project OPS --format json

# Confluence, only the latest version of each page (fast, skips history)
ATLASSIAN_PAT=xxxx prowl confluence https://wiki.acme.com --current-only

# Confluence Cloud, two spaces, cap the work
ATLASSIAN_EMAIL=you@acme.com ATLASSIAN_API_TOKEN=xxxx \
  prowl confluence https://acme.atlassian.net --space ENG --space OPS --max-items 5000
```

This is for **authorized use only** — scan instances you own or are explicitly permitted to test. The scan makes real authenticated requests and, by default, walks a lot of history; point it at your own Atlassian, not a third party's.

## Authentication — environment only

Credentials are read from the **environment only**, never from a flag (so they don't land in shell history, process listings, or a CI log). prowl refuses to run with no credentials.

| Deployment | Variables | Auth |
|---|---|---|
| **Cloud** | `ATLASSIAN_EMAIL` + `ATLASSIAN_API_TOKEN` | Basic `email:token` |
| **Server / DC** | `ATLASSIAN_PAT` | Bearer Personal Access Token |
| **Server / DC** | `ATLASSIAN_USER` + `ATLASSIAN_PASSWORD` | Basic `user:password` |

`ATLASSIAN_API_LOGIN` / `ATLASSIAN_API_KEY` are accepted as aliases for the Cloud pair. A Cloud API token (from id.atlassian.com) is **not** the same as a Server/DC PAT — use the one that matches your deployment. The base URL can also be given via `ATLASSIAN_BASE_URL` instead of the positional argument.

> Create a Cloud API token at <https://id.atlassian.com/manage-profile/security/api-tokens>. Use a read-only / least-privilege account where possible.

## What it scans

**Jira** — for every issue in scope:
- current fields: `summary`, `description`, `environment` (and any `--field` you add)
- every **comment** (paged in full — the search API truncates the comment list)
- the full **changelog history**: old field values are reconstructed from each change's `fromString`/`toString`, so a since-removed secret is recovered

**Confluence** — for every page in scope (current, archived, draft, and trashed where readable):
- every **version** of the page body (storage XHTML), from the first to the current

Each finding carries a direct **URL** to the issue / page version, so you can jump straight to where the secret lives. The extracted text is fed through the same detection cascade, ML filter, live-verification, and baseline as every other source — `--ml`, `--verify`, `--fail-on`, `--baseline`, `--format sarif|json|defectdojo` all apply.

## Deployment detection

prowl never guesses from the hostname. For Jira it reads `/rest/api/2/serverInfo` (`deploymentType` is authoritative on every deployment). For Confluence — which exposes no such field — it probes the path shape: Cloud serves `/wiki/api/v2`, Server/DC serves `/rest/api/*` with no `/wiki` prefix. An auth-gated `401/403` still classifies the instance, so detection works even before credentials are accepted.

## Flags

| Flag | Applies to | Meaning |
|---|---|---|
| `--current-only` | both | scan only the latest version of each issue/page (skip history — much faster) |
| `--project KEY` | jira | restrict to one or more projects (repeatable); skips project enumeration |
| `--space KEY` | confluence | restrict to one or more spaces (repeatable) |
| `--field NAME` | jira | also scan these custom field ids/names (repeatable) |
| `--max-items N` | both | stop after N scanned items (a safety cap; default is high) |
| `--workers N` | both | fetch concurrency (default 8) |

All the common scan flags — `--ml`, `--verify`, `--fail-on`, `--min-severity`, `--baseline`, `--format`, `--output` — work exactly as on `prowl scan`.

## Speed & politeness

The per-item fetches (changelog, comments, page versions) run across a worker pool, and Jira Cloud uses the batched `/changelog/bulkfetch` endpoint so history costs one round-trip per ~50 issues instead of one per issue. A `429` is honored with jittered exponential backoff. Still, a full first-to-current history walk of a large instance is a lot of requests — use `--current-only`, `--project`/`--space`, and `--max-items` to bound a first run, and prefer off-peak hours.

## Notes & limits

- **Курсоры Confluence и ссылки Jira.** Из `_links.next` читается ровно один непустой query-параметр `cursor`; фрагмент URL не входит в его значение. Некорректный URL, ошибочное percent-encoding, отсутствующий или повторный курсор дают диагностику неполного сбора; уже прочитанный контент сохраняется. Сканер повторяет исходный API-путь на настроенном хосте, используя только курсор, а не переходит по адресу из ответа. Ключ задачи Jira экранируется как один сегмент пути, а `focusedCommentId` — как одно query-значение. Исходные идентификаторы в пути находки и fingerprint не изменяются.
- **Базовый URL и ошибки подключения.** Клиент принимает абсолютный HTTP(S)-адрес с хостом и корректным портом; некорректный адрес отклоняется до HTTP-запросов. CLI по-прежнему добавляет `https://` к адресу без схемы. Userinfo, query-параметры и фрагмент базового URL удаляются, в том числе пустой `?`; context path и его percent-encoding сохраняются. Сообщения ошибок разбора адреса, создания запроса, транспорта, редиректа и очистки ответа не печатают исходные URL или произвольный текст причины. Сообщение CLI `connected` также не печатает адрес, поскольку context path может содержать чувствительные данные. Причины обёрнутых ошибок транспорта, создания и кодирования запроса, а также очистки ответа остаются доступны программно через `errors.Is/As`; для HTTP-ошибки сохраняется код статуса.
- **Текст и вложенные поля Jira.** Соседние текстовые узлы ADF соединяются в исходном порядке, даже если их форматирование различается. Абзацы, ячейки, разрывы строк и встроенные объекты сохраняют границы. Атрибуты узлов и ссылок читаются отдельно от видимого текста, включая вложенные объекты и массивы. Из выбранных пользовательских полей (`--field`) извлекаются все строковые значения с контекстом их ключей; ключи объектов обходятся в стабильном порядке. Это относится к текущим полям и телам комментариев; числовые и логические значения не преобразуются в текст.
- **Недоступная история и неполный сбор.** Ошибки получения проектов, пространств, задач, комментариев и версий, циклы пагинации и превышение лимитов попадают в отчёт как `source_error`. CLI сохраняет полученные находки, выставляет `truncated: true` в JSON и завершается с кодом `2`; записать baseline из такого сканирования нельзя. Это относится и к отключённому чтению исторических версий Confluence. Неподдерживаемый необязательный фильтр статусов (`400/404/405` на первой странице) пропускается; отказ в доступе, ошибка сервера или обрыв следующих страниц означают неполный сбор.
- **Целостность HTTP-ответов.** Лимит тела одного успешного ответа — 64 МиБ, включая запросы определения типа Confluence. Ответ читается до EOF в пределах лимита; повреждённая кодировка, непарные Unicode-escape, повторные JSON-поля, данные после JSON, отсутствие обязательных полей и ошибки чтения или закрытия тела не считаются успешным сбором. Имена динамических пользовательских полей сохраняют регистр; пустые списки и явно пустое содержимое страницы допустимы.
- **Номер версии Confluence.** Cloud и Server/DC сначала читают текущее тело без параметра `version`: номер из списка мог устареть до чтения страницы. Полный обход затем получает номера через endpoint истории, если версия текущего тела не равна 1, номер в списке больше 1 или текущее тело прочитать не удалось. Список истории может не содержать текущую версию — её тело уже сохранено отдельно. При отсутствии номера в ответе текущего тела путь содержит `@current`. Несовпадение запрошенного и возвращённого номера даёт диагностику неполного сбора; прочитанное содержимое сохраняется с возвращённым номером. Попытка чтения текущего тела учитывается в лимите 5000 чтений тел на страницу, включая неуспешную попытку. Повторные номера из перекрывающихся страниц истории не расходуют лимит повторно. Между ответами списка в памяти сохраняются не более 5000 различных номеров истории; при переполнении остаются наибольшие номера независимо от порядка страниц. Переполнение отмечает сканирование как неполное. Чтение следующих страниц списка продолжается в существующих пределах пагинации, чтобы более поздний ответ мог добавить свежие версии; ошибка чтения сохраняет доступную часть окна.
- **Состояния страниц.** Cloud передаёт состояние страницы в запрос её тела; если ответ списка не содержит `status`, используется фильтр этого списка. При отказе в объединённом необязательном фильтре `trashed/deleted` на первой странице (`400/404/405`) оба состояния проверяются отдельно. Ошибка обхода одного состояния отмечает сбор как неполный, а остальные состояния продолжают сканироваться. Cloud перечисляет `current`, `archived`, `trashed` и `deleted`; черновики перечисляются в Server/DC.
- **Cloud v1 only.** A Confluence Cloud site that exposes only the legacy v1 REST API (removed by Atlassian on 2025-03-31) cannot be scanned by the v2 walker — prowl reports this rather than scanning nothing silently.
- **Attachments, blog posts, and macro-rendered values** are not scanned yet.
- **Internal hosts.** Like domain scanning, the SSRF guard blocks private/loopback targets; set `PROWL_ALLOW_PRIVATE_IPS=1` to scan a Server/DC instance on an internal network you control.
