# Domain Scanning

`prowl domain <host>` scans a live site for exposed secrets: it fetches the host's own HTML, extracts inline SSR/hydration state blobs, and pulls the JavaScript bundles and source-maps the page references — then runs the full detector over everything. It does **not** enumerate subdomains unless you ask for it with `--recon`.

```bash
# Scan a site you own or are authorized to test
prowl domain example.com --authorized

# Deep sweep: add subdomain enumeration (crt.sh) + Wayback history
prowl domain example.com --authorized --recon --format json

# Cap the number of fetched assets
prowl domain example.com --authorized --max-assets 100
```

This is for **authorized use only**. The scan makes real outbound requests to the target's published pages and assets. Run it against your own properties, or with explicit written authorization (a bug-bounty scope, a pentest engagement). `--authorized` is a hard consent gate — see below.

## `--authorized` is required

Without `--authorized`, prowl refuses to run and exits non-zero:

```text
refusing: pass --authorized to confirm you are authorized to scan example.com
(the scan fetches the domain's published pages/JS).
```

There is no config or environment override. You must pass the flag on every invocation. It is an explicit attestation that you are permitted to fetch the target.

## Список целей

Допустимы DNS-имя, IPv4/IPv6, `host:port` и URL `http://`/`https://`.
Порт сохраняется; для IPv6 с портом нужны скобки: `[::1]:8080`.
URL выбирает точные схему и authority. Путь, query и fragment не сканируются:
команда проверяет корень хоста и связанные ресурсы. Они также не попадают в
идентификатор цели в логах. Bare DNS-имя без порта сохраняет обход apex/`www`
с HTTPS и HTTP fallback; IP и имя с портом не расширяются на `www`.
URL с credentials, неоднозначный адрес или некорректный порт отклоняются с кодом `2`.
Весь список проверяется до первого запроса. IDN приводятся к ASCII, а `--recon`
допустим для DNS-имён без явного порта.

`prowl domain --targets hosts.txt --authorized` читает по одной цели на строку.
Пустые строки и комментарии `#` пропускаются, повторы удаляются с сохранением
первого вхождения. LF и CRLF поддерживаются. Файл должен быть обычным и содержать
корректный UTF-8: до 16 МиБ, до 10 000 непустых строк без комментариев (включая
повторы), до 4 КиБ на строку. Ошибка или превышение лимита дают код `2` до сетевого
обхода; частичный список не применяется и предыдущий отчёт сохраняется. FIFO и
другие специальные файлы отклоняются без ожидания, исправные ссылки на обычный
файл поддерживаются. Эти же правила действуют для `hermes-audit --targets` и
отдельного `prowl-hermes-audit --targets`.

## What it extracts by default

A default scan (no `--recon`) is focused on the host itself. For the apex and `www` host (https first, http fallback) prowl fetches and scans:

- **The HTML** of the landing page(s).
- **Inline state / config blobs** embedded in the page. These are SSR/hydration payloads that routinely leak API keys, tokens, and runtime config. prowl recognizes:
  - `__NEXT_DATA__`, `__NUXT_DATA__`, `window.__NUXT__` (Next.js / Nuxt)
  - `window.__INITIAL_STATE__`, `window.__PRELOADED_STATE__` (Redux-style)
  - `window.__APOLLO_STATE__` (Apollo)
  - `window.__remixContext`, `__sveltekit_*`, `window.___gatsby`
  - `window.env` family: `__ENV__`, `__RUNTIME_CONFIG__`, `runtimeConfig`, `ENV`, `env`, `CONFIG`, `_config`, `appConfig`
  - `<script type="application/json">` JSON islands, suspicious inline scripts (those mentioning `key`/`token`/`secret`/`config`/`apikey`/`env`), and `<meta>` token values
  - Для выбора блоков используются настоящие атрибуты `script` и `meta` в HTML-дереве:
    порядок атрибутов, одинарные кавычки, значения без кавычек и пробелы вокруг `=`
    не мешают извлечению. При дубликатах действует первое значение. `data-id`,
    `data-type` и `data-content` не подменяют соответствующие атрибуты.
    JSON islands распознаются по MIME type `application/json`, включая параметры.
    У `meta` проверяются оба настоящих поля `content` и `value`; их HTML entities
    раскрываются один раз. При отказе HTML-парсера доступный state извлекается из токенов,
    а отчёт остаётся неполным.
  - Перед сканированием раскрываются HTML entities и один слой распространённых
    JSON/JavaScript escape-последовательностей: `\/`, кавычки, обратный слеш,
    управляющие символы, `\xNN`, `\uNNNN` и `\u{…}`. Корректные суррогатные пары
    Unicode собираются вместе; JavaScript line continuation не добавляет символов.
    Уже полученный обратный слеш не запускает повторное декодирование.
    Некорректные или неподдерживаемые escapes, включая legacy octal и одиночные
    суррогаты без представления в UTF-8, сохраняются как исходный текст.
    Это декодирование текста найденных блоков; JavaScript сайта не исполняется.
- **Referenced JavaScript and source-maps.** prowl resolves `src`/`href` references to `.js`, `.json`, `.map`, `.env`, `.cfg`, `.config` assets on the same registrable host, then fetches them. For every `*.js` it also probes the adjacent `*.js.map` — a classic source of leaked keys when source-maps ship to production.

Размер ресурса ограничен 4 МиБ, число запросов — общим бюджетом (`--max-assets`).
Для `429/5xx` используются ограниченные повторы с задержкой. Три последовательных
отказа чтения приостанавливают запросы на 30 секунд только к сочетанию схемы, хоста
и порта, где произошли ошибки. Успешное чтение сбрасывает счётчик. Это состояние
принадлежит одному сканированию: другие порты и последующие запуски независимы.

HTML-ссылки извлекаются из настоящих `src`/`href`, в том числе без кавычек и с
HTML entities. Комментарии, `data-src` и текст внутри скриптов не считаются ссылками.
Первый HTML `<base href>` в дереве документа вне HTML `template` задаёт базовый адрес,
но итоговые URL проверяются относительно исходного семейства хостов. SVG/MathML
`base` не меняет его; HTML внутри точек интеграции SVG/MathML учитывается.
CDATA и теги, отброшенные HTML-парсером, не создают ссылки. Отказ парсера, включая
глубину вложенности свыше 512 элементов, даёт `source_error`, неполный отчёт и код `2`,
блокируя запись baseline. Прочитанный текст и доступный inline state сохраняются;
другие корни продолжают обход. Относительные ресурсы одинаковых HTML-страниц на apex
и `www` разрешаются отдельно. Предполагаемые `.js.map` сохраняют query исходного
JS-файла, а при его наличии также проверяется карта без query. Fragment удаляется
при дедупликации HTTP-ресурсов.

При разрешённом редиректе относительные ссылки разрешаются от итогового адреса
HTML-страницы, а находки содержат адрес фактически прочитанного ответа. Тело и адрес
заменяются вместе при успешном повторе; последующая ошибка или `404/410` не приписывает
сохранённый префикс другому ответу. Недопустимый адрес ответа не расширяет область
обхода: доступный текст сохраняется, а источник помечается неполным.
После успешного редиректа JS-файла карты проверяются и рядом с его итоговым адресом,
без повторной загрузки одинаковых адресов в одной группе и в пределах общего бюджета.

Загрузки остаются параллельными, но результаты и дедупликация одинаковых тел
обрабатываются в порядке списка ресурсов. Скорость ответов не выбирает адрес находки
и её fingerprint. Окно ожидающих результатов ограничено числом параллельных загрузок:
8 для ресурсов страницы/recon-путей и 6 для архивных ресурсов. Ограниченный бюджет
выбирает префикс исходного списка; доступные результаты этого префикса сохраняются.
Медленный ранний запрос задерживает выдачу следующих результатов. HTTP timeout
и отмена ограничивают это ожидание; уже обработанные находки сохраняются.

Неполный обход отмечается находками `source_error`, `truncated: true` в JSON и кодом `2`.
Это действует при недоступности отдельной цели в списке, ошибке чтения/закрытия HTTP-ответа,
превышении 4 МиБ, недоступном явно указанном JS/JSON-ресурсе и исчерпании бюджета.
Доступные страницы и их находки остаются в отчёте. Пустая успешно прочитанная страница
считается доступной. Для предполагаемых `.js.map` и recon-путей ответы `404`/`410`
означают отсутствие ресурса; ошибки транспорта и прочие неуспешные статусы не скрываются.
Inline state из прочитанного HTML обрабатывается независимо от оставшегося бюджета запросов.
Диагностику неполноты не удаляет `--verified-only`.

## `--recon` (deep sweep)

`--recon` opts into a broader, slower sweep on top of the default. It adds:

- **Subdomain enumeration** via Certificate Transparency logs (`crt.sh`).
- **Historical assets** from the Wayback Machine (`web.archive.org`) — old JS, `.env`, `.json`, config files that may still expose live keys.
- **Common misconfiguration path probes** against discovered subdomains (e.g. `/.env`, `/.env.production`, `/config.json`, `/.git/config`, `/.npmrc`, `/swagger.json`, `/firebase-config.js`, `/appsettings.json`, source-map paths).

`--recon` fetches third-party and attacker-influenceable URLs (CT/Wayback results), which is exactly why the SSRF guard below is load-bearing.

Ошибки HTTP/JSON и неверная схема каталогов CT/Wayback также дают неполный результат.
Лимиты выборки (30 поддоменов, 120 исторических ресурсов, 4000 строк CDX) обозначаются
в отчёте при отсечении или невозможности подтвердить полноту. Имена CT проверяются
до построения URL; исторические URL вне семейства целевого домена пропускаются.

## `--max-assets N`

Caps the total number of fetched assets across the whole scan (politeness + bounded work). Default `300`. Must be a positive integer. Once the budget is exhausted, discovery stops emitting new fetches.

## SSRF guard

Every outbound connection goes through a hardened HTTP client that refuses to connect to **internal address space**: loopback, link-local (incl. `169.254.169.254`), RFC 1918 private ranges, IPv6 ULA (`fc00::/7`), unspecified, and multicast. The check runs on the **resolved IP** right before connect, so it also defeats DNS rebinding (a hostname that resolves public, then internal). Redirects are capped and any cross-host redirect is refused so secret-bearing headers never leak to a third party.

To scan an **internal or self-hosted target** (a staging host on a private IP, localhost), opt out explicitly:

```bash
PROWL_ALLOW_PRIVATE_IPS=1 prowl domain internal.corp.example --authorized
```

Leave this unset in any context where the target host is untrusted.

## Output

`domain` honors the same reporting flags as [Scanning Files](Scanning-Files.md): `--format pretty|json|sarif`, `--output FILE`, `--fail-on <level>` (exit 1 if any finding meets the level), and the verification flags from [Live Verification](Live-Verification.md).

Также действуют `--min-confidence`, `--min-severity`, `--disable`, `--dedupe`/
`--no-dedupe`, `--max-per-file`, `--baseline` и `--write-baseline`; автоматические
baseline и `.gitleaksignore` читаются из каталога запуска. Создание baseline при
неполном или прерванном обходе запрещено с кодом `2`. Диагностику неполноты не
удаляют фильтры отчёта и списки подавления.

```bash
# Machine-readable, gate CI on anything high or worse
prowl domain example.com --authorized --format json --fail-on high

# Only keep secrets the provider confirms are live (see Live Verification)
prowl domain example.com --authorized --verify --verified-only
```

Findings carry the fetched URL as their path; state blobs are tagged with a `#<blob-name>` suffix (e.g. `https://example.com#__NEXT_DATA__`).

## See also

- [Live Verification](Live-Verification.md) — confirm domain findings are live credentials
- [Scanning Files](Scanning-Files.md) — the filesystem scan and shared flags
- [Rules](Rules.md) — what the detector matches
- [Security Model](Security-Model.md) — the SSRF guard and threat model in depth
- [Configuration](Configuration.md)
- [Home](README.md)
