# Verifier schema: pluggable live-credential checks (data-driven, like rules)

A verifier is a YAML file describing HOW to confirm a secret is live: an HTTP request (with the
secret interpolated) plus conditional matchers on the response. AppSec teams author these and drop
them in a directory, with **no recompile and nothing hard-coded**. Run with `prowl scan . --verify`
(loads `./verifiers` by default, or `--verifiers DIR`).

```yaml
id: github                              # REQUIRED, unique
info:
  name: GitHub
  author: appsec
  reference: https://docs.github.com/en/rest/users/users
match: [github, ghp_, gho_]             # REQUIRED: detector/rule type ids OR secret-value prefixes
                                        #   this verifier applies to (substring, case-insensitive)
requests:                               # REQUIRED: probe(s); the secret is LIVE if ANY request matches
  - method: GET                         # GET (default) | POST | …
    url: https://api.github.com/user
    headers:
      Authorization: "token {{secret}}" # interpolation: {{secret}} | {{base64(EXPR)}}
    body: ""
    matchers-condition: and             # and (default) | or
    matchers:
      - type: status                    # status | word | regex
        status: [200]
      - type: word                      # optional extra conditions
        part: body                      # body (default) | header
        words: ['"login"']
        condition: or                   # or (default) | and  (combines words/regex)
        negative: false
```

## Interpolation

| token | expands to |
|-------|-----------|
| `{{secret}}` | the raw detected value |
| `{{base64(EXPR)}}` | Base64 выражения: переменные заменяются по полному имени; литералы сохраняются. |

`{{base64(secret:)}}` → HTTP Basic with the key as the username (Stripe). `{{base64(api:secret)}}`
→ Basic `api:<key>` (Mailgun).

Подстановка выполняется один раз по исходному шаблону: содержимое вставленного секрета не
интерпретируется повторно. Переменная `secret` зарезервирована; объявлять её в `extract` нельзя.
Если используемая переменная отсутствует или пуста, запрос не отправляется, а результат остаётся
неопределённым. Для Basic auth можно использовать извлечённые реквизиты, например
`{{base64(account_sid:secret)}}`; отсутствие `account_sid` не означает, что ключ отозван.

## Matching

- `status`: response code is in the list.
- `word`: substring present in `body` (default) or `header`.
- `regex`: RE2 pattern matches `body`/`header`.

`matchers-condition: and` (default) needs every matcher; `or` needs one. `negative: true` inverts a
matcher. A request with **no matchers** treats any `2xx` as live. If every request errors (network),
the result is *inconclusive* (the finding is kept, marked unverified); only an explicit provider
rejection marks it `verified: false`.

В 1.4.0 несовпадение положительных matchers само по себе не означает отказ
credential. HTTP 401 при отсутствии положительного совпадения даёт `invalid`;
403, 404, прочие неподтверждённые ответы и изменённая схема тела дают `error`.
Отказ на конкретном endpoint не доказывает глобальный отзыв ключа.
Неизвестные типы matchers, пустые условия и неверные HTTP-коды не загружаются.
Generic passwords и semantic-кандидаты провайдерам не передаются; entropy
fallback требует явного префикса токена в начале значения.

## Safety

Проверка включается явно (`--verify`). Кэш учитывает выбранный verifier, секрет и извлечённые
реквизиты, например account SID или AWS key pair. Нерелевантный текст вокруг находки не меняет
идентичность проверки. Одновременные одинаковые проверки используют один запрос; отмена
ожидающего вызова не отменяет запрос другого вызова. В кэше остаются только определённые вердикты;
сетевая ошибка, таймаут и другие неопределённые результаты допускают повторную проверку.

HTTP 5xx, ошибка чтения ответа и превышение лимита 64 КиБ оставляют результат неопределённым.
Матчеры, включая `negative`, не применяются к обрезанному ответу. Ответ ровно в 64 КиБ допустим.
Для `429`/`503` выполняется одна повторная попытка; ожидание `Retry-After` ограничено пятью секундами.
Значение заголовка не может переполнить длительность ожидания.

`--verified-only` сохраняет подтверждённые live-находки, находки с неопределённым результатом
проверки и high/critical-находки без подходящего verifier. Это позволяет не скрывать потенциальный
секрет при сбое провайдера. Ошибка загрузки хотя бы части набора verifier’ов останавливает scan
с кодом `2` до получения источника или отправки проверочных запросов.

## Lifecycle

Загрузчик читает весь YAML-поток, включая содержимое после `...`; пустые документы допустимы.
Неизвестные поля, отсутствующие `id`/`match`/`requests`/URL, повторяющиеся ID, неизвестные типы
матчеров, неверные условия/части ответа и пустые списки шаблонов блокируют загрузку.
Корректные detection templates можно хранить рядом с verifier’ами.

Лимиты чтения: 512 КиБ на YAML-файл, 8 МиБ на `MANIFEST.sha256`, 64 МиБ YAML и 10 000
YAML-файлов на выбранный каталог. Требуются обычные файлы; FIFO отклоняется без ожидания
писателя. Ссылки внутри каталога не могут выводить чтение за его корень. Явно выбранная
ссылка на отдельный файл поддерживается. Ошибка обхода каталога блокирует его загрузку.

Checksum и компиляция используют одни прочитанные байты. Повторяющиеся записи manifest
и пути вне корня отклоняются; пробелы в именах файлов сохраняются.

`verifiers manifest` заменяет checksum-файл атомарно внутри открытого корня каталога. Ссылки
и специальные файлы в месте назначения отклоняются; другие жёсткие ссылки на прежний файл
сохраняют его байты. Имена с переводами строки, возвратом каретки и обратной косой чертой
экранируются в [формате GNU checksum](https://www.gnu.org/software/coreutils/manual/html_node/cksum-output-modes.html).
Сгенерированный manifest ограничен 8 МиБ.

```sh
prowl verifiers list [DIR]       # which providers, type ids, and endpoints are loaded
prowl verifiers validate [DIR]   # parse + regex compile check; exit 1 on error
```
