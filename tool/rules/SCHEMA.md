# Prowl rule template schema

One YAML file = one rule (or several, separated by `---`). Drop files under `rules/<category>/`.
Run with `prowl scan . --rules-dir rules/`, filter with `--tags`, `--rule-severity`.

Загрузка проверяет весь выбранный набор до чтения или скачивания источника. Ошибка чтения,
неизвестное YAML-поле, неверное условие AND/OR, пустой список regex/word или неподдерживаемый
тип extractor останавливают сканирование с кодом `2`; отчёт и baseline не создаются.
Лимит 512 КиБ применяется к фактически прочитанному YAML-файлу, включая все его документы.
FIFO и другие специальные файлы не принимаются. При обходе каталога ссылки за его пределы
отклоняются; отдельный файл по ссылке можно выбрать явно.

Если в выбранном каталоге есть `MANIFEST.sha256`, его checksum проверяются перед компиляцией.
Изменённый, неуказанный или отсутствующий YAML, повреждённый manifest и повторяющиеся записи
блокируют весь каталог. Проверка и компиляция используют одни прочитанные байты; пробелы в
именах файлов сохраняются. Каталог без manifest поддерживается для локальных авторских правил.
Manifest ограничен 8 МиБ; на каталог допускается 64 МиБ YAML и 10 000 YAML-файлов.
Эта проверка действует также для `rules validate`, запросов библиотеки, MCP, HTTP-сервера и LSP.

`rules manifest` заменяет checksum-файл атомарно внутри открытого корня каталога. Ссылка или
специальный файл в месте назначения отклоняются; жёсткие ссылки на прежний файл не меняются.
Имена с переводами строки, возвратом каретки и обратной косой чертой экранируются в
[формате GNU checksum](https://www.gnu.org/software/coreutils/manual/html_node/cksum-output-modes.html).
Сгенерированный manifest ограничен теми же 8 МиБ, что и его загрузчик.

`rules validate` сообщает ошибки с кодом `1`. Команды `rules list/show/test/search/stats`
возвращают код `2`, если библиотека загружена не полностью. Эти требования также действуют
для установленной библиотеки, используемой LSP.

```yaml
id: provider-secret-name              # REQUIRED, kebab-case, globally unique
info:
  name: Human Readable Name           # REQUIRED
  author: prowl
  severity: high                      # REQUIRED: info | low | medium | high | critical
  description: One sentence on what this detects.
  reference:
    - https://provider.example/docs    # where the format is documented
  tags: provider,cloud,credentials     # REQUIRED, comma-separated, lowercase
category: cloud                        # REQUIRED: cloud|vcs|ai|payment|db|messaging|comms|ci|saas|pki|auth|generic
matchers-condition: and                # and (default) | or
matchers:
  - type: word                         # cheap pre-filter: anchor substrings (case-insensitive)
    words: [sk-, secret]
    condition: or                      # or (default) | and
  - type: regex                        # RE2 syntax only: NO backreferences, NO lookahead/behind
    regex:
      - '\bsk-[A-Za-z0-9]{32,48}\b'
  - type: entropy                      # the extracted value's Shannon entropy must be >= min
    min: 3.2
extractors:
  - type: regex                        # what to report as the secret (defaults to first regex matcher)
    regex:
      - '\bsk-[A-Za-z0-9]{32,48}\b'
    group: 0                           # explicit 0 = whole match, 1 = capture group 1
```

Если `group` не указан, выбирается первая группа захвата, а при её отсутствии — весь матч.

## Rules for good templates

- **RE2 only.** Go's regexp has no backreferences or lookaround. Use `\b`, character classes,
  bounded quantifiers `{16,32}`. Test mentally: `(?:...)`, `[A-Z0-9]`, `\b` are fine; `(?=...)`,
  `(?<=...)`, `\1` are NOT.
- **Always include a `word` matcher** with the rule's anchor token(s) (e.g. `ghp_`, `AKIA`,
  `xoxb-`). It is the speed pre-filter; without it the regex runs on every file.
- **Use `matchers-condition: and`** so a hit needs the anchor word AND the regex (precision).
- **Add an `entropy` matcher** (`min: 3.0` to `3.5`) for high-entropy tokens to cut placeholders.
- **Prefer specific prefixes/lengths** over generic `[A-Za-z0-9]+`. Bound the length.
- **Set severity by blast radius**: live cloud/db/payment/private-key = critical/high; API keys =
  high/medium; webhooks/low-impact = medium/low.
- **One provider concept per file**, named `rules/<category>/<provider>-<thing>.yaml`.

## Example with a capture group (context-anchored generic)

```yaml
id: generic-bearer-token
info:
  name: Bearer Token in Authorization Header
  author: prowl
  severity: medium
  description: A bearer token assigned in an Authorization header or config.
  tags: generic,auth,token
category: auth
matchers-condition: and
matchers:
  - type: word
    words: [bearer, authorization]
    condition: or
  - type: regex
    regex:
      - '(?i)bearer\s+([A-Za-z0-9._\-]{20,})'
  - type: entropy
    min: 3.5
extractors:
  - type: regex
    regex:
      - '(?i)bearer\s+([A-Za-z0-9._\-]{20,})'
    group: 1
```
