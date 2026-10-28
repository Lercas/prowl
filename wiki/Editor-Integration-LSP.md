# Editor Integration (LSP)

`prowl lsp` runs Prowl as a **Language Server** over stdio. Editors that speak the [Language Server Protocol](https://microsoft.github.io/language-server-protocol/) connect to it and get **real-time secret diagnostics** — secrets are highlighted as you type, powered by the same detection engine as `prowl scan`.

```sh
prowl lsp
```

It reads JSON-RPC from **stdin** and writes to **stdout**, so you point your editor's LSP client at the `prowl` binary with the single argument `lsp` and a stdio transport.

Политика загружается из каталога запуска: `.prowl.yaml` (либо `.prowl.yml`/`prowl.yaml`),
автоматический импорт `.gitleaks.toml` (либо `gitleaks.toml`) с allowlist и установленные
шаблоны. Список `detectors.enable/disable` применяется к таксономии после импорта, как в
CLI. Запускайте процесс из корня нужного проекта. Ошибка выбранной конфигурации или
правил завершает `prowl lsp` с кодом `2` до обработки документов; частичная политика
или переход к дефолтам при ошибке не допускаются.

## What it does

When you open or edit a document, Prowl scans the buffer's text and publishes diagnostics for anything that looks like a secret. Each diagnostic is placed on the exact range of the match and labelled with the detector type and its provenance, e.g.:

```
possible secret: slack_token (conf 0.90, L1-regex)
possible secret: aws-access-key-id (rule)
```

Built-in taxonomy detectors carry their confidence and detection stage (`conf 0.90, L1-regex`), while findings from nuclei-style rule templates are tagged `(rule)`.

Diagnostics carry `source: "prowl"` so you can filter Prowl's findings from other language servers in your editor.

Диапазоны используют UTF-16-координаты. Для всех находок одного документа, включая
таксономию и установленные шаблоны, применяется общий индекс позиций. Он сохраняет
координаты русского текста и emoji и ограничивает повторное чтение текста при вычислении
каждой границы диапазона, в том числе в длинной строке без переносов.

### Severity mapping

Diagnostic severity is derived from the finding's category and confidence:

| Condition | LSP severity |
|-----------|--------------|
| High-impact categories (`pki`, `payment`, `db`, `cloud`, `vcs`, `ai`, `comms`, `messaging`, `ci`, `saas`, `observability`, `auth`) | Error (1) |
| `generic` category, or anything unrecognised | Warning (2) |
| Confidence `< 0.70` (unverified/generic) | Warning (2) |

So a confirmed cloud or database credential surfaces as an Error, while a low-confidence generic match surfaces as a Warning.

## Protocol support

Сервер поддерживает проверку документов через JSON-RPC 2.0 по stdio.
Каждое сообщение передаётся отдельным кадром с `Content-Length`.

| Message | Direction | Behaviour |
|---------|-----------|-----------|
| `initialize` | request → response | Возвращает `textDocumentSync: {openClose: true, change: 1, save: {includeText: true}}` и `serverInfo` (`name: prowl`). |
| `initialized` | notification | Завершает инициализацию; после него принимаются уведомления документов. |
| `textDocument/didOpen` | notification | Scans the opened document, publishes diagnostics. |
| `textDocument/didChange` | notification | Re-scans the latest full document text, publishes diagnostics. |
| `textDocument/didSave` | notification | Сразу проверяет полный текст сохранённого документа. Без `text` сохраняет текущую проверку. |
| `textDocument/didClose` | notification | Отменяет проверку документа и очищает диагностику. |
| `textDocument/publishDiagnostics` | ← notification | Emitted by Prowl with the findings for a document URI. |
| `shutdown` | request → response | Останавливает приём проверок и публикацию их результатов, возвращает `null`. |
| `exit` | notification | Завершает процесс: код 0 после `shutdown`, иначе 1. |

Клиент сначала отправляет единственный запрос `initialize`, затем уведомление
`initialized` с объектом `{}`. В `initialize` обязательны `processId` (целое
число или `null`), `rootUri` (абсолютный URI или `null`) и объект `capabilities`.
Например: `{"processId":null,"rootUri":null,"capabilities":{}}`.
До `initialize` уведомления документов игнорируются, а запросы получают ошибку
`-32002`; проверка документов начинается после `initialized`.
Повторный `initialize` и запросы после `shutdown` получают `-32600`.
Неизвестные запросы и запросы к методам уведомлений получают `-32601` и не
изменяют состояние документа. Уведомления не получают ответов.

`id` запроса — строка или целое число в пределах `int32`; отсутствие `id`
означает уведомление. Имена полей чувствительны к регистру, `jsonrpc` должен
быть строкой `"2.0"`. Дубли ключей конверта, повреждённая UTF-8/Unicode-кодировка
и смешение запроса с ответом не запускают обработчик. Ошибки используют
стандартные коды JSON-RPC и фиксированный текст без значений из запроса.
`shutdown` и `exit` передаются без `params`. После ответа на `shutdown` клиент
отправляет `exit`; поздние уведомления документов игнорируются.

Редактор должен передавать полный текст документа при каждом изменении: `change: 1`
означает **full** sync. Prowl проверяет последний полный снимок в уведомлении;
изменения с `range` или `rangeLength` не поддерживаются и не заменяют текущий текст.
Некорректные параметры, дубли ключей и повреждённая кодировка не меняют состояние
проверки. Пустой массив `contentChanges` сохраняет проверяемый текст и обновляет
версию документа; корректное
`text: ""` очищает диагностику. При открытии обязательны `uri`, `languageId`,
целочисленный `version` и `text`; при изменении — `uri`, `version` и полные
снимки в `contentChanges`. Неизвестные поля расширений допускаются.
Hover, code actions и completion не реализованы.

Уведомления открытия и закрытия должны чередоваться для каждого URI. Повторное
открытие, изменения и сохранения неоткрытого или закрытого документа игнорируются.
Версия каждого принятого изменения должна быть строго больше предыдущей:
пропуски номеров и отрицательные значения допускаются в пределах `int32`.
Старые и повторные версии не отменяют текущую проверку. Некорректное изменение
не занимает свой номер версии; после закрытия и нового открытия отсчёт начинается
с версии нового `didOpen`. Сохранение не содержит версии и принимается только
для открытого документа.

Изменения одного документа объединяются в течение 200 мс. Новый снимок сразу делает
результат предыдущего фонового скана неактуальным, даже если тот ещё выполняется.
Открытие и сохранение с полным текстом проверяются сразу; сохранение без текста оставляет
текущую проверку в силе. Закрытие очищает диагностику и отменяет публикацию старых
результатов, в том числе после повторного открытия того же URI. При завершении сервер
дожидается начатых сканов и не публикует их результаты.

Неполная проверка публикует предупреждение у начала документа с `source: "prowl"`
и машинным `code`: `document_too_large` при превышении `performance.max_size`,
`results_truncated` при достижении `detection.max_matches_per_file` или
`scan_failed` при внутренней ошибке. Лимит кандидатов общий для regex и шаблонов;
его достижение остаётся видимым после allowlist и объединения пересекающихся
находок, даже если итоговый список секретов пуст. Это консервативный признак:
сервер не может подтвердить полноту проверки после достижения лимита.
Предупреждение не содержит исходных значений; корректный новый снимок без находок
или закрытие документа очищает его. Превышение лимита размера пропускает поиск
секретов и не выдаёт пустой список как результат успешной проверки.

Тело одного кадра ограничено 16 МиБ, весь блок заголовков — 16 КиБ вместе с CRLF
и завершающей пустой строкой. Заголовки должны быть ASCII и завершаться CRLF;
обязателен ровно один `Content-Length` с неотрицательным десятичным числом байтов.
Имена заголовков нечувствительны к регистру, дополнительные корректные поля
допускаются. `Content-Type` по умолчанию использует UTF-8; поддерживаются
`charset=utf-8` и совместимое написание `utf8`.

При неверном `Content-Type` сервер потребляет ровно известную длину тела,
возвращает `ParseError` с `id: null` и продолжает со следующего кадра.
Отсутствующая, повторная, неверная или чрезмерная длина, повреждённые заголовки,
превышение их лимита и обрыв внутри кадра завершают сеанс с ошибкой транспорта
(код процесса 2). Сервер не ищет заголовки внутри отвергнутого содержимого:
при неоднозначной длине надёжно восстановить границы сообщений невозможно.
Обычный EOF между кадрами остаётся корректным завершением. Паника обработчика
перехватывается без записи исходных значений в журнал.

## Wiring it into an editor

Prowl is a generic LSP server, so configure it the way your editor configures any custom language server: a **command** (`prowl`), its **arguments** (`["lsp"]`), and a **stdio** transport. Attach it to whatever file types you want scanned (or all of them).

### Neovim (built-in LSP)

```lua
vim.api.nvim_create_autocmd("FileType", {
  pattern = "*",
  callback = function(args)
    vim.lsp.start({
      name = "prowl",
      cmd = { "prowl", "lsp" },
      root_dir = vim.fn.getcwd(),
    }, { bufnr = args.buf })
  end,
})
```

### VS Code

There is no bundled extension; use a generic LSP client extension (or a thin custom extension) configured with:

```json
{
  "command": "prowl",
  "args": ["lsp"],
  "transport": "stdio"
}
```

### Helix (`languages.toml`)

```toml
[language-server.prowl]
command = "prowl"
args = ["lsp"]
```

Then add `prowl` to the `language-servers` list of the languages you want scanned.

### General checklist

- Ensure `prowl` is on the editor's `PATH` (or give an absolute path to the binary).
- Use **stdio** transport — Prowl does not listen on a socket.
- Attach the server to the file types/buffers you care about; it scans raw text and is language-agnostic.

Diagnostics update on open and on every change. To scan whole files, directories, or git history instead of a live buffer, use [Scanning Files](Scanning-Files.md).

## See also

- [Scanning Files](Scanning-Files.md)
- [Output Formats](Output-Formats.md)
- [Configuration](Configuration.md)
- [Server Mode](Server-Mode.md)
- [Home](README.md)
