# Составные credentials между файлами

CLI `scan --cross-file --verify` собирает компоненты из выбранных локальных корней.
Включение явно разрешает связывание однозначных именованных ролей внутри каждого
корня; выбирайте корень одной связанной конфигурации. Единственность значений сама
по себе не доказывает, что приложение использует их вместе. Режим использует
`credentialset` и `verify.Set.VerifyComponents`, не перебирает возможные пары.

```sh
prowl scan ./config --cross-file --verify --ml --format json
prowl scan ./config --cross-file --verify --index "$HOME/.prowl/index" --scope app:config
```

Без `--cross-file` поведение `--verify` не меняется. Флаг доступен только у `scan`:
stdin, Git modes, `repo/org`, remote adapters, image/mobile и MCP/HTTP/LSP этим этапом
не включены. Общий пункт TODO остаётся открытым до остальных источников и форматов.

## Поддержанные входы CLI

Принимаются JSON/YAML/TOML mappings, включая вложенные объекты/таблицы и массивы,
и dotenv (`.env`, `.env.*`, `*.env`). Межфайловое связывание выполняется только
внутри одинакового точного пути namespace: `prod.service` в двух документах
обозначает одну явно выбранную область. Родитель/ребёнок и соседние namespace
не наследуют поля друг друга. Сегменты различаются: ключ `"prod.service"`
не равен вложенным `prod` → `service`. Регистр и Unicode не нормализуются.
JSON, YAML и TOML могут дополнять друг друга при одинаковых сегментах.
Dotenv принадлежит только корневому namespace.
Non-string и пустой scalar сохраняются как неизвестная роль; потребовать её из
другого файла нельзя. Объект, объявленный под именем роли, также оставляет
эту роль неизвестной в родительском namespace. Несколько YAML documents
не сопоставляются и дают неполноту.
Имена компонентных полей должны быть простыми идентификаторами,
допустимыми в resolver.

YAML scalar/mapping aliases и merge поддерживаются по явным ссылкам внутри одного
документа. Namespace определяется местом использования: `prod: *defaults`
дополняет именно `prod` в другом файле выбранного root. Совпадение anchor names
в разных документах не устанавливает связь.
Явное поле имеет приоритет над merge независимо от порядка ключей. В merge
`<<: [*first, *second]` первое определение поля имеет приоритет. Явные null,
число, пустая строка или container остаются неизвестными ролями и блокируют
заимствование строкового значения из других файлов. Дубликаты полей/merge,
неизвестные ссылки, циклы и выход за бюджет не разрешают composite probes.
Вложенная sequence в merge и alias на sequence отвергаются, как и в используемом
`yaml.Node.Decode`. Это ограничение merge operands; обычные sequences и их aliases
разрешены с индексированными namespace.

Физическая декларация primary и её alias-use сохраняют свои namespace, component
evidence и отдельные provider verdicts. Декларация сама по себе не наследует
companions из места использования; ей нужны компоненты её собственной области.
В результате отчёт может честно оставаться неполным, даже если один alias-use
удалось проверить. При одинаковом значении LIVE и dead observations сохраняются
в `occurrences` после группировки CLI.

Dotenv поддерживает `export`, literal single quotes, double quotes без expansion,
обычные bare values и комментарии. Подстановки `$...`, backticks, shell syntax и
неподдержанные escapes не исполняются и не становятся известными значениями.
Их объявленное имя остаётся неизвестным, препятствуя заимствованию чужого значения.
Duplicate keys отклоняются. Другие текстовые форматы сканируются обычным детектором,
но не устанавливают межфайловые companions; standalone verifiers могут работать.

Каждый явно выбранный root получает отдельный scope. Два отдельных file arguments
не составляют общую область — выбирайте их общий конфигурационный каталог.
Вложенный `.git` начинает новую область; архивные members не наследуют scope
внешнего каталога. Ошибка определения границы не становится разрешением связывать.

## Контракт временного индекса

Новый `credentialset.Set` принадлежит одному запуску. Источник должен передать
parser-established имя, точное literal-значение и opaque location ID. Нельзя
подставлять результаты regex-поиска по произвольному тексту, decoded JWT claims,
непривязанные printable strings или запись из исторического SQLite-индекса.

Отдельный `Scope` обозначает одну acquisition/revision, независимо от одинакового
display label или пользовательского имени `--scope`. Источник обязан определить
эту границу до передачи компонентов. Совпадение имён файлов или единственный
кандидат во всём скане само по себе не устанавливает связь разных acquisitions.

До полного drain выполняется только intake. `Seal(ctx, true)` разрешён после
успешного завершения выбранного источника; ошибка, лимит, отмена или неизвестное
покрытие означают `Seal(ctx, false)`. До seal выдавать составной credential нельзя.
CLI intake ограничен 10000 Items и 32 MiB текста; один config document — 1 MiB.
В retained snapshots допускается суммарно не более 100000 literals, включая
комментарии. При ошибке накопленный inventory освобождается до обычного L1-прохода.
Метаданные namespace ограничены суммарно 32 MiB; один путь содержит не более
64 сегментов и 4096 байт имён до JSON-кодирования. Исчерпание этого бюджета
также отменяет весь составной inventory до provider calls.
Файлы не читаются повторно после начала verification. Превышение лимита оставляет
частичные находки и явную неполноту, а не успешный составной вердикт.
Поздние observations отклоняются. Разные значения одной роли или alias конфликтуют;
повторные observations одинакового значения сохраняют отдельные location ID.
Связывание требует реально наблюдавшийся primary и все обязательные роли.
Схема проверяет literal целиком; перебора комбинаций и поиска подстроки нет.

Лимиты задаются явно: максимум 100000 observations и 32 MiB суммарных retained
строк. Это лимит содержимого, а не точное ограничение Go heap с накладными расходами.
Один literal ограничен 65536 байтами. Исчерпание бюджета и невалидная observation
не позволяют использовать оставшийся частичный inventory как однозначный набор.
После `Close` ссылки освобождаются; криптографическое стирание Go strings не обещается.
JSON-сериализация набора запрещена, диагностическое форматирование указателя скрывает
значения. Постоянная SQLite-схема и политика «не хранить исходные секреты» не менялись.

## Адаптер верификатора

`VerifyComponents` получает отдельно тип primary, установленное парсером имя поля,
значение и область. Требуемые роли и полные regex берутся из выбранного verifier,
aliases — из существующего literal-binding контракта. После однозначного разрешения
адаптер вызывает `VerifyLiteral`, сохраняя signer, транспортные ограничения и cache
по точным переменным. Неполный или чужой набор не получает старый cached verdict.

JSON/SARIF `verification.components` и `occurrences` возвращают канонические роли
и opaque location ID. Имя primary из исходного
документа не отражается: оно само может содержать другой секрет. Ни component values,
ни context в evidence не копируются. Тип без verifier остаётся unsupported; отсутствие
реального verifier для OAuth/DB не заменяется утверждением об успешной проверке.

Без `--index` ключ location ID создаётся только в памяти для текущего запуска,
без файлов состояния; такие ID не стабильны между запусками. С `--index` ID primary
совпадают со scoped location ID постоянного индекса. Наблюдение не-секретного
компонента само по себе не создаёт дополнительную строку в SQLite. Raw values
в SQLite не передаются. Ошибка связывания сохраняет exit 2 и запрет baseline,
включая `--verified-only`.

Default verification выполняется после ML. `--verify-all` и индекс сохраняют
существующую проверку до ML и приватный verdict observer; live результат не
теряется при подавлении моделью. Source-derived/JWT candidates не заимствуют роли
из конфигурационных literals, даже если их текст похож на поле.

## Проверки и оставшаяся интеграция

Тесты resolver проверяют AWS-пару, OAuth `client_id/client_secret/tenant` и
DB `host/username/password`, различные acquisition, неоднозначность aliases,
полное совпадение literal, лимиты, отмену, seal/close и параллельную работу.
Provider-adapter тесты используют подменённый HTTP transport, включая AWS SigV4
из обеих typed primary-частей, cached verdict и отсутствие probes на ошибочных данных.
Нативный runner `scripts/check_cross_file_credentials.py` дополнительно проверяет
JSON/SARIF, ML, occurrences, scoped index IDs, отсутствие plaintext в SQLite,
immutable observed intake, source boundaries и baseline guards на собственном
loopback verifier. Это локальная квалификация сканера, не live-provider acceptance.

Расширение для вложенных namespace прошло 310/310 native CLI-проверок, полный
Go-набор и целевые race/minimum-Go/lint. Проверены совпадающие сегменты в трёх
форматах, смешанные форматы, quoted dots, независимые siblings, запрет наследования,
unknown/container roles, index privacy и namespace budget до provider calls.
Обычные quality IDs и полный GOROOT digest сохранены; performance gate проходит.
Текущий отчёт: `evidence/1.5.0-cross-file-namespaces-20261116.json`.

До закрытия общего пункта остаются остальные acquisition adapters/revisions,
import relationships, другие сложные namespace и межфайловые overlays,
а также отсутствующие
реальные OAuth/DB verifiers. Текущая локальная матрица не квалифицирует эти области.
Автоматически связывать исторические plaintext-значения нельзя:
сквозной SQLite-индекс хранит только HMAC и metadata.

## Квалификация YAML relationships

Первоначальная версия opt-in policy — `yaml-explicit-alias-merge-v1`. Она записывалась только
при `CrossFile`, вместе с configured stage. Default policy и обычный scan не меняются.
Разрешение графа ограничено 100000 посещений, глубиной 64 и 32 MiB учитываемых
строк; существующие parser/intake/namespace bounds могут остановить его раньше.
Unknown и unsupported конструкции не превращаются в известные значения.

Native CLI matrix расширена до 466/466: JSON/SARIF, ML, opaque index IDs и отсутствие
plaintext в SQLite, overrides/merge order, invalid graphs и baseline guard.
Primary declaration/alias-use дали по одному LIVE и dead на одном loopback verifier;
отдельные verdicts сохранились при CLI dedupe в обоих форматах и с ML.
Это собственный stub, а не проверка реального аккаунта.

Дифференциальный fuzz строковых mappings против `yaml.Node.Decode` выполнил
80908 проверок за 11,422s при лимите 10s. Он выявил лишнее разрешение вложенной
sequence/alias на sequence в первоначальном варианте; эти формы теперь отказные
тесты. Full Go, targeted race, Go 1.26.11 и полный lint проходят.
Pinned quality metrics и ID совпали с parent: 1661/2094, FP 61/982. Полный JSON
digest GOROOT совпал: 12044 файла, 132407542 байта, 420 findings, 85 incomplete,
`c70f3622ace725e1c60bd80998747d1b1382ba8eb82a6fa2d3d96d0e0782dec6`.
Это проверка результата, не новый performance gate.

Точные source/binary hashes и логи:
`evidence/1.5.0-cross-file-yaml-relationships-20261116.json`.

## Индексированные namespace

Policy `indexed-namespaces-yaml-v2` добавляет JSON/YAML sequences, в том числе
корневые и вложенные, TOML arrays of tables и arrays of inline tables.
Путь содержит типизированные сегменты: `rows` → индекс `0` отличается от `rows` →
строковый ключ `"0"`. Scalar/null/пустые элементы сохраняют свою позицию, поэтому
последующие объекты не сдвигаются. Другая глубина массива тоже означает другой путь.

`--cross-file` разрешает связывание только одинаковых порядковых позиций внутри
выбранного root одной конфигурации. Пользователь должен выбирать файлы, в которых
порядок записей соответствует одной конфигурации. Режим не сопоставляет записи
по содержимому, имени/ID внутри объекта или сходству значений, не выполняет join
и не применяет merge/overlay между файлами. Если порядок отличается, общий root
для такого связывания выбирать нельзя.

YAML mapping/sequence aliases используют путь места применения с его индексом.
Два primary с одинаковым значением на позициях 0 и 1 сохраняют собственные companions,
location IDs и provider verdicts. Безымянный scalar внутри массива не становится
именованной ролью. Пустое/null/container поле роли по-прежнему запрещает заимствование
из другого файла. Остальные acquisition boundaries и budgets сохраняются.

Native CLI — 760/760, включая JSON/SARIF ±ML, index privacy, baseline guards,
независимые LIVE/dead verdicts двух одинаковых primary на разных индексах.
Parent binary не проходит новый положительный array-сценарий. Full Go, targeted
race, Go 1.26.11 и lint проходят; differential YAML fuzz — 30699 исполнений за
11,409s при лимите 10s. Pinned quality metrics/IDs и полный GOROOT digest выше
сохранились. Fixed-reference performance gate проходит: время +17,65% при лимите
+20%, bytes -4,52%, allocations +1,94%. Это сравнение с фиксированной policy
reference, а не измерение стоимости одного array-расширения относительно parent.
Квалификация: `evidence/1.5.0-cross-file-indexed-20261116.json`.
