# Составные credentials между файлами

CLI `scan --cross-file --verify` собирает компоненты из выбранных локальных корней
или выбранных staged blobs одного Git index (`--staged`), а также изменённых
рабочих файлов `--since REV`. В CLI `repo`/`org`
доступно связывание внутри закреплённого commit каждого репозитория.
Включение явно разрешает связывание однозначных именованных ролей внутри каждого
корня, выбранного индекса, working-tree intake или commit; выбирайте область одной связанной конфигурации.
Единственность значений сама
по себе не доказывает, что приложение использует их вместе. Режим использует
`credentialset` и `verify.Set.VerifyComponents`, не перебирает возможные пары.

```sh
prowl scan ./config --cross-file --verify --ml --format json
prowl scan --staged --cross-file --verify --ml --format json
prowl scan --since HEAD~1 --cross-file --verify --ml --format json
prowl scan ./config --cross-file --verify --index "$HOME/.prowl/index" --scope app:config
```

Без `--cross-file` поведение `--verify` не меняется. Флаг доступен у CLI `scan`, `repo`, `org`:
stdin, history/timeline, остальные remote adapters, image/mobile и MCP/HTTP/LSP этим этапом
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

## Staged Git index

`scan --staged --cross-file --verify` рассматривает выбранные изменённые staged paths
как одну явно разрешённую конфигурационную область. Companions берутся только из
этих выбранных entries: неизменённый committed файл и unstaged рабочая копия не
добавляются. Для проверки полной конфигурации используйте подходящий явный набор
входов, а не предположение, что `--staged` читает весь repository tree.

Один `git ls-files --stage -z` фиксирует mode/blob ID/stage/path до чтения объектов.
Все последующие bytes читаются по этим immutable blob IDs. Редактирование index
после первого item или во время verification не заменяет уже наблюдённые компоненты.
Новый запуск получает новую acquisition scope, даже при одинаковом listing digest.
Не существует связывания между двумя запусками или индексами репозиториев.

SHA-256 listing сохраняется в `provenance.git_index_snapshot` и в policy scope
`components-index-snapshot`; report принимает только корректный immutable hash.
Это digest наблюдавшегося index listing, не commit ID и не утверждение о рабочей
копии. В opt-in режиме Git selection/listing ограничены 64 MiB stdout до
материализации; действуют прежние component intake/literal/namespace budgets.

Роли разрешены только для regular modes `100644`/`100755`. Link text по-прежнему
сканируется обычным L1, но не представляет содержимое конфигурационного файла.
Archive members не наследуют index scope. Конфликтный/missing/oversize entry и
неподдержанный config literal оставляют неполноту, запрещают composite probes и
запись нового baseline. Empty selected index остаётся полным пустым выбранным сканом.

Native CLI — 910/910: JSON/SARIF ±ML/index, конфликтующая рабочая копия,
mutation во время provider call, отдельное последующее acquisition, запрет
заимствования committed/unselected/symlink/archive ролей, unmerged entries,
baseline guards, empty selection и subdirectory. Source unit test меняет index
после первого из 80 items и подтверждает исходные blob IDs/scope/listing digest.
Full Go, targeted race, Go 1.26.11 и lint проходят; pinned quality metrics/IDs и
полный GOROOT digest сохранены. Новый performance gate этим этапом не заявляется.
Квалификация: `evidence/1.5.0-cross-file-staged-20261116.json`.


## Закреплённый commit `repo`/`org`

```sh
prowl repo https://github.com/org/app --branch release --cross-file --verify --ml
prowl org github:owned --cross-file --verify --format json
```

Флаг явно разрешает считать выбранные файлы каждого репозитория одной конфигурацией.
Однозначность ролей сама по себе не устанавливает совместное использование приложением.
Если в repository находятся независимые конфигурации с одинаковыми namespace, выберите
подходящие exclude-фильтры или не включайте такое связывание для этого набора.
Наследование namespace, joins и overlays между файлами не выполняются.

`RepositoryContext` фиксирует commit выбранного HEAD/branch/tag до начала intake.
Producer читает `ls-tree -r -z COMMIT` и сами blobs по immutable object IDs. Изменения
HEAD и файлов checkout после фиксации не заменяют данные. Настройки `.prowl.yaml`
клонированного репозитория не управляют сканером. Provenance сохраняет commit/blob
и безопасный source URL; временный путь clone не становится report identity.

Один repository acquisition получает новый scope. Параллельные repositories в `org`
не поставляют друг другу companions, даже при одинаковых primary, display labels
или содержимом. Cache верификатора сохраняет точные компоненты каждой попытки:
LIVE одного репозитория не заменяет dead verdict другого. С `--index` primary
location IDs разрешаются в постоянном индексе; plaintext туда не передаётся.

Принимаются regular modes `100644`/`100755`; link text остаётся входом обычного L1,
но не конфигурационным companion. Archive members не наследуют repository scope.
Submodule entries отмечаются policy-пропуском и не читаются как конфигурационные файлы.
History/`--git-timeline` вместе с `--cross-file` отклоняются до clone: общая история
blobs не доказывает их сосуществование в одной revision. MCP `prowl_repo` новый
режим не включает.

Tree listing ограничен 64 MiB до материализации. Дополнительно producer ограничивает
выбранные scannable blob entries 10000 файлами и 32 MiB сырых bytes; действуют также
общие intake, literal и namespace budgets. Пути должны быть каноническими относительными
Git paths; дубликаты выбранного пути отвергаются. Ошибка metadata/object acquisition,
лимит или недостоверный config inventory сохраняют неполноту и baseline guard.
Подтверждённый пустой repository остаётся полным пустым выбранным сканом.

Native matrix — 144/144: положительные repo/org JSON/SARIF ±ML, index privacy,
выбранный старый tag, параллельные repository verdicts, отрицательные bindings,
revision failures и baseline guards. Предыдущий бинарник отвергает новый opt-in.
Прежние 910 cross-file и 99 repository checks, full Go, целевые race, Go 1.26.11
и lint проходят. Unit-проверки закрепляют commit при смене HEAD/checkout, разделяют
acquisitions и проверяют item/byte bounds и duplicate tree paths. Quality metrics/IDs
и полный GOROOT digest сохранены; новый performance gate этим этапом не заявляется.
Это локальные Git origins/forge inventory и собственный loopback verifier, не
acceptance реального provider account или hosted Git service.

Квалификация: `evidence/1.5.0-cross-file-repositories-20261116.json`.


## Выбранные рабочие файлы `--since`

`scan --since REV --cross-file --verify` использует существующую семантику Git diff:
выбирает изменённые tracked paths относительно REV и читает их текущие working-tree
байты. Это не содержимое index, не полный commit и не все файлы конфигурации.
Неизменённый companion не добавляется автоматически. Новые untracked файлы
не входят в diff; для полного дерева используйте явный конфигурационный root.
Список путей фиксируется один раз, но рабочая копия не является атомарным снимком:
байты каждого файла наблюдаются при чтении. Временный component set закрывается
после полного intake, до первого provider call; повторного чтения во время probes нет.

Каждый запуск получает новую acquisition scope. Вложенные `.git` разделяют области,
даже когда их каталоги отсутствуют в diff. Файлы с symlink в любом компоненте пути
могут читаться только внутри закреплённого `os.Root` и не передают межфайловые роли;
внешний alias оставляет неполноту. Archive members также не заимствуют scope.
Сверка file identity между stat и открытым дескриптором отклоняет замену inode;
это не обещание атомарности содержимого изменяемого файла.

Selection ограничен прежними 64 MiB stdout Git; reader принимает максимум 10000
выбранных scannable paths и 32 MiB суммарных исходных байтов. `--max-size`, excludes
и component literal/namespace budgets продолжают действовать. Неканонический или
повторный путь, недоступный файл, special file, превышение лимита и ошибка определения
границы не разрешают composite probes или новый baseline. Пустой diff — полный
пустой выбранный скан. Metadata `git_worktree:true` не утверждает commit identity;
coverage `components-worktree` фиксирует revision reader и его лимиты.

Локальная квалификация: 1044/1044 CLI checks JSON/SARIF ±ML/index, в том числе
working/index disagreement, неизменённый companion, symlink внутри/вне root,
archive/unknown roles, max-size, empty diff, subdirectory и mutation после начала
provider calls. Запросы идут только owned loopback fixture под OS network deny
с исключением localhost. Новый CI step повторяет этот runner; hosted run не выполнен.
Full Go, целевые race/min-Go/lint, шесть CGO=0 builds проходят. Pinned quality metrics
и точные IDs прежние: 1661/2094, FP 61/982. Полный GOROOT digest прежний.
Новый performance gate не выполнялся: изменения reader включаются только opt-in.
Evidence — `evidence/1.5.0-cross-file-since-20261116.json`.
