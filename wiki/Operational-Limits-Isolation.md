# Изоляция операционных лимитов

Настройки `limits.org_max_pages`, `limits.clone_timeout` и
`performance.verify_concurrency` принадлежат конкретному запуску CLI. Загрузка
следующего Config и построение LSP workspace не меняют эти настройки в других
запусках, уже созданных verifier Sets или выполняющихся acquisitions.

| Настройка | Built-in default | Где фиксируется |
|---|---|---|
| Org pages | 200, hard cap 4096 | Один вызов ListRepos/ListGists вместе с API/inventory scopes |
| Fetch timeout | 5 минут на попытку | Контекст acquisition: clone, repository metadata, bucket, remote image |
| Verification concurrency | 8 | Semaphore конкретного verifier Set |

CLI хранит выбранные значения в собственном value snapshot `commonFlags`.
Repo/scan/org/image передают timeout после загрузки Config. Положительный явный
`--timeout` сохраняет приоритет над `clone_timeout`; общий parent deadline и
cancellation продолжают действовать. Нулевой, отрицательный или неразобранный
config timeout сохраняет built-in default, а не значение предыдущего запуска.

LSP не выполняет provider verification или перечисление repositories и больше
не меняет соответствующие process-wide defaults при построении workspace.

## API и совместимость

Для явного выбора предназначены `forge.ListReposWithOptions`,
`forge.ListGistsWithOptions`, `verify.NewWithOptions`, `verify.LoadWithOptions`,
`verify.LoadWithPolicyAndOptions`, `verify.LoadEmbeddedWithOptions` и
`source.WithFetchTimeout`. Zero-value Options выбирает built-in defaults.
Значения передаются по значению; контекст source сохраняет immutable timeout.

Legacy `SetMaxPages`, `SetConcurrency` и `SetCloneTimeout` остаются. Они атомарно
меняют defaults только для следующих legacy вызовов. Listing фиксирует один cap
на входе, acquisition — один timeout, constructor verifier — один semaphore.
Изменение defaults во время HTTP ответа не меняет уже начавшуюся pagination.

Forge API и inventory scopes используют тот же cap, что и фактический обход.
Revision/schema scopes сохранены; неполный список остаётся incomplete с partial
inventory. Время ожидания и число параллельных вызовов не меняют загруженные
verifier definitions или их digest. Acquisition/verification failures сохраняют
существующие incomplete guards; успешный обход не доказывает remote absence.

## Квалификация и границы

На предыдущем исходнике reproduced: смена cap с 2 на 1 внутри ответа первой
страницы обрывала начатый listing после одной страницы и записывала изменённый
cap. Новый Go regression сохраняет две страницы и согласованные scopes.
Проверены независимые constructors, обновления legacy defaults под race,
реальный предел двух одновременно выполняющихся owned HTTP verification calls,
owned clone/bucket/metadata commands и CLI/LSP wiring.

Native runner `scripts/check_operational_limits_native.py` выполняет 41 проверку
CLI org/history над двумя локальными Git-репозиториями через owned loopback HTTP:
partial/default/hard caps, timeout и приоритет `--timeout`, findings, scopes,
privacy. Внешняя сеть запрещена OS sandbox. Loaded-policy suite — 134/134,
config-policy — 289/289. Реальные providers, registry и cloud bucket не вызываются.

Полный Go suite, race forge/verify/source плюс targeted CLI/LSP, Go 1.26.11 для
пяти изменённых packages и lint проходят. Шесть static builds созданы из чистого
исходника; чужие платформы не запускались. Quality gate сохраняет IDs:
1661/2094 positives, FP 61/982. GOROOT digest/performance не запускались повторно:
в этом пакете нет изменений detector/scan/rules/model runtime.

Хеши исходника, binary, проверок и native evidence:
`evidence/1.5.0-operational-limits-20261116.json`. Полный переход на 1.5.0,
финальная release factory, native foreign-platform execution и публикация
остаются отдельными незавершёнными пунктами TODO.
