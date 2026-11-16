# Подавление, JWT и encoded evidence при переходе с 1.4.0

## Восстановленные границы

Маркер allow действует только в распознанном operator comment исходного формата.
Строки, triple quotes и JS template literals не разрешают подавление. В `.env`
и Python используются hash comments, в JS — slash/block, в SQL — SQL/block,
в HTML — HTML comments. `prowl:allowed` и `xprowl:allow` не равны `prowl:allow`.
Это ограниченный lexical/parser contract, а не исполнение или полный AST каждого языка.

JWT номинируется по строковому непустому top-level `alg`, JSON-object claims и
допустимому представлению signature segment. `alg: none` не допускает signature.
Структура не проверяет криптографическую подпись, срок, issuer, audience или
права. Это `L1-structure`, не checksum proof и не `verified: true`.
Структурные JWT сохраняются при ML, как в выпущенном контракте. Внутренний
selection rank может учитывать typed child evidence, чтобы parent envelope
сохранился до привязки payload children; reported confidence не повышается
до checksum confidence и children не наследуют доказательства parent.

Настоящий checksum-факт GitHub token сохраняет severity при Base64-преобразовании,
в comments и fixture paths. Он также не доказывает, что ключ жив у провайдера.
Неполнота декодирования возвращает `base64_limit` вместо общего diagnostic code.

Alias-free YAML вновь обрабатывает 9000 flow mappings и 18000 физических scalars.
Предел inventory — 100000 values, 8 MiB retained content, исходный документ до
1 MiB, прежние node/depth budgets. Для документов с aliases сохранён отдельный
shared bound 10000 values, включая expansion. Превышение лимитов не выдаётся
за полное покрытие и не разрешает baseline.

`detectors` помечает JWT как `[structure]`; doctor явно сообщает об отсутствии
проверки подписи. README описывает текущую модель с 51 признаком. Установленная
legacy-модель, веса, пороги продукта и quality baseline не изменялись.

## Fixtures и квалификация

Четыре released test files содержат 15 тестов; оригиналы проходят на
пересобранном неизменённом теге 1.4.0. Адаптация использует immutable Pipeline,
явную квалифицированную модель и штатный порог 1.5 0,3 вместо legacy 0,5.
В YAML assertions не считаются служебные coverage markers, а короткий Unicode
password учитывает намеренно добавленный в 1.5 short-password contract.
Проверка координат использует physical inventory нового parser API.
Отдельные прежние unit fixtures исправлены: Python operator comment использует
`#`, а synthetic JWS — декодируемый signature segment.

```sh
python3 scripts/check_released_encoded_boundaries.py /path/to/prowl
```

Native CLI матрица — 232/232, с JSON/SARIF, ML и dense YAML. При квалификации
runner, detectors и doctor выполнены под OS network deny. Full Go, race,
minimum Go и lint проходят. Performance gate: +18,05% времени при лимите +20%.

Quality gate проходит: 1560/2094, FP 57/982. Три прежних positive IDs
`pb-03032`, `pb-05640`, `pb-23840` имеют signature lengths 57/45/45,
то есть некорректную длину Base64URL. Они перестали считаться JWT. Разметка,
корпус и baseline сохранены; остальные quality IDs не менялись.

Два source snapshots полного GOROOT (12044 файла, 132407542 bytes) сравниваются
по всем сериализованным результатам. Все 420 findings и 85 incomplete inputs
сохранены. В 13 уже неполных файлах меняется только diagnostic code
`results_truncated` → `base64_limit`; остальные поля идентичны. Поэтому полный
digest намеренно отличается. Helper `scripts/quality/corpus_snapshot_test.go`
копируется в `tool/internal/scan` отдельных Git exports; нужны
`PROWL_BENCH_CORPUS` и `PROWL_SNAPSHOT_OUTPUT`, затем
`go test ./internal/scan -run '^TestReleasedCompatibilitySnapshot$' -count=1 -v`.

Доказательства: `evidence/1.5.0-released-encoded-20261116.json`.
Это локальная квалификация, не hosted CI, provider-account acceptance или публикация релиза.
