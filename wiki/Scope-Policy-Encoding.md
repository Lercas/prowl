# Кодирование scope policy

`Coverage.RegisterScope` больше не считает успешным кодирование, которое теряет
байты выбранной области сканирования. Это локальное исправление для базы 1.5.0;
полный переход и финальная квалификация release artifacts остаются открытыми.

## Воспроизведённая ошибка

В одном новом локальном Git-репозитории созданы два независимых индекса. В первом
выбран `owned-\xff.env` с синтетической находкой, во втором — `owned-\xfe.env`
с обычным текстом. Невалидные байты находятся в Git index, поэтому воспроизведение
не требует поддержки таких имён файловой системой macOS.

Прежний JSON encoder заменял оба байта символом U+FFFD. Поэтому `git-index`
policy получала одинаковый SHA/HMAC, оба скана были полными, а
`remediation-check` ошибочно возвращал `comparable: true`, `absent_in_scope`.
Отдельно `json.Marshal` errors игнорировались и давали digest пустого буфера.

## Поведение после исправления

Перед хешированием проверяются исходные строки и ключи map, вложенные структуры
и указатели, включая exported members unexported embedded structs. После JSON
encoding проверяются UTF-8 и парность Unicode surrogates. Ошибки и panic
сериализации не превращаются в успешный scope.

При отказе не добавляется проблемный scope, регистрируется только
`scope_policy_failed` без исходного policy, target или текста ошибки.
Находки сохраняются; отчёт имеет `complete: false`, CLI возвращает 2.
Существующий baseline остаётся прежним, новый не создаётся. Сравнение отчётов
возвращает `inconclusive` и не подтверждает отсутствие секрета.

Для корректных plain-data policies сохраняются прежние JSON bytes и SHA/HMAC.
Легитимный U+FFFD разрешён; обычные `[]byte` кодируются losslessly через base64.
Непрозрачные `encoding.TextMarshaler` policies не сертифицируются: они способны
создавать строки, которые JSON исправляет до проверки результата. Проверка
ограничена глубиной 128 и миллионом посещённых values; превышение тоже даёт
неполный scan. Это консервативная проверка, а не новый формат представления
произвольных byte paths и не обещание поддержки любого custom Go marshaler.

## Проверки и границы

На финальном runtime source `9312b64` выполнены 20 model test/subtest passes,
полный Go-набор, model race, minimum Go 1.26.11 и lint 2.15.0. Нативная матрица —
203/203: JSON/SARIF, сохранение находок, старый false-absence, новый отказ,
защита baseline и неизменные scope/stats/diagnostics для ASCII, Unicode и U+FFFD.
Correlation — 46/46; ProwlBench совпадает с родительской версией по всем полям,
кроме hash бинарника: 1661/2094 positive hits и 61/982 negative hits.

На первой версии исправления `0ebe8ce` дополнительно прошли scoped race
model/correlation/source/scan/CLI и minimum Go для тех же packages,
coverage 90/90, source coverage 36/36, config policy 289/289, loaded policy
134/134. GOROOT digest сохранился:
`c70f3622ace725e1c60bd80998747d1b1382ba8eb82a6fa2d3d96d0e0782dec6`.
Последующее runtime-изменение ограничило byte fast path точным типом `byte`,
чтобы именованный byte type с TextMarshaler не обходил проверку; для него
добавлены отдельные slice/array regressions. Широкие первоначальные проверки
не выдаются за повторные запуски финального бинарника.

Нативное воспроизведение и quality gate выполнялись с OS-запретом всей сети.
Loaded-policy suite использовала отдельный OS-профиль с разрешённым только
loopback. Реальные provider accounts, native Windows и новые release artifacts
этой работой не квалифицированы.

Временные worktrees, процессы и loose evidence предыдущего запуска в `/tmp`
оказались отсутствующими при продолжении. Изменение восстановлено из кода и
контекста, проверки выполнены заново. Новый исходник и новые loose artifacts
расположены под `/Users/sugar/dev/`; замороженные исторические JSON не меняются.

[Машинный отчёт](evidence/1.5.0-scope-encoding-20261116.json).

Повтор нативной проверки:

```bash
/usr/bin/sandbox-exec -p '(version 1)(allow default)(deny network*)' \
  python3 -I scripts/check_scope_encoding_native.py BEFORE_BINARY CANDIDATE_BINARY
```

`BEFORE_BINARY` — неизменённая пересборка родительской базы `0043e09`.
Это сравнение с родительской базой 1.5.0, не с опубликованным архивом 1.4.0.
