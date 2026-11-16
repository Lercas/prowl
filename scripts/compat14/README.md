# Нативные контракты выпущенной 1.4.0

`fixtures/` содержит 12 неизменённых runners из тега `v1.4.0`
(`f72ea02d0295e764bec5a32359240e77192073fc`). Исходные пути и SHA-256
зафиксированы в `manifest.json`. Это исторические тестовые программы;
их устаревшие рекомендации не являются текущей документацией продукта.

Запуск из корня checkout:

```sh
python3 scripts/check_released_native_contracts.py /path/to/candidate \
  --reference-binary /path/to/rebuilt-v1.4.0
```

По умолчанию выполняются 11 suites: acceptance, quick, interfaces, pipeline,
JSON, encoding, TOML, YAML, password roles и две noise fixtures. Каждый binary
получает отдельные временные входы и PROWL_HOME. Reference выполняет исходные
проверки без адаптаций. Candidate получает только перечисленные ниже изменения
ожиданий. Runner проверяет hashes, точное число замен и неизменность AST
генераторов `corpus()`, затем сохраняет полный список замен в qualification JSON.
Байты обеих noise fixtures также проверяются по SHA-256.

## Явные адаптации кандидата

- Quick: английские UI-тексты и текущая формулировка отказа `--stdin-name`.
  Явный boolean `=false` принимается в 1.5: вместо старого отказа проверяются
  сохранение redaction, отсутствие provider verdict и отдельный incomplete
  результат с exit 2 для каждого из семи флагов. Проверки полной справки
  и нулевого summary после baseline сохранены.
- JSON: duplicate keys дают `truncated=true` и по одному `response_truncated`
  на каждый затронутый файл. Проверяются точные paths, detector/stage и отсутствие
  secret identity у markers; затем исходные assertions применяются к credentials.
- Encoding: depth limit сохраняет credential и добавляет один marker неполноты;
  проверяются оба типа, detector/stage marker и отсутствие его secret identity.
- Noise: только десять перечисленных fixture names допускают уточнение
  `generic_high_entropy` до `generic_api_key`. Значения credentials, остальные
  типы, negative/ambiguous labels и корпуса не меняются.

Модель, пороги и старые raw-score expectations не подменяются. Эта проверка
не заявляет legacy ML parity или работу с реальными provider accounts.

## Границы запуска

На macOS локальные suites запускаются под OS network deny. Interfaces и pipeline
используют проверенные собственные loopback-серверы; proxy-переменные очищаются.
На других ОС сетевую изоляцию локальных suites обеспечивает вызывающая среда,
что явно отмечается в evidence. Окружение PROWL/Git/Python очищается от внешних
настроек; оригинальные runners работают через `python -I`.

`benchmark-1.4.0.py` сохранён для аудита, но не входит в gate: он информационный,
а текущие quality/performance gates имеют отдельные pinned inputs.
`check-docker-action.sh` также сохранён: Docker factory требует отдельной
квалификации конечных image/source digests. Опциональный `--check-hook` старого
acceptance runner здесь не включён. Полный аудит изменённых Go test bodies/helpers
остаётся отдельным открытым пунктом TODO.


## Exported Go API inventory

`api_inventory.go` фиксирует AST экспортированных funcs/methods/types/values
для двух `tool/` деревьев, исключая tests и комментарии. Build tags не применяются;
это review inventory, а не доказательство поведенческой совместимости.

```sh
GOTOOLCHAIN=go1.27.4 go run scripts/compat14/api_inventory.go \
  /path/to/immutable-v1.4.0/tool tool > /new/path/inventory.json
```

Rules public matching contracts, известные API-различия и reference overlay
описаны в `wiki/Rules-API-Compatibility.md`. Старые runners в `fixtures/`
этой работой не меняются.
