# Полнота сканирования

JSON и run-level `properties` SARIF передают общий ledger одного CLI-сканирования:
`complete`, `completion_reason`, `truncated`, `diagnostics`, `stats`, `scope`,
`filtered`, `identity_scope`, `secrets_revealed`. Версия машинного envelope
остаётся `schema_version: "1.4"`; это версия протокола, а не продукта.

`complete: false` означает, что запрошенные проверки выполнены не полностью.
CLI возвращает код 2 и отказывается записывать baseline, даже если источник
не произвёл ни одной находки. SARIF `invocations[].executionSuccessful`
отражает эту полноту. Неполнота не подавляется фильтрами находок.

`--strict` сохранён для совместимости с 1.4. В 1.5 полнота обязательна для любого
скана: отсутствие флага и `--strict=false` также дают код 2 при неполноте и
не разрешают записать baseline. `--ci` дополнительно выбирает `--fail-on high`,
если оператор не передал другой `--fail-on`. Этот severity gate не ослабляет
проверку полноты. В MCP `strict` передаётся в `tools/call`; `isError` при неполноте
поднимается при любом значении. Startup-флаги скана MCP не принимает.

Локальная проверка совместимости: `scripts/check_strict_contract.py /path/to/prowl`
(JSON/SARIF, malformed/oversize, baseline guard и четыре MCP-транспорта).


`stats.processed` и `stats.bytes` считают исходные логические Item и байты их
UTF-8 текста перед нормализацией, разбором literals и реконструкцией; производные
представления повторно не считаются. Это не число физических файлов или байтов
архива. `stats.skipped` считает события неполноты, а не уникальные пропущенные
файлы. Диагностика ограничена 1024 записями, полный счётчик остаётся в stats.

`filtered` отмечает фактическое подавление allowlist, прагмой, ML, фильтрами
отчёта, baseline, verified-only или лимитом generic-находок. Дедупликация с
сохранением occurrences сама по себе фильтрацией не считается.

CLI регистрирует scope запрошенной команды и эффективной конфигурации pipeline.
CLI pipeline policy и HTTP detection policy также включают `scan.DetectionRevision`:
ревизия меняется при изменении интерпретации исходного текста.
Filesystem, stdin, явный список файлов, Git worktree/index/history/timeline,
mobile, image и agent surface добавляют собственный scope. Он регистрируется
до чтения, поэтому пустая выбранная область не теряет профиль. Policy хранится как digest,
с identity key используется HMAC. Формат отчёта и путь выходного файла policy
не меняют. Command scope описывает запрошенный профиль, а не доказывает
неизменность удалённого источника или ревизии. Policy-пропуски (расширение,
бинарное содержимое, symlink, исключённый путь/каталог, submodule) отражаются
диагностикой без признака неполноты. Они не увеличивают `stats.skipped` и не
поднимают `filtered`, который относится к подавлению находок.

Полный аудит remote adapters (domain, CI/CD, SaaS, repo/org и bucket), immutable
revision provenance и MCP/LSP остаётся открытым. Scope локального Git-источника
описывает выбранные пути/режим, а не атомарный снимок всех изменяемых refs.

Mobile scope использует revision `1.5.0-mobile-source-v1`, исходный acquisition
selector и настройки чтения. Он не зависит от временной директории HTTP-загрузки.
Неверный ZIP, отсутствующий файл и сбой загрузки сохраняют неполный отчёт
с `mobile_acquisition_failed` и запретом записи baseline.
[Mobile provenance](Mobile-Provenance.md) описывает digest и границы доказательств.

Для `domain` revision `1.5.0-web-source-v1` отмечает provenance наблюдаемого
ответа/prefix и отдельные source-declared views. Читаемый prefix не превращает
неполную загрузку в complete. Это не полный URL inventory или доказательство
удалённого отсутствия; [контракт](Web-Provenance.md).

Локальная проверка: `python3 scripts/check_coverage.py /path/to/prowl`.
Матрица использует приватный временный PROWL_HOME, локальные фикстуры,
JSON/SARIF, файл/stdin и stdout/атомарный файл отчёта. Внешних провайдеров нет.

`python3 scripts/check_source_coverage.py /path/to/prowl` проверяет 36 сочетаний
локальных Git, APK, Docker tar и agent-фикстур с JSON/SARIF и stdout/файлом.
Docker daemon, registry, облачные credentials и установленный runtime не нужны.
