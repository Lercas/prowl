# TODO

## v1.5.0

Составлено по итогам ревью кода 2026-11-14. На момент ревью сборка, `go vet`, тесты и
`golangci-lint` проходили чисто — пункты ниже про продукт, релизы и архитектуру, а не про баги
в логике детекта.

### P0 — влияет на пользователей релизов

- [x] **`--ml` не работает в релизных артефактах.** Бинарники из `release.yml` и Docker-образ
  собираются с `CGO_ENABLED=0`, а `mlscore.NewEmbedded` на nocgo-сборке отказывается грузить
  модель (exit 2). При этом `AGENTS.md` и README рекомендуют `--ml` как основной режим.
  - [x] Переобучена переносимая модель, удалён cgo-путь. Признак версионирован как
    `compression_ratio_go_flate_v2`; старые zlib- и flate-v1-модели отклоняются.
    При security-обновлении `klauspost/compress/flate` до v1.20.4 изменились 12735
    признаков сжатия; модель переобучена и прошла гейт. Все 525102 вектора совпали
    между Go 1.26.11 и 1.27.4.
  - [x] Запасной вариант с cgo не требуется: статическая сборка сохранена.
  - [x] В CI добавлены parity-тесты и static-ML smoke на Go 1.26.11/1.27.4: типизированная находка,
    редактирование вывода и отказ старой модели. Кандидат прошёл гейт качества на корпусе;
    отчёт — `tool/internal/mlmodel/testdata/portable_qualification.json`. Публикация ещё не выполнена.
- [ ] **Релизный пайплайн расходится с `.goreleaser.yaml`.** Конфиг описывает архивы,
  `checksums.txt` и Homebrew-формулу, но `release.yml` делает голый `go build` в матрице и
  ничего из этого не выпускает.
  - [x] `release.yml` использует `goreleaser release --draft`. Snapshot собрал и проверил
    шесть архивов, шесть SPDX SBOM, checksums и Homebrew-формулу; static-ML smoke пройден
    на бинарнике из архива. Устаревший `brews` заменён генератором существующей формулы
    из подписанных checksums, без смены формата установки для пользователей.
  - [x] Проверка TAR/ZIP отклоняет повторные entry и каталог, пустой файл,
    ссылку или special member вместо обязательного файла. SHA-256 с корректным
    списком assets сам по себе не подтверждает состав архива: две такие регрессии
    воспроизведены на старом verifier. Шесть release-helper тестов, 22 archive
    subcase и сохранённый шестиплатформенный snapshot проходят новый гейт;
    `wiki/evidence/1.5.0-release-members-20261115.json`. Это локальная проверка
    упаковки; актуальный финальный релиз и внешняя публикация остаются открыты.


- [x] **Вернуть совместимость `--stdin-name` с 1.4.0.** В `refs/tags/v1.4.0`
  есть логическое имя для structured stdin и запрет сочетания с путями/Git-режимами;
  исходная база 1.5.0 отвечала `unknown flag`, helper `StdinNamed` отсутствовал.
  Сопоставление с пересобранным неизменённым тегом прошло 190/190: локальный
  CLI, named stdin/file JSON/YAML/TOML, UTF-16 LE/BE, настоящий PTY против pipe,
  source/flag scope и защита существующего отчёта/baseline. В 24 парах совпали
  позиции и маскирование; логическое имя не открывается и не создаётся.
  Явные `--ci=false`/`--strict=false` — документированное расширение: 1.4.0
  их отвергает, 1.5.0 поддерживает без ослабления неполноты.
  `wiki/evidence/1.5.0-cli-upgrade-20261115.json`, [границы](wiki/CLI-Upgrade.md).
  - [x] Возвращены флаг и `StdinNamed`, запрет путей/Git-режимов до конфигурации и записи
    отчёта. Имя не открывается и не создаётся; чтение, предел размера, UTF-16 и отмена
    используют общий intake. Целевые тесты CLI/source проходят.
  - [x] Восстановить обработку логических значений JSON/YAML/TOML и их исходных координат;
    в L1 проверены файловый ввод и structured stdin. L2 квалифицирован отдельным
    контрактом ниже; это не утверждение совместимости всех компонентов продукта.
    - [x] JSON: потоковый разбор строк/ключей, Unicode escapes, исходные byte/UTF-16
      координаты, fingerprint/HMAC по логическому значению, pragma внутри данных не
      подавляет находку. Ошибки, дубликаты ключей и лимиты сохраняют неполноту.
      Верификация использует только явные поля того же объекта, с отказом при
      неоднозначности; текст значения не становится новым credential binding.
    - [x] YAML/TOML: многострочные/экранированные значения, `!!binary`, декларации и
      use sites алиасов/merge с исходными evidence; TOML dotted keys, таблицы и массивы
      таблиц. Комментарии сохраняются, прагмы действуют только в настоящих комментариях.
      Неопределённые теги, циклы/междокументные алиасы, дубликаты и лимиты не разрешают
      верификацию. Проверены 18 сценариев связывания полей на локальном HTTP-сервере.
    - [x] Канонические значения + встроенный L2: устранены 30 пропусков пяти видов
      паролей (Unicode, кавычки/перевод строки, `<…>`, смешанные `${…}`/`{{…}}`).
      Нативная матрица проходит 204/204: JSON/YAML/TOML, файл/stdin, с ML/без ML,
      identity, маскирование и диагностика. Калибровка включается только по фактам
      парсера; остальные 525102 оценки побитово сохранены. Порог 0,3 и допуск
      ProwlBench не повышены; находки subset и дополнительной полной структурированной
      выборки не изменились. Четыре неполных случая остаются явно неполными.
      Отчёт — `wiki/evidence/1.5.0-literal-calibration-20261114.json`, границы и
      воспроизведение — `wiki/ML-Literal-Calibration.md`. Установленная модель и
      опубликованные артефакты не обновлялись; Python sidecar квалифицируется отдельно.
      - [x] Проверено покрытие исходного корпуса: среди 20294 положительных паролей
        всего 15 не-ASCII, 10 с угловыми скобками, 3 с `${…}`, 1 с `{{…}}`, без
        переводов строки; пять проверочных значений отсутствуют.
      - [x] Добавлены захват фактических contexts/spans из Pipeline и независимые
        синтетические положительные/отрицательные примеры. Исходные holdout-части
        закреплены, сравнение с квалифицированной моделью обязательно.
      - [x] Первая попытка переобучения отклонена: original-test precision
        0,643888 → 0,621755 и F1 0,778379 → 0,761601, за допуском 0,005.
        Модель не экспортирована и не подключена; вместо неё прошла ограниченная
        калибровка с сохранением исходного леса вне области парсера.
        Отчёт — `wiki/evidence/1.5.0-canonical-ml-attempt1-20261114.json`.

- [ ] **Восстановить выпущенные контракты 1.4.0 в базе 1.5.0.** Проверка истории
  обнаружила: `refs/tags/v1.4.0` (`f72ea02d0295e764bec5a32359240e77192073fc`)
  не является предком текущей ветки; общий предок — `61126387b51a714cd13339eefcf09d5b25cc68fd`.
  Зелёные тесты текущей ветки не доказывают совместимость обновления.
  - [ ] Вернуть CLI-контракты релиза: в том числе `--ci`, structured stdin и проверки
    областей флагов; проверить фактическое поведение, а не только наличие файлов.
    - [x] Нативная локальная upgrade-матрица с неизменённым тегом 1.4.0 — 190/190,
      включая реальный PTY, pipe, UTF-16 и guards отчёта/baseline. Проверены
      generated foreign-flag schemas 18 команд и связанные Go-контракты.
      ML/провайдеры и все remote adapters этим сравнением не квалифицированы;
      общий пункт CLI остаётся открыт. `wiki/evidence/1.5.0-cli-upgrade-20261115.json`.
    - [x] Возвращены короткие формы запуска: без аргументов — cwd или piped stdin,
      локальный путь/флаги без слова `scan`; явные команды имеют приоритет над файлами.
    - [x] Возвращён `--ci`: порог high, явный `--fail-on` сильнее независимо от порядка
      аргументов и настроек файла. Неполнота по-прежнему даёт код 2 даже с `--ci=false`.
      Флаг не включает ML, OCR или проверку у провайдера.
    - [x] Восстановлены default-порядок L2 → verification и `--verify-all`
      из 1.4.0. `--fail-on-verified` также проверяет до ML и сохраняет live-вердикт.
      Подтверждённые ответы для нового индекса собираются до ML. Постфильтрация
      сохраняет исходные binding/spans при сжатии массива; проигравший rule/builtin
      не вызывает провайдера. Нативная матрица запросов/gate/index — 48/48,
      `wiki/evidence/1.5.0-verification-order-20261114.json`.
    - [x] Возвращены provider verdict/routing/cache guards из выпущенного тега:
      несовпавший ответ кроме 401 остаётся inconclusive; generic password/API/semantic
      не отправляется по тексту значения; неоднозначный companion и 1025-й match
      отклоняются до cache lookup. Три регрессии воспроизведены до исправления.
      Native JSON/SARIF/ML/coverage/baseline — 172/172; reference provider-only — 60/60,
      порядок verification — 48/48, cross-file — 310/310. Full Go, race/min-Go/lint
      проходят; default quality IDs прежние. Строгая отчётность 1.5 сохранена.
      [Контракт](wiki/Verification-Verdicts.md),
      `wiki/evidence/1.5.0-verification-verdicts-20261116.json`.
    - [x] Восстановлены released report/literal boundaries: LIVE не скрывается
      display-фильтрами от gate, verified-only оставляет только LIVE и markers,
      oversize сохраняет max_size, malformed literals — error metadata без probes,
      contextual passwords внутри structured scalar сохраняют свои spans.
      Оригинальные 11 tests проходят на пересобранном 1.4.0; текущий native runner
      — 303/303, full Go/race/min-Go/lint проходят. Default quality IDs и GOROOT
      digest прежние; performance +15,31% при лимите +20%. Длинные bindings
      квалифицированы с текущей моделью при штатном 0,3; legacy L2 parity при 0,5
      не заявляется. [Границы](wiki/Released-Boundaries.md),
      `wiki/evidence/1.5.0-released-boundaries-20261116.json`.
  - [ ] Восстановить structured literals, безопасное связывание частей для верификации,
    provenance/coverage и ограниченную реконструкцию строк с регрессиями из релиза.
    - [x] Возвращены два неизменённых noise-корпуса: 644 примера, nomination/ML-transport
      fixtures и точные repeated occurrences через новый API. Контекст длинной строки
      смещается к пропущенному кандидату; короткий trained context сохранён.
      Оригинальные 8 tests проходят на 1.4.0. Full Go, targeted race, min-Go,
      lint и native 232/232 проходят; quality IDs прежние: 1560/2094, FP 57/982.
      [Границы](wiki/Released-Noise-and-Context.md),
      `wiki/evidence/1.5.0-released-context-20261116.json`.
    - [ ] Отдельно квалифицировать L2 на released noise positives: настоящая новая
      модель сохраняет 201/308; 107 кандидатов отсекаются. Среди 334 negatives
      находок нет; 2 ambiguous не считаются доказанными секретами. Nomination
      fixtures с recording scorer не закрывают этот пункт. Общий quality gate
      проходит, но не доказывает паритет с прежней моделью на каждом примере.
    - [x] Восстановлены released suppression/encoded boundaries: allow-маркер только
      в operator comment, JWT structure без checksum/authenticity claim, child proof
      сохраняет parent nomination без повышения reported confidence, CRC-факт
      проходит через Base64 без demotion; Base64 limit имеет свой diagnostic code.
      Alias-free YAML: 9000 maps/18000 scalars, alias expansion сохраняет 10000 bound.
      15 original tests проходят на 1.4.0; native CLI 232/232 под OS network deny,
      full Go/race/min-Go/lint проходят. Quality 1560/2094 и прежние 57 FP: исключены
      три структурно невалидных JWT, без смены baseline. Во всём GOROOT findings
      прежние; ровно 13 diagnostic codes уточнены. Performance +18,05% при +20%.
      [Контракт](wiki/Released-Suppression-and-JWT.md),
      `wiki/evidence/1.5.0-released-encoded-20261116.json`.
    - [x] Декодированный typed primary проверяется с companions собственного blob,
      без заимствования внешнего текста или соседнего blob. Base64/nested Base64,
      hex, gzip/zlib+Base64 и Base64-of-hex: CLI 228/228 с ML, JSON/SARIF,
      verify-all/index и отдельными occurrence verdicts. JWT/unbound/cross-file guards
      сохранены. Private context включён только при verification и ограничен
      32 MiB на non-linear sweep; обычный L1/ML/disclosure contract не меняется.
      Четыре released pipeline tests проходят на исходном 1.4.0 и после API-адаптации;
      дополнительные coverage markers 1.5 не скрываются в production.
      Full Go/race/min-Go/lint проходят, quality IDs и GOROOT digest прежние,
      performance +15,61% при лимите +20%. [Контракт](wiki/Decoded-Verification-Contexts.md),
      `wiki/evidence/1.5.0-verification-contexts-20261116.json`.
    - [x] Producer provenance передаётся в Item/Finding; восстановлены report HMAC
      `secret_id`, `identity_scope`, `occurrence_id`, keyed fingerprint и
      `identity init` / `--identity-key-file`. Ключ snapshot-копируется в Pipeline,
      occurrence пересчитывается после отображения исходных координат; keyed
      Git observations сохраняются до ML. Нативная JSON-матрица — 39/39,
      [контракт и границы](wiki/Report-Identity.md), отчёт —
      `wiki/evidence/1.5.0-report-identity-20261114.json`. Полный coverage envelope,
      run-level SARIF и заполнение всех метаданных источниками остаются открыты.
    - [x] Возвращены `occurrences` при стандартной дедупликации. Сохраняются
      вложенные группы и evidence; финальный entry образа представляет группу,
      live-вердикт и наиболее сильные severity/confidence не теряются. Лимит 2048
      даёт явную неполноту и не позволяет перезаписать baseline. Без ID одинаковые
      координаты не доказывают общую физическую запись; keyed ID различает
      повторные TAR-entry без раскрытия внутреннего номера. Нативная матрица
      JSON/SARIF, файл/stdin, keyless/keyed, ML и локальный image tar — 71/71;
      `wiki/evidence/1.5.0-occurrences-20261114.json`.
    - [x] SARIF result properties сохраняют report identity, occurrences, evidence,
      provenance и имеющийся verification; alert fingerprint и UTF-16 координаты
      сохранены. Полный coverage envelope и run-level metadata остаются открыты.
    - [x] Подробные verdicts проходят из verify в Finding/occurrences и JSON/SARIF:
      status, verifier, capabilities, checked_at, безопасный error reason. Кэш
      сохраняет время исходной попытки; unsupported/skipped не получают ложный
      timestamp. Ошибка провайдера или обязательного binding даёт неполноту и
      код 2, новый baseline не записывается. Нативная loopback-матрица — 49/49;
      `wiki/evidence/1.5.0-verdicts-20261114.json`.
    - [x] CLI передаёт общий coverage ledger в JSON и run-level SARIF: полнота,
      диагностика, stats, scope, filtered и reveal/identity metadata. Исходный
      Item считается один раз до производных представлений; неполнота источника
      без находок даёт код 2 и блокирует baseline. Нативная матрица — 76/76;
      [контракт и границы](wiki/Scan-Coverage.md), отчёт —
      `wiki/evidence/1.5.0-coverage-20261114.json`.
    - [x] Локальные acquisition scopes восстановлены для Git worktree/index/history/
      timeline, явного списка файлов, mobile, image и agent surface. Пустая
      выбранная область сохраняет профиль, policy-пропуски получают диагностику
      без ложной неполноты. Panic file-list теперь даёт source error вместо
      успешного пустого результата. Нативная локальная матрица — 36/36;
      `wiki/evidence/1.5.0-source-coverage-20261114.json`. Remote adapters,
      immutable revision provenance и аудит MCP/LSP остаются открыты.
    - [x] Mobile APK/IPA: отдельный namespace архива/member, SHA-256 сырых байтов
      member до декодирования, безопасный исходный URL вместо временного пути
      и приватные acquisition selectors. Keyed occurrences и индекс различают
      повторные ZIP-entry; display/ML path сохранён. Ошибка acquisition даёт
      неполноту и блокирует baseline; printable strings не устанавливают companions.
      Нативная матрица JSON/SARIF, ML, индекс и owned HTTP — 102/102;
      [контракт и границы](wiki/Mobile-Provenance.md),
      `wiki/evidence/1.5.0-mobile-provenance-20261115.json`.
    - [x] Image producer provenance: acquisition namespace, manifest/config snapshot,
      raw member digest и полностью прочитанный layer diff ID. Финализатор обновляет
      occurrence ID после EOF/close; повторные TAR-entry разделены в индексе,
      одинаковые labels не заимствуют чужой flatten-index. JSON/SARIF и occurrences
      сохраняют final-image status; сырой build instruction — только с disclosure.
      OCI metadata cache не принимает content-address mismatch.
      - [x] Реализация и native matrix 400/400, report identity 39/39,
        occurrences 71/71, web 181/181, mobile 102/102; full Go/race/min-Go/lint,
        quality и полный GOROOT digest подтверждены в изолированном checkout.
      - [x] Повторная квалификация 2026-11-16: fixed performance gate против
        `e0f05cd…` в трёх парах пройден: время +17,09%, B/op −4,53%, allocs/op −1,60%.
        Full Go/race/Go 1.26.11/lint и пять native-матриц повторены после утраты
        временных артефактов; quality IDs совпали с main, GOROOT digest прежний.
      [Контракт и границы](wiki/Image-Provenance.md),
      `wiki/evidence/1.5.0-image-provenance-20261116.json`.
    - [x] Восстановлен `--reconstruct` для ограниченных статических JS/TS-выражений:
      парсер и 279 Node-reference случаев из выпущенного тега, исходные evidence и
      координаты, общий бюджет до ML, исходный контекст верификации. Нативная
      матрица файл/stdin × ML/без ML — 24/24; неизвестные/изменяемые bindings
      не исполняются и не подставляются. Отчёт —
      `wiki/evidence/1.5.0-reconstruction-20261114.json`. Полная интеграция
      provenance/coverage и остальные контракты 1.4.0 остаются открыты.
  - [ ] Проверить остальные разошедшиеся компоненты: MCP/LSP, источники, отчёты,
    correlation, integrity шаблонов и release checks. Намеренные замены ML/cgo
    не откатывать: сохранить квалифицированную Go-flate-v2 модель и security-обновления.
    - [x] Integrity выбранных rules/verifiers: native CLI candidate и неизменённый
      пересобранный тег 1.4.0 — по 182/182 под OS network deny. Проверены
      installed/explicit selection, повреждённые manifests/files, list/validate,
      baseline guard и bundled override. Целевые Go-тесты — 258 passed, один
      opt-in corpus test пропущен; runtime integrity sources совпадают с тегом.
      Remote update/install и подписи релиза остаются отдельно.
      [Контракт](wiki/Template-Integrity.md),
      `wiki/evidence/1.5.0-template-integrity-20261116.json`.
    - [x] HTTP worker вновь возвращает полный coverage envelope и `/capabilities`,
      сохраняя immutable Pipeline 1.5.0. Неподдерживаемые request stage/disclosure
      поля отклоняются, batch count ограничен до материализации всей коллекции.
      Пустой batch сохраняет policy scope; отмена, parser failure и лимиты не
      сертифицируются как complete. Нативный worker на loopback — 57/57;
      `wiki/evidence/1.5.0-http-contract-20261114.json`. MCP/LSP остаются открыты.
    - [x] Восстановлены MCP transport negotiation/discovery, structuredContent,
      отмена request ID и EOF, два активных скана, бюджеты времени и stdout.
      Строгий JSON отказывает при неоднозначности до subprocess, пути сохраняются
      буквально; доступны `reconstruct` и `verified_only`. Нативная stdio-матрица
      четырёх версий — 80/80, `wiki/evidence/1.5.0-mcp-contract-20261114.json`.
      Этапы LSP, `bundled`, `strict` и opt-in `semantic` описаны ниже;
      semantic в compare требует отдельного фиксированного набора кандидатов.
    - [x] Восстановлены линейные Base64 source spans, padding, цепочки evidence
      и несколько внутренних вхождений, в том числе повтор одного значения.
      Сохранены текущие gzip/zlib/hex и их fail-closed проверки; baseline не
      записывается при лимите decode. Нативная матрица — 197/197;
      [контракт](wiki/Encoded-Secrets.md),
      `wiki/evidence/1.5.0-base64-spans-20261114.json`. Модель не менялась.
    - [x] Закрыты выявленные LSP/noise-регрессии выпущенного тега. Общий Pipeline
      сохраняет отдельные вхождения, source ranges, pragmas и allowlist; восстановлены
      локальный code-value filter, точный контекст и 25 provider-шаблонов, а также
      `sensitive: false` для публичных метаданных. Встроены 175 шаблонов с manifest.
      Корпус: 308 положительных + 334 отрицательных примера; 2 неоднозначных не
      квалифицируются. В 10 случаях сохранён новый тип 1.5 `generic_api_key`
      вместо прежнего entropy-only типа при том же точном диапазоне.
      Настоящий LSP stdio: 2258/2258; полный Go-набор, targeted race, lint и
      Go 1.26.11. Evidence: `wiki/evidence/1.5.0-lsp-contract-20261114.json`.
      Конкретные редакторные плагины ещё не проверены.

    - [x] Восстановлен встроенный rules/verifiers snapshot и `--bundled` в CLI,
      MCP tools/call, LSP и version. Без установленных наборов используются
      175 шаблонов и 84 верификатора; ошибки выбранных overlays не скрываются
      fallback. Сохранены `--rules-only`, изоляция agents, конфигурация и identity key.
      Локальная нативная матрица — 64/64; provider calls в ней не выполняются.
      Evidence: `wiki/evidence/1.5.0-bundled-contract-20261114.json`.

    - [x] Возвращён CLI/MCP `strict` как флаг совместимости с 1.4. В 1.5
      неполный скан всегда возвращает код 2 и не пишет baseline, даже при
      `--strict=false`. `--ci` сохраняет severity default high, явный `--fail-on`
      имеет приоритет. Локальная CLI/MCP-матрица — 79/79, targeted CLI tests и lint.
      Evidence: `wiki/evidence/1.5.0-strict-contract-20261114.json`.

    - [x] Восстановлен opt-in `semantic` в CLI сканирования и MCP tools/call,
      immutable Pipeline и source-backed evidence, включая JSON/TOML/YAML.
      Local endpoint pinning, remote opt-in + HTTPS, запрет redirects и строгий
      ответ модели; ошибки/лимиты сохраняют неполноту и baseline guard.
      Локальная transport/span-матрица со stub — 101/101; полный Go-набор,
      targeted race, lint и Go 1.26.11. Качество реальной модели и retention с L2
      не квалифицированы. Контракт: `wiki/Semantic-Discovery.md`, evidence:
      `wiki/evidence/1.5.0-semantic-contract-20261114.json`.
    - [x] `compare --semantic`: один intake и один кандидатный проход, raw/kept
      projections до/после local L2 с bounds 100000 строк / 32 MiB. Ошибка score,
      неполнота, timeout и budget отменяют источник и не дают процента подавления.
      Одно inference на наблюдаемый chunk; файл не читается повторно после модели.
      Исправлен подсчёт повторных fingerprint с `--no-dedupe`; provider/sidecar
      опции не выдаются за возможности compare. Нативная матрица — 31/31.
      `wiki/evidence/1.5.0-compare-contract-20261114.json`.
    - [x] Связаны report/post-filter флаги `compare`: pretty/JSON и атомарный `-o`,
      одинаковые confidence/severity/disable фильтры до dedupe. Неподдерживаемые
      baseline/CI/gate/cap и `--ml=false` отклоняются до intake. Help и shell
      completion согласованы с parser. Нативная матрица — 52/52, full Go, race,
      lint и Go 1.26.11 проходят. При ошибке нет процента и замены готового файла.
      `wiki/evidence/1.5.0-compare-report-20261115.json`.

    - [x] Возвращены CLI `correlate` и `remediation-check` для keyed JSON envelope.
      Shared immutable metadata links не выдаются за направление распространения;
      отсутствие, сохранённый verdict и закрытие исправления разделены.
      Проверены 46/46 нативных сценариев с отчётами текущего CLI и Git-объектами,
      а также strict JSON, file/aggregate/array-row budgets и противоречия verdicts.
      Полный Go-набор, correlation race, lint и Go 1.26.11 проходят.
      Контракт — `wiki/Report-Correlation.md`, evidence:
      `wiki/evidence/1.5.0-correlation-contract-20261114.json`.

    - [x] Восстановлены офлайн `selftest` и проверка выбранных rules/verifiers в
      `doctor`, без provider requests. Selftest использует общий in-memory intake
      и Pipeline, все 7 синтетических carriers/controls; `--ml` использует локальный
      resolver с порогом 0,3 и отказывается скрывать повреждённую выбранную модель.
      Восстановлен пропущенный CLI guard: `--bundled` несовместим с явными
      `--rules-only/--rules-dir/--verifiers`. Нативная матрица — 43/43;
      `wiki/evidence/1.5.0-offline-contract-20261114.json`. Это smoke,
      не измерение точности ML или доступности реальных провайдеров.

    - [x] Восстановлены source maps и строковые module imports в `domain` через
      существующий bounded ordered fetcher, с retry/redirect и общим бюджетом.
      Inline/внешние карты дают исходный текст и безопасное provenance; ошибки
      обязательных карт и лимиты делают отчёт неполным и блокируют baseline.
      Матрица CLI JSON/SARIF ±L2 и MCP четырёх версий — 135/135;
      `wiki/evidence/1.5.0-source-map-contract-20261114.json`.
      Indexed maps/VLQ не разворачиваются; полный аудит remote adapters остаётся открыт.
    - [x] Web producer provenance: digest наблюдаемого ответа/prefix и отдельного
      state/source-map текста, безопасные URL в SARIF, URI отдельных представлений
      и private selectors в keyed identity/индексе. Повторные имена map sources
      разделены; ошибки не отражают URL/response в stderr. Декодирование state
      не создаёт verifier companions, включая замену builtin более сильным rule.
      Нативная матрица — 181/181; source maps/MCP — 135/135, mobile — 102/102.
      Full Go, race, минимальный Go 1.26.11 и lint проходят; обычные quality IDs
      и GOROOT digest прежние, fixed performance gate пройден.
      [Контракт и границы](wiki/Web-Provenance.md),
      `wiki/evidence/1.5.0-web-provenance-20261115.json`.

    - [x] Docker Action и Git runtime: root и `tool/` descriptors, UID/GID владельца
      workspace и приватный SARIF `0600`, фиксированные `--strict --bundled --reconstruct`.
      CLI image остаётся nonroot `65532:65532`, содержит Git и доверяет только `/src`.
      `inputs.path` после `--` не включает флаги; disclosure-регрессия воспроизведена
      и закрыта. Шесть локальных образов: 48/48 Linux/arm64 и 48/48 Linux/amd64
      под эмуляцией, включая static ML, staged и history с ML. CI gate добавлен;
      hosted runner, GHCR/tag и публикация этим не подтверждены.
      `wiki/evidence/1.5.0-docker-action-20261116.json`.
    - [x] Восстановлены причины неполноты Git index и архивов, читаемый plaintext
      fallback повреждённого архива и context cancellation в unpack. Возвращены
      выпущенные source/unpack boundary regressions. Нативная матрица — 17/17:
      staged/conflict/empty/subdirectory, depth/malformed, reconstruction и link cap;
      JSON/SARIF ±L2 сохраняют находку, redaction и baseline guard при ошибке архива.
      Evidence — `wiki/evidence/1.5.0-source-boundaries-20261114.json`.

    - [x] Восстановлены каталог pre-commit и нативная оболочка: сборка в checkout
      хука, скан immutable staged blobs вызывающего репозитория, bundled rules и
      reconstruction; статический Go без cgo. Реальный pre-commit 4.7.0 — 14/14,
      с partial staging, возвратом рабочей копии, unmerged/empty index и redaction.
      Добавлен CI gate; `wiki/evidence/1.5.0-precommit-contract-20261114.json`.
      Docker hook закреплён на будущем v1.5.0, его итоговый образ ещё не квалифицирован.

    - [x] CI/CD: восстановлены acquisition scope и commit/run/artifact provenance,
      добавлен digest исходных байтов member/log. Ошибки/expired/empty collection
      остаются неполными до baseline; binary policy skips не считаются потерей текста.
      Читаемый prefix сохраняется при ошибке HTTP; JSON/rows/ID/request bounds
      блокируют неоднозначные или бесконечные листинги. CLI JSON/SARIF ±L2 и MCP
      четырёх версий — 192/192; полный Go-набор, race, lint и Go 1.26.11 проходят.
      `wiki/evidence/1.5.0-cicd-contract-20261114.json`. Scope описывает выбранное
      CI-окно; remote absence/remediation и остальные remote adapters остаются открыты.

    - [x] `repo`/`org`: общий repository snapshot с HEAD/ref-set digest,
      безопасным source URL и стабильными selection scopes вместо временного checkout.
      HEAD не приписывается историческим blobs. Default full history включает tags;
      выбранный branch/tag сохраняет свою область. Ошибка metadata сохраняет текст
      и блокирует baseline; URL credentials/query исключены из вывода и scopes.
      Нативная матрица — 99/99, полный Go-набор/race/lint/Go 1.26.11 проходят.
      `wiki/evidence/1.5.0-repository-contract-20261114.json`.
      Наблюдаемый forge inventory квалифицирован ниже; remote absence остаётся открытым.

    - [x] `bucket`: стабильные acquisition/selection scopes, source URL и SHA-256
      исходных байтов объекта, включая UTF-16 и содержимое архивов. Контейнерный
      digest не подменяется digest члена; новые acquisition boundaries не наследуют
      чужую revision metadata. Ошибки cloud CLI скрывают stdout/stderr, сохраняют
      exit status и частичный текст; baseline при неполной загрузке защищён.
      Нативная матрица — 113/113; repo/org nonregression — 99/99;
      полный Go-набор/race/lint/Go 1.26.11 проходят.
      `wiki/evidence/1.5.0-bucket-contract-20261114.json`.
      Cloud inventory/identity/version и remote absence не подтверждаются.

    - [x] `detectors.disable`: регистр, дефис/подчёркивание и окружающие пробелы
      обрабатываются одинаково для taxonomy/import/custom и rule templates в CLI/LSP.
      Шаблоны отключаются до кандидатов и verification; report IDs не меняются.
      `detectors.enable` сохраняет прежний exact-match контракт.
      Доказательства: `wiki/evidence/1.5.0-config-disable-20261114.json`.

    - [x] `org` forge inventory: отдельные API/observed-set scopes, включая
      empty/partial и org→user fallback; токены и provider identity не приписываются.
      GitHub/GitLab pagination сохраняет отбор, Bitbucket next остаётся opaque
      в пределах endpoint. Строгий JSON, preallocation row bounds и ограниченный
      page cap; транспортные/URL/close ошибки не отражают приватные детали.
      Нативная GitHub/GitLab матрица — 241/241; полный Go-набор, race forge,
      Go 1.26.11 и lint проходят. `wiki/evidence/1.5.0-forge-inventory-20261114.json`.
      Добавлен CI gate для нативных repo/forge/bucket/config матриц.
      Полный remote inventory, права токена и absence/remediation не доказываются.

    - [x] Jira/Confluence: восстановлены acquisition/deployment scopes и coverage
      ledger для object/collection/budget ошибок. В provenance сохранены source URL,
      наблюдаемая version label и доступные object/event IDs без выдуманного digest
      или immutable revision. Empty/connect failures дают неполный JSON/SARIF,
      защищают baseline и записываются incomplete в индекс.
      Cloud-shaped native CLI ±L2 — 157/157; доказательства:
      `wiki/evidence/1.5.0-atlassian-contract-20261114.json`.
    - [x] Atlassian tenant-qualified occurrence/index: логический URI до детекции
      разделяет продукт, transport, origin/context и экранированную локальную метку.
      History event ID отделяет одинаковые даты; неизвестные event/comment IDs
      сохраняют текст с неполнотой и baseline guard. Legacy обычные/keyed baseline
      не подавляют новый namespace; совпадающее value сохраняет общий secret/value ID.
      Нативная Cloud-shaped матрица — 230/230, включая повторный scan и один индекс
      с двумя tenant. `wiki/evidence/1.5.0-atlassian-identity-20261114.json`.

### P1 — архитектура CLI

- [x] **Декларативные флаги по командам.** `flags.go` задаёт имена, алиасы, области команд,
  типы значений, проверки и help. Включены вложенные команды `rules`/`verifiers` и отдельная
  безопасная область `hermes-audit`. `flagVal`/`hasFlag`/`stripValueFlags` и глобальный
  список `knownFlags` удалены из runtime.
  - [x] Единая таблица для парсинга, валидации и help. Поддержаны `--key=value`, повторяемые
    опции, явные boolean-значения, разделитель `--` и флаги между позиционными аргументами.
  - [x] Чужой флаг отклоняется до чтения источника и записи отчёта; подсказки ограничены командой.
  - [x] Парсер возвращает `error`; единственный `os.Exit` — в `main`, после `runCLI`.
    Явные CLI-дефолты сохраняют приоритет над конфигом. CLI-suite пройден, покрытие — 60,8%.
- [x] **Разнести `cmd/prowl/main.go`**: входная точка и диспетчеризация занимают 98 строк;
  обработчики вынесены в `org.go`, `domain.go`, `repo.go`, `rules_cmd.go`, `report.go`,
  `scan_cmd.go`, `serve.go`, `doctor.go`, `setup.go`. Покрытие CLI — 61,0% против 55,6%.
  CLI race-тесты, vet, lint и 80/80 E2E на Go 1.25 прошли. Help сохраняет описания и
  подкоманды, а имена и области флагов генерируются из схемы. См. `wiki/Command-Line.md`.
- [x] **`scan.Pipeline` вместо длинных сигнатур.** Зависимости собраны в `scan.Options`;
  `Pipeline.Run` и `Pipeline.Findings` принимают только контекст и входные элементы.
  CLI хранит Pipeline вместе с политикой отчёта в `preparedScan`; сервер и Hermes
  используют тот же API. Сохранён порядок финализации образа перед дедупликацией и лимитами.
- [x] **Убрать глобальный `scan.SetRevealSecrets`.** Раскрытие значения и контекста задаётся
  при создании Pipeline. Проверены перекрывающиеся сканы с разными политиками, HTTP single/batch
  и повторная загрузка CLI-конфига. Full Go suite, race по затронутым пакетам, vet, lint
  и static-ML smoke на Go 1.25 прошли. Остальные глобальные настройки пока не изолированы.

### Удобство работы в терминале

- [x] **Отчёт не выдаёт диагностику за находки.** Нечитаемый путь, пропуск по `--max-size`
  и обрезанный результат выводятся отдельным блоком «scan incomplete» с причиной по-человечески;
  в счётчик находок не попадают. Исправлено «1 findings».
- [x] **Справка по разделам.** Флаги команды сгруппированы (Input, Output, Exit code, Noise
  control, …), колонка выровнена, длинная метка занимает свою строку. Список команд разбит по
  назначению, сверху — три примера быстрого старта. Всё по-прежнему строится из `cliFlags`.
- [x] **`prowl completion bash|zsh|fish`.** Скрипт генерируется из таблицы флагов: команды,
  подкоманды, флаги только своей команды, значения перечислимых флагов. Bash и zsh проверены
  в работе; fish — только сравнением с таблицей (локально не установлен).
- [x] **Подсказки на терминале.** После отчёта в stderr: время скана и, если есть находки,
  следующие шаги (`--verify`, `--show-secrets`, `# prowl:allow`, `--write-baseline`). В конвейере,
  файле и машинных форматах вывод не меняется. Строки `loaded rule templates` и дублирующая
  `scan complete` на терминале ушли на уровень debug.
- [x] **Имена типов в `--disable`.** Написания через дефис и подчёркивание (и регистр)
  считаются одним типом: `--disable aws_access_key_id` снимает и `aws-access-key-id` из шаблона.
  Сами имена в отчёте не менялись, чтобы не сломать baseline и потребителей JSON.
  `detectors.disable` в `.prowl.yaml` по-прежнему сравнивает точно.
- [x] **Строка кода под находкой** в pretty-отчёте на терминале. Маскируются все найденные
  на строке секреты; строка показывается, только если файл на диске совпадает со снимком скана
  (номер строки и видимый префикс маски), иначе не показывается вовсе. В конвейер и файл не идёт.
- [x] **Прогресс долгого скана.** Через секунду после старта на терминале появляется строка
  «scanning… N files · X MB · Ns», перед отчётом стирается. Считаются элементы, переданные
  сканеру, для всех команд на `scanItemStream`.
- [x] **`prowl init`**: стартовый `.prowl.yaml` (проходит `config validate`) и pre-commit-хук
  `prowl scan --staged --ci` в каталоге хуков репозитория (учитывает `core.hooksPath`).
  Существующие файлы не перезаписываются. Baseline не создаётся — команда подсказана в выводе.
- [x] **Опечатка в пути.** До старта печатается `path not found: srcc; did you mean 'src'?`.
  Скан при этом идёт и падает с кодом 2 как раньше: ранний отказ ломал контракт индекса
  (`TestIncompleteIndexedScanCannotBecomeDiffBaseline` — неполный скан должен быть записан).
- [x] **Один язык интерфейса — английский** (решение владельца). Переведено около 100 строк:
  справка и флаги, ошибки, вывод `index`/`diff`, `identity`, `correlate`, `selftest`, сообщения
  MCP и LSP, причины блокировки `guard`. Правило записано в `AGENTS.md`. Русский остался в
  данных детекта и в подсказке OCR-модели (`internal/ocr/client.go` — это запрос к модели,
  а не текст для пользователя).
- [x] **`detectors.disable` в конфиге** — та же свёртка написаний, что и у `--disable`.
- [x] **Прогресс для стадий без потока элементов** (2026-11-15, `cmd/prowl/progress.go`): общий
  индикатор стадий вместо привязанного к `prowl scan`. Показывает `cloning repository…`,
  `listing repositories…`, `loading image…`, `scanning and verifying…` со счётчиком файлов и
  временем; работает во всех командах скана, в том числе когда отчёт уходит в файл или конвейер
  (условие — stderr на терминале). Запись лога сначала стирает строку прогресса.
  - [x] Квалификация и точечные исправления: реальный Unix PTY 36/36,
    раздельные stdout/stderr, файл/pipe, ширина 30 колонок и отмена трёх стадий.
    Исправлены перенос строки, стирание новой стадии старым callback и зависший
    индикатор при отмене image input; lazy image loading отслеживается до drain.
    Full Go, CLI race, lint, Go 1.26.11 и шесть сборок проходят.
    [Контракт](wiki/Terminal-Progress.md),
    `wiki/evidence/1.5.0-terminal-progress-20261115.json`.
- [x] **Отказ до скана, а не после** (2026-11-15): несуществующий `--baseline`, каталог для
  `--output` / `--write-baseline` проверяются в preflight — раньше скан отрабатывал целиком и
  результат терялся при записи.
- [x] **Мелочи** (2026-11-15): подсказка «did you mean» не предлагает посторонние короткие имена
  (`nope` → `e`) и считает перестановку соседних букв одной опечаткой; `prowl help <нет такой>`
  завершается с кодом 2 и подсказкой; ошибки до настройки лога не содержат цветовых кодов вне
  терминала; флаги `--semantic*`, `--bundled`, `--strict`, `--verify-all`, `--reconstruct`,
  `--identity-key-file` разложены по разделам справки (тест не даёт новому флагу `scan` остаться
  без раздела); `live-verification enabled` переведено в debug.
- [x] **Опечатка в `--disable`** (2026-11-15): идентификатор, не совпавший ни с одним детектором,
  но отличающийся от настоящего на опечатку, даёт предупреждение с подсказкой — раньше он молча
  ничего не отключал. Далёкие от известных имена не трогаются (свои пакеты правил).
- [x] **Скан без единого детектора больше не «чистый»** (2026-11-15): `prowl scan . --rules-only`
  без `--rules`/`--rules-dir` проверял все файлы нулём детекторов и выходил с кодом 0; теперь код 2
  с объяснением (`scan` и `repo`). `--tags`, не совпавший ни с одним шаблоном, даёт предупреждение.
- [x] **Скрытое фильтрами видно** (2026-11-15): `--min-severity`, `--min-confidence`, `--disable`
  сообщают, сколько находок убрали (`report filters hid findings`), — раньше отчёт просто писал
  `no secrets found`. Итоговая строка `scan complete` не считает диагностику неполноты находками
  (отдельное поле `incomplete_inputs`).
- [x] **Проверки детекторов во всех командах скана** (2026-11-15): отказ при нуле детекторов,
  предупреждения об опечатке в `--disable` и о `--tags` без совпадений работают в `repo`, `org`,
  `image`, `mobile`, `cicd`, `domain`, `jira`/`confluence`, `compare`, `serve` (общий
  `detectorPreflight`), а не только в `scan`.
- [x] **Понятные ошибки Git-режимов** (2026-11-15): `--since <нет такой ревизии>` сообщает
  `bad revision '…'` вместо `exit status 128`; `--staged` / `--since` вне репозитория —
  `needs a git repository` вместо `exit status 129`.

### Новые возможности (то, что на рынке есть только в enterprise или отсутствует)

- [x] **Сквозной индекс секретов между источниками.** Явное `--index DIR --scope NAME`,
  приватный SQLite-каталог и локальный ключ; существующий path-specific fingerprint сохранён.
  - [x] `value_fingerprint`: версионированный HMAC-SHA256 точного значения, без типа и пути;
    присутствует в JSON/SARIF только с индексом. Исходные значения и контекст в SQLite не пишутся.
  - [x] `prowl index`: число исторически наблюдавшихся позиций по всем источникам и областям;
    разные query-локаторы, области репозиториев и повторные позиции правил не сливаются.
  - [x] `prowl diff`: новые / не наблюдавшиеся значения и места; сравнение только полных
    снимков одной области. Последний неполный скан не заменяется более старой зелёной парой.
  - [x] Датированные переходы live → dead / dead → live и наблюдаемый интервал после первого
    live в периоде. Подтверждённые ответы сохраняются до ML; исчезновение не означает отзыв.
    Работоспособность ключа-замены не утверждается. Контракт — `wiki/Secret-Index.md`.
  Нативные Unix-тесты, race, минимальный Go и шесть сборок CGO=0 проверены локально;
  Windows ACL CI подготовлен, его внешний запуск остаётся частью релизной квалификации.
- [ ] **Аудит ключей, «публичных по замыслу»** (для `domain` и `mobile`): проверять не «жив ли
  ключ», а «правильно ли он ограничен». Отдельный opt-in `--audit-public --authorized`
  отделяет наблюдение прав от обычного `--verify` (его профили не гарантируют read-only).
  - [ ] Supabase: anon-ключ + таблицы без RLS.
    - [x] Bounded HEAD для явных public-schema таблиц с publishable/узко
      распознанным legacy anon key. Same-object URL/ref, без user session,
      RPC/записи/тела ответа; scoped checks и неполнота при сбое.
      Публичный ключ сам по себе не считается утечкой.
      CLI 40/40 под проверенным OS network deny, owned HTTP pipeline,
      full Go/race/lint/min-Go и два fuzz-прогона проходят.
      [Контракт](wiki/Supabase-Public-Audit.md),
      `wiki/evidence/1.5.0-supabase-audit-20261115.json`.
    - [ ] Подтверждение RLS на разрешённом аккаунте, другие форматы привязок,
      custom/self-hosted endpoints и schemas. HEAD не доказывает отсутствие RLS.
  - [x] Credential baseline не скрывает изменившиеся public-права Firebase/Algolia
    и не принимает идентичности audited-находок; сохранены occurrences,
    JSON/SARIF и severity gate. Целевые Go/race/min-Go и lint проходят.
  - [ ] Firebase: открытые RTDB / Firestore / Storage.
    - [x] Read-only наблюдения RTDB root shallow, configured Storage root list и явно
      выбранных Firestore collections `(default)`. Google key не отправляется;
      scoped `checks`, данные ответов не сериализуются, частичный сбой сохраняет
      наблюдённый доступ и делает покрытие неполным. Поддержаны flat config,
      static JS и документированная Android-связь google-services.json.
      CLI 39/39 под OS network deny; full Go/race/lint/min-Go и fuzz проходят.
      [Контракт](wiki/Firebase-Public-Audit.md), `wiki/evidence/1.5.0-firebase-audit-20261115.json`.
    - [x] Firebase XML: Android `<resources>` с `google_api_key` / legacy crash key
      и строковый root-dict `GoogleService-Info.plist`. Компоненты принадлежат
      одной конфигурации и точному исходному значению; чужие равные ключи,
      вложенные plist, дубликаты, динамические ресурсы и повреждение не заимствуют
      поля. Неустановленная XML-привязка — `inconclusive` без запроса.
      XML entities/CDATA, лимиты и отмена проверены; DTD не загружается.
      APK/IPA CLI 34/34 под OS network deny, owned HTTP для трёх сервисов,
      full Go/race/min-Go/lint и финальный fuzz 28281 проходят. Комментарий
      внутри string проверен отдельно: совпадение значения не даёт ему владеть
      CharData. Обычные quality IDs и
      полный GOROOT digest прежние. `wiki/evidence/1.5.0-firebase-xml-20261115.json`.
    - [ ] Другие Firebase формы/точки чтения и подтверждение на разрешённом
      реальном аккаунте; отказ root/list не считается доказательством всех rules.
  - [ ] Google API key: отсутствие ограничений по referrer / API.
  - [ ] Algolia: admin-ключ вместо search-ключа (ACL).
    - [x] Read-only self-ACL для пар из одного объекта JSON/YAML/TOML: отдельный
      `public_key_audit`, после ML, фиксированный GET, bounded/cache-aware запросы,
      строгий ответ и неполное покрытие при неоднозначности. JSON/SARIF/occurrences
      сохраняют результат без `verified:true`. CLI 32/32, full Go/race/lint и Go 1.26.11;
      [контракт](wiki/Public-Key-Audit.md), `wiki/evidence/1.5.0-public-key-audit-20261115.json`.
    - [x] Статические JS/ES-module привязки одного объекта или одной `const`-декларации:
      AST с исходными byte spans, без JS runtime и source-map I/O, один ленивый
      разбор на item после ML. 72 Node-reference случая; успешный HTTP fixture и
      отказ от неоднозначных привязок. CLI 37/37 с проверенным OS network deny,
      full Go/race/lint/min-Go, fuzz и scoped govulncheck проходят;
      `wiki/evidence/1.5.0-public-js-bindings-20261115.json`.
      Обычный scan без opt-in не меняется. Установленная локальная модель с 49
      признаками не заменялась; квалификация использует явную модель с 51.
    - [ ] Специфичный TypeScript/JSX, XML/plist/dex и другие связи;
      точное отличие встроенного admin от широкого custom ACL.
  - [ ] Только read-only пробы; под тем же `--authorized`, что и `domain`.
- [ ] **Сборка составных учётных данных из разных файлов.** Связывать части, найденные в разных
  местах: AWS key ID + secret, `client_id` + `client_secret` + tenant, хост БД + пользователь +
  пароль. Сейчас верификатор ищет пару только в контексте рядом с находкой. Строится поверх
  сквозного индекса.
  - [x] Подготовлены bounded ephemeral resolver и provider adapter: непрозрачные
    acquisition scopes, seal после полного intake, exact literal roles, запрет
    конфликтов/перебора и plaintext persistence. Unit-схемы AWS/OAuth/DB и mock HTTP
    с AWS SigV4 прошли на начальном этапе adapter-only; CLI-интеграция проверена ниже.
    [Контракт и остаток интеграции](wiki/Cross-File-Credentials.md),
    `wiki/evidence/1.5.0-credential-components-20261116.json`.
  - [x] `scan --cross-file --verify`: bounded intake flat JSON/YAML/TOML и dotenv,
    отдельные root/nested-repo scopes, запрет archive/JWT/derived borrowing,
    исходные literals до provider calls, existing ML ordering, JSON/SARIF/occurrences
    evidence и scoped index IDs. SQLite не получает raw values; неполнота блокирует
    baseline даже с `--verified-only`. Локальная native qualification —
    `wiki/evidence/1.5.0-cross-file-runtime-20261116.json`.
  - [x] Вложенные JSON/YAML/TOML namespaces: точные сегменты пути внутри acquisition,
    без наследования между parent/child/siblings, с межформатным дополнением.
    Quoted dots не становятся вложенным путём; unknown/container roles блокируют
    заимствование. Namespace metadata ограничены 32 MiB до provider calls.
    Native CLI — 310/310; full Go, targeted race/min-Go/lint проходят.
    Default quality IDs и полный GOROOT digest сохранены; финальный performance
    gate +14,94% времени при лимите +20%, без изменения модели/порогов.
    `wiki/evidence/1.5.0-cross-file-namespaces-20261116.json`.
  - [ ] Остальные source adapters/revisions, import/overlay relationships,
    arrays/aliases и сложные namespace
    и реальные OAuth/DB verifiers; текущий local-filesystem этап их не закрывает.
- [x] **Хронология наблюдений в Git.** Явный `--git-timeline` для `scan/repo/org` включает
  историю; все достижимые ветки и зафиксированный HEAD, события относительно первого родителя.
  - [x] Коммиты появления и повторного появления: hash, родители, имя автора, авторская дата
    и дата коммита; обычная правка blob при сохранении значения не разрывает период.
  - [x] Коммиты прекращения наблюдения и `in_head`; неполное/непрочитанное покрытие не
    подтверждает отсутствие. Подавление кандидата ML/allowlist не становится удалением.
  - [x] Интервалы между датами коммитов; JSON `git` и SARIF `properties.git`. Это история
    распознавания, а не точное время публикации или подтверждение отзыва у провайдера.
  Семантика веток, переименований, контейнеров и пределы — `wiki/Git-Timeline.md`.
- [x] **Поверхность AI-агентов.**
  - [x] `prowl agents`: известные MCP/Claude/Cursor/Codex-конфиги и текстовые транскрипты;
    home и история оболочки только по явным флагам. Метки продукта/вида в JSON/SARIF,
    маскирование и совместимость с индексом; неявные проектные подавления игнорируются.
  - [x] `prowl guard`: локальная проверка payload до prompt/tool, без ML/провайдеров,
    самоподавления прагмой или отражения значения. Адаптеры Claude Code и Cursor,
    отказ с блокировкой на ошибке/лимите; шаблоны обязательной host failure policy.
  Нативные stdin/stdout-тесты и шесть сборок CGO=0 проверены; конфиги настоящих клиентов
  не менялись, установка и приёмка host отдельно. Границы — `wiki/Agent-Security.md`.

Отложено на следующую версию: офлайн-анализ токена до обращения к провайдеру (включая защиту
от canary-токенов при `--verify`) и вывод типа секрета по месту использования.

### Движок детекта

Базовая реализация сохранена в Git: пакет `internal/linewin` — каждая регулярка запускается
не по всему файлу, а по строкам вокруг своего обязательного литерала. Применимость доказывается
автоматически по синтаксическому дереву; что не доказано — идёт прежним полным проходом.
Подключено к встроенной таксономии (`detect`) и шаблонам правил (`rules`). На исходниках Go
(156 МБ), исторический замер: 34,4 → 6,4 с в один поток, находки идентичны.

- [x] **Байтовые окна для минифицированных файлов.** AST даёт конечную длину совпадения
  или непоглощаемые разделители. Бюджет исходного окна — 8 КиБ; пересекающиеся окна
  объединяются. Совпадения на искусственной границе перепроверяются по полному тексту.
  Без доказательства остаётся строковый путь. На 12044 файлах GOROOT — ноль расхождений
  у встроенного детектора и bundled-правил; ProwlBench subset и однострочный JS дают
  идентичные находки до/после. См. `wiki/Regex-Windows.md`.
- [x] **Оставшиеся полные проходы.** DeepSeek, PEM и восемь ранее неограниченных regex
  шаблонов получили байтовые планы: алфавит повторов + бюджет конечных частей. Планируются
  421/421 regex шаблонов. `telegram_bot_token`, `discord_bot_token` и семь regex
  Heroku/MongoDB/Mailgun/Telegram получили структурные якоря: обязательный разделитель
  после ASCII-класса длиной не менее восьми символов. Проверка GOROOT: 12044 файла,
  1129 совпадений встроенного детектора и три находки правил, ноль расхождений.
  `basic_auth_header` использует обязательный `@` для URL-ветви вместо частого `//`,
  сохраняя `Authorization:` для заголовка. На 453 regex изменился только этот набор
  якорей; комментарии без учётных данных не создают окна. Полный проход сохраняется
  при недоказуемых границах и исчерпании бюджета; длинные URL не обрезаются.
- [x] **Аллокации в `rules.Engine.MatchN`**: потоковый Unicode lowercase без копии файла;
  общий Aho-Corasick индекс для всех word-условий, включая negative/OR. `Matcher.eval`
  использует готовые флаги; временные boolean-массивы переиспользуются отдельно на вызов.
  На синтетическом 1 МиБ/128 active rules: медиана 67,6 → 2,32 мс, 1,11 МБ → 48,5 КБ.
  При отсутствии якорей — 0 allocs после прогрева. Это не скорость всего сканера.
- [x] **Честные цифры скорости в README.** Убрано универсальное обещание «~310 МБ/с» и
  отсутствия аллокаций; указана зависимость от корпуса и режимов. Исторические сравнительные
  таблицы явно отделены от квалификации переносимой L2-модели 1.5.0.
- [x] **Бенчмарк на корпусе в CI**: `BenchmarkFindingsCorpus` сравнивается с фиксированной
  базой 1.5.0 в трёх чередующихся парах на GOROOT/src. Порог медианы времени — +20%,
  B/op и allocs/op — +25%; пустой корпус и неполные метрики отклоняются. Плановый
  `corpus-equivalence` сравнивает окна и полный проход детектора и bundled-правил.
  Локальный runner и ошибки входов проверены; внешний CI ещё не запускался.
  Процедура и ограничения — `wiki/Performance-CI.md`.
  - [x] **Пройти фиксированный performance gate на текущем исходнике локально.**
    Main `71a0a99` равен изолированному `157518e`; против фиксированного `e0f05cd`
    три пары дают медианы 11,886 / 9,994 с: time +18,93%, B/op −10,36%, allocs −7,47%.
    Пороги +20%/+25%/+25%, модель и база сохранены. Полный digest находок и coverage
    совпадает с текущим JWT-родителем на 12044 файлах: 419 находок, 85 файлов с неполным
    покрытием в обоих состояниях. ProwlBench сохраняет точные списки пропусков/FP:
    1556/2094 и 57/982. Полный Go, затронутый race + финальные gate-race, minimum Go,
    lint и native 45/45 проходят. Запас времени небольшой; внешний CI ещё требуется.
    `wiki/evidence/1.5.0-performance-recovery-20261115.json`.
- [x] **Восстановить допуск ProwlBench:** точный фильтр bcrypt не позволяет трактовать
  полный хеш как plaintext `generic_password`. На subset recall сохранён — 1580/2094,
  T4-FP снизился с 63 до 61/982 и проходит старый порог 0,058 + 0,005. Удалены ровно две
  ошибочные находки; остальные не изменились. Порог и baseline не повышались.
  Проверено с пустым временным `PROWL_HOME` и встроенной моделью; старые установленные
  модели корректно отклоняются. Это локальный гейт subset, а не допуск публикации релиза.
- [x] **Глубина декодирования** (2026-11-14, `detect/decode.go`): hex, вложенный base64 (до 3
  слоёв), gzip/zlib внутри base64, `user:password` в base64 под ключом `auth`/`_auth`
  (docker `config.json`, `.npmrc`). Base64 без «секретного» имени на строке теперь тоже
  раскрывается, но только ради точного типизированного попадания (уверенность ≥ 0,9).
  Квалифицировано в чистой копии: subset recall 1585/2094, T4-FP 61/982; прежний гейт
  проходит. Распаковка ограничена 256 КиБ, вложенность — тремя слоями и общим бюджетом
  32 внутренних попыток на внешний blob. Обрезанный читаемый поток помечает скан неполным.
- [x] **Нормализующие представления** (2026-11-14, `detect/views.go`): JSON внутри JSON-строки
  (`\"`, `\/`, `\uXXXX`, `\xNN`), склейка строк `"…" + "…"` (в том числе через перенос),
  блочные скаляры YAML (`key: |`, `key: >-`), markdown-выделение вокруг присваивания
  (`**Password:** x`).
  Строгие лимиты: 1 МиБ нормализованного текста и 4096 конструкций; исходные позиции,
  маскирование и признак неполного результата сохраняются. См. `wiki/Decoding.md`.
- [x] **Percent/HTML-представления для типизированных секретов.** Однослойные `%HH` и
  полные HTML-сущности, исходные позиции и логическая идентичность, совместный бюджет
  нормализации. Generic-пароли с неустановленной семантикой не преобразуются автоматически.
- [x] **Целостность сжатых кандидатов.** Зафиксированы регрессии на короткий/низкоэнтропийный
  повреждённый поток с секретом и на бинарный обрезанный префикс. Эвристика энтропии,
  скрывавшая эти случаи, не принята; консервативная неполнота остаётся видимой.
- [x] **Литеральные `String.fromCharCode(...)`.** Числа, литеральный spread-массив и
  `apply(null/undefined, [...])`, Number/ToUint16 и UTF-16 без исполнения JavaScript.
  Типизированные значения и generic-значения под явным секретным именем, исходные позиции,
  маскирование и HMAC. Общий бюджет нормализации; повреждение UTF-16 остаётся неполнотой,
  изменённое при восстановлении значение не выдаётся. См. `wiki/Decoding.md`.
- [ ] **Что по-прежнему не раскрывается**: generic-значения percent/HTML без знания
  потребителя, перевёрнутые и разряженные строки; шифрованный JWE не расшифровывается.
- [x] **Встроенный детектор в JSON payload JWT/JWS.** Контейнер не перекрывает вложенные typed
  и именованные generic-секреты; bare entropy claims не становятся находками.
  Поддержаны JSON whitespace, unsigned claims, escaped/duplicate fields и bounded
  nested JWT. Исходные Base64-диапазоны, ML-контекст, маскирование и HMAC сохранены;
  claims не заимствуют companion bindings для verify/public audit.
  Ошибка JSON/Unicode и лимиты сохраняют неполноту. См. `wiki/Decoding.md`.
  CLI 45/45, полный Go suite, race, lint, min-Go и fuzz проходят; subset 1556/2094,
  FP 57/982, модель и пороги прежние. Source/evidence:
  `wiki/evidence/1.5.0-jwt-payload-20261115.json`.
- [x] **Передавать JSON payload JWT также template engine.** Внешние и bundled-правила
  получают исходный JSON, а при escapes — дополнительно логические строки. Сохраняются
  исходные координаты и evidence, HMAC, ML-контекст, фильтры правил и приоритет checksum.
  Вложенные JWT внутри escaped scalar имеют отдельную байтовую проекцию. Raw/normalized
  rule hits расходуют общий оставшийся бюджет; claims не дают companion bindings для
  verify/public audit. Main `c265d0f` = изолированный `f63ed66`: полный Go, race,
  минимальный Go, lint, два fuzz-теста (24899 исполнений), native 62/62 + прежние 45/45.
  Quality сохраняет точные ID пропусков/FP (1556/2094, 57/982); фиксированный performance
  gate проходит три пары: time +18,78%, B/op −10,33%, allocs −5,36%, пороги прежние.
  `wiki/evidence/1.5.0-jwt-rules-20261115.json`.
- [x] **Непрямые представления самого JWT-контейнера.** Связать их декодированные payload
  со всеми исходными преобразованиями и координатами, включая внешнее кодирование
  и реконструированные выражения; проверить builtin и template engine вместе.
  - [x] **Parser-proven реконструкция JS/TS.** `--reconstruct` сохраняет builtin/template
    children, включая пароль, который прежде терялся как JS identifier. Evidence
    переносится из виртуальной строки на доказанное исходное выражение с цепочкой
    преобразований и отдельными spans литералов/bindings до ML и наблюдений индекса.
    Обычный некавыченный JS и shadowed decoders сохраняют прежние ограничения.
    Main `140fac5` = изолированный `d4378e9`: full Go, scan race, min-Go, lint,
    fuzz 15332 и native 46/46 (concat/array join/atob/URI, JS/TSX, ML, bundled/external,
    occurrences, SARIF, HMAC/private index, incomplete baseline). Quality IDs сохранены;
    фиксированный gate +17,82% времени, B/op −10,64%, allocs −5,39%, пороги прежние.
    `wiki/evidence/1.5.0-reconstructed-jwt-20261115.json`.
  - [x] **Линейный Base64 вокруг JWT.** Четыре варианта алфавита/padding, до трёх
    внешних слоёв плюс payload, source proof из исходных квантов для builtin/templates.
    Прямые JWT обнаруживаются первыми; общий бюджет и cache физических контейнеров
    запрещают сброс глубины через другой путь. Claims-aware duplicate сохраняет
    запрет companion bindings при выключенном JWT output; логический контейнер
    удаляется из приватных метаданных и без template engine. Base64-данные читаются
    независимо от opt-in исполнения реконструкции JS. Main `c45fc23` = `e0d9ad4`:
    full Go, detect/scan race, min-Go, lint, fuzz 19461, native 168/168; точные Quality
    IDs прежние (1556/2094, 57/982), GOROOT digest сохранён. Фиксированный gate:
    time +18,72%, B/op −11,26%, allocs −4,33%; модель/reference/пороги сохранены.
    `wiki/evidence/1.5.0-base64-jwt-20261115.json`.
  - [x] **Hex и смешанные hex/Base64-обёртки JWT.** До трёх hex-слоёв с общими
    бюджетами, линейная проекция 2:1 и именованные decode steps для builtin/templates.
    Coarse non-linear duplicate заменяется claims-aware находкой только по доказанному
    исходному диапазону; независимые вхождения и запрет companion borrowing сохранены.
    Main `e9ad714` = изолированный `9d42c7b`: full Go, detect/scan race, min-Go, lint,
    fuzz 9085, native 174/174 (пять форматов, ML, bundled/external, реконструкция,
    HMAC/private index, masking и incomplete baseline). Quality IDs и полный GOROOT
    digest сохранены; фиксированный gate time +18,20%, B/op −11,05%, allocs −3,25%.
    `wiki/evidence/1.5.0-hex-jwt-20261115.json`.
  - [x] **Gzip/zlib вокруг JWT.** Base64/hex и смешанные цепочки передают payload
    builtin/templates с отдельными inflate steps, проецируемыми на весь исходный поток.
    До трёх распаковок, общий бюджет 8 МиБ сохранённого output и 4096 попыток;
    отдельные позиции одинаковых JWT внутри потока сохранены в cache. Checksum/обрыв/
    превышение лимита сохраняют неполноту и запрет baseline. Реконструкция сохраняет
    claims, но не снимает неполноту исходного повреждённого compressed fragment.
    Main `1df9458` = изолированный `0a5867d`: full Go, detect/scan race, min-Go, lint,
    два fuzz-теста (55685 исполнений), native 180/180, включая ожидаемые incomplete
    случаи. Quality IDs и полный GOROOT digest сохранены; фиксированный gate:
    time +18,23%, B/op −10,27%, allocs −3,13%, пороги/reference/модель прежние.
    `wiki/evidence/1.5.0-compressed-jwt-20261115.json`.
  - [x] **Нормализованные views JWT.** Escape/concat, percent/HTML и статический
    `String.fromCharCode` передают claims builtin/templates с общей source proof;
    длинный носитель расширяется за пределы 256-байтового окна с сохранением разделителя.
    Общие бюджеты 1 МиБ, 4096 constructs и трёх уровней; JSON escaped scalars имеют
    приоритет в cache, а внешнее поле не заменяет claims child при отключённом JWT.
    Main `273d103` = изолированный `2a37396`: full Go, detect/scan race, min-Go, lint,
    fuzz 27153, native 136/136 и 180/180 регрессионных compressed-сценариев. Обычная
    нормализация может стать primary для прямой конкатенации; AST proof сохранена
    в occurrences. Quality IDs и GOROOT digest прежние; фиксированный gate time
    +17,69%, B/op −3,41%, allocs −2,42%, модель/reference/пороги не менялись.
    `wiki/evidence/1.5.0-normalized-jwt-20261115.json`.
- [x] **Таблицы Markdown/Jira.** Вертикальные key/value-строки, Markdown-заголовки с
  выравниванием и Jira `||…||`; целые значения с разделителями и экранированным `|`.
  Имя столбца передаётся ML; исходные позиции, маскирование и HMAC-идентичность сохранены.
  Ресурсные лимиты передаются как неполнота. Границы и квалификация — `wiki/Decoding.md`.
- [x] **Именованные присваивания** (2026-11-14, `detect/named.go`, включено): `SECRET_KEY=<hex>`,
  `os.environ["API_KEY"] = …`, `'api_key' => …`, `*_TOKEN=`, `API key: …`, `Basic <base64>` в
  коде (проверяется декодированием в `user:password`), пароли с `;,'` внутри кавычек. Полный
  `prowlbench` без ML: 13804 → 14340 из 16552 (+536), ложные 750 → 760 из 8051.
  С ML: 12609 → 12793 (+184), ложные 480 → 481. В обоих полных замерах одинаковые
  четыре маркера неполного декодирования; это сравнение, а не полный допуск корпуса.
- [x] **Проверить именованные присваивания с ML-стадией**: встроенная переносимая модель
  с пустым временным `PROWL_HOME`; subset 1608/2094 против 1585/2094 до включения,
  ложные 61/982 без изменений, индекс включён/выключен. Старый пользовательский файл
  модели не менялся. Baseline и пороги прежние; локальная квалификация не заменяет релиз.
- [x] **Значения короче 20 символов под именем токена или ключа** (2026-11-15).
  Добавлены сгенерированные ASCII-значения длиной 12–19 под явным секретным именем:
  присваивания, сравнения, таблицы, статические строки и JWT claims, включая escapes.
  Энтропия 3,5 и остальные проверки случайности сохранены; короткие hex, проза,
  metadata/public/CSRF-поля, выражения и custom taxonomy с минимумом 20 не расширены.
  Полный `prowlbench`: L1 +19 положительных / +3 отрицательных случая;
  ML +13 / +0 без потерь прежних положительных ID, те же четыре неполных случая.
  Quality IDs прежние: 1563/2094 и 57/982. Оценка «~60» не является точным
  числом подтверждённых секретов; значения короче 12 и низкоэнтропийные токены
  остаются вне контракта. Gate time +16,33%, пороги/модель/reference прежние.
  Границы — `wiki/Decoding.md`, `wiki/evidence/1.5.0-short-keys-20261115.json`.
- [x] **Пароли короче 6 символов** (2026-11-15). Значения длиной 1–5 Unicode-символов
  допускаются при явном password-binding: строковые присваивания, типизированные
  скаляры, сравнения и таблицы. Boolean/null, примеры, маски, последовательности
  и выражения не становятся паролями; custom taxonomy с минимумом 6 сохранена.
  На полном `prowlbench`: L1 +95 положительных / +1 отрицательный случай;
  с неизменной ML-моделью +44 / +0, без потерь прежних положительных ID.
  Одинаковые четыре неполных случая не считаются находками. Прежняя оценка «212»
  была эвристикой, а не числом подтверждённых коротких секретов. ML по-прежнему
  отсекает часть коротких паролей; ключи/токены описаны отдельным пунктом выше.
  Контракт, ограничения и квалификация — `wiki/Decoding.md`,
  `wiki/evidence/1.5.0-short-passwords-20261115.json`.
- [x] **Сравнения с литералом.** `==`, `!=`, `===`, `!==`, прямой и обратный порядок
  операндов; bare/property/dictionary-поля с секретным именем и quoted-значение.
  Метаданные, placeholders и выражения не становятся новыми comparison-кандидатами;
  имя поля передаётся ML, позиции и логическая HMAC-идентичность сохранены.
  Короткие пароли и ключи дополнены отдельными контрактами выше.
  Квалификация — `wiki/Decoding.md`.

- [x] **Регресс recall после возврата «шумовых контрактов» 1.4.0** (`523dc7d`). На размеченном
  подмножестве (`benchmark/ci_subset.jsonl`, 2094 секрета, 982 трудных негатива) recall без ML упал
  с 87,2% до 73,2%, с ML — с 77,2% до 66,3% (ниже выпущенной 1.4.0: 67,0%). Причина — «имя секрета
  рядом» сузилось до прямого присваивания, и секреты в прозе перестали находиться. Возвращено
  точечно: идентификатор секрета в прозе перед значением (`the staging awsSecretKey is …`,
  `rotate the API_KEY (…)`), пароли после слова-признака через обычные слова (`db_password is …`,
  `пароль сервиса — …`). Итог: без ML 79,6% / 8,5% ложных, с ML 72,5% / 5,4% (ложные как до правки).
  Шумовой корпус LSP — 2258/2258; 736 МБ стороннего Go-кода — +1 находка.
  - [ ] Остаток до прежних 87%: ~100 случаев — артефакт набора (конфиги и shell-фрагменты
    записываются с расширением `.py`, и фильтр значений кода отбрасывает `PGPASSWORD: x`);
    ~60 — проза без имени рядом со значением. `benchmark/ci_baseline.json` устарел (июнь, cgo-модель)
    и каталог `benchmark/` не в Git.
    - [x] Вернуть воспроизводимый гейт в CI/release: runner в `scripts/quality/`,
      внешний корпус закреплён commit + SHA-256; прежние 3076 записей совпали.
      Полнота/байты/пути проверяются, baseline не создаётся и не снижается.
      8 unit-тестов и actionlint проходят. Текущий кандидат честно не проходит:
      1517/2094 против минимума 1554; FP 53/982 в пределах прежнего допуска.
      [Протокол и границы](wiki/Detection-Quality.md),
      `wiki/evidence/1.5.0-quality-gate-20261115.json`.
    - [x] Recall восстановлен до сохранённого порога: 1556/2094 (минимум 1554),
      FP 57/982 (максимум 61), одинаково на Go 1.26.11/1.27.4. Проза 8–64 байта,
      `passwd`/CJK, bounded API-key labels и точные ML-имена без изменения прежних
      присваиваний; модель, baseline и расширения корпуса не менялись.
      Полный публичный корпус: +339 положительных без потери прежних, +22 ложных.
      CLI 169/169, LSP 2332/2332; full Go, race и lint проходят.
      [Границы](wiki/Prose-Credentials.md),
      `wiki/evidence/1.5.0-prose-recovery-20261115.json`.

### P2 — CI и гигиена

- [x] Добавить `govulncheck` в CI: закреплён v1.9.0, проверяются шесть релизных целей
  и минимальный Go 1.26.11. Тот же гейт включён перед релизом; локально findings отсутствуют
  во всех семи конфигурациях. Обновлены Docker CLI/helpers, containerregistry, PDF,
  compress, logrus и x/net/text/sync/sys. Минимальный Go — 1.26.11, сборочный — 1.27.4;
  Go 1.25.14 оставлял 21 достижимую уязвимость. Модель переквалифицирована после compress.
- [ ] Запускать Python-тесты (`tests/test_pipeline.py`, `tests/test_data.py`) в CI — сейчас
  только ruff по пяти классам ошибок. Уточнено 2026-11-14: `src/`, `tests/`, `references/`
  и `pyproject.toml` исключены из Git; сначала определить место CI для исследовательского проекта.
  - [x] Подготовлен отдельный локальный CI-handoff: минимальные 18 research source/test
    файлов, hash-locked зависимости, стабильный seed taxonomy и сетевой guard.
    Python 3.12/3.14 × два seed — 4×41; распакованный архив — ещё 2×41, все 15 imports
    из нового каталога. Actionlint проходит. Исходники и CI сканера не менялись.
    `wiki/evidence/1.5.0-python-research-ci-handoff-20261115.json`.
  - [x] По выбору владельца создан отдельный локальный `/Users/sugar/dev/prowl-research`,
    commit `a3e5861`, 29 файлов без corpora/weights. Восстановлены 18 source/test файлов
    и четыре byte-identical CI-файла; lock пересобран из прежних pins. Матрица 4×41
    и 15 fresh imports в новом checkout под OS network deny проходят; scanner originals
    не менялись. `wiki/evidence/1.5.0-python-research-canonical-20261116.json`.
  - [ ] Отдельно разрешённая публикация research-репозитория и фактический hosted Linux CI;
    локальная матрица общий пункт не закрывает. [Границы](wiki/Python-Research-CI.md).
- [x] Убрать двойные прогоны: push запускается только для `main`, остальные ветки — через PR.
- [x] Добавлены минимальные `permissions:`; все Actions в CI и релизном workflow закреплены
  по проверенным SHA. YAML, `actionlint` и ShellCheck прошли локально.
- [x] Fuzz-цели продублированы в `Makefile` и `ci.yml` — CI вызывает `make fuzz`,
  который обнаруживает все fuzz-цели в пакетах продукта (18 на 2026-11-14).
  Локальный smoke: `GOMAXPROCS=2 make fuzz FUZZTIME=1s` — прежние 15 прошли;
  цели таблиц, сравнений и char-code проверены отдельными 5-секундными прогонами.
- [x] Покрытие: `internal/model`, `internal/ahocorasick`, `internal/ownedcmd` — 100%,
  `internal/hermesaudit` — 78,0% (было 54,4%). Проверены маскирование PEM/Unicode,
  стабильность fingerprint, URI, Aho против substring-оракула, параллельное чтение,
  лимиты диагностики и отмена дерева процессов, точные passive IP-запросы, отсутствие
  payload/credentials в отчёте, cookie/redirect и размер ответа. Race и Go 1.25 прошли.
- [x] Проверить, что `tool/.dockerignore` исключает локальный мусор (`purrloin`, `*.test`,
  `0N_*`-фикстуры, `.env.prod`, ~30 МБ) — Dockerfile делает `COPY . .`.
  Добавлен отсутствовавший `purrloin`; остальные указанные шаблоны уже были.

### До начала работ

- [x] Закоммитить текущее рабочее дерево тематическими коммитами (на 2026-11-14 — 254
  незакоммиченных файла, +7100/−2588 строк с 31 июля). Рефакторинг CLI начинать только после
  этого. Сохранено семью локальными коммитами `68914bf`…`6d0a7ba`; публикация не выполнялась.
