# Аудит Go-тестов с совпадающими именами

Наличие теста под прежним именем не доказывает сохранение его assertions.
После восстановления 30 имён предыдущим этапом текущая база содержит 1009
из 1024 released Test/Fuzz/Benchmark declarations под тем же package/name.
Первоначальные 979 совпадений и карта остальных 45 имён сохраняют историческое
значение; новые числа относятся к source `e76334a`.

## Воспроизводимая инвентаризация

```sh
go run scripts/audit_reference_tests/main.go /path/to/reference /path/to/candidate
```

Инструмент только читает файлы. Он использует Go parser/scanner, сравнивает
токены без комментариев и отдельно нормализует эквивалентные строковые
константы: escaped/plain spelling и конкатенацию строк. API-вызовы, assertions,
типы и числа не нормализуются. Включены file hashes, testdata hashes и
синтаксические ссылки на declarations из test files того же package.

Для 1009 совпадений:

- 841 имеет одинаковые токены тела.
- 38 отличаются только эквивалентной записью строковых констант.
- 130 имеют другие изменения и требуют сопоставления assertions. Часть уже
  восстановлена предыдущим этапом, но полной карты этой группы пока нет.
- Изменены либо удалены 15 helper declarations, включая методы и constants.

Восемь из девяти исходных testdata файлов сохранены byte-for-byte. Отсутствующий
`mlmodel/testdata/release_parity.json` относится к намеренной замене старой модели;
текущая portable/canonical qualification не заявляет равенства старых raw scores.
Go 1.27.4 и 1.26.11 дали одинаковый JSON inventory. Все 694 tool blobs reference
сверены с тегом после тестов; дополнительных файлов в reference tool tree нет.

Ссылки на identifiers не являются typed call graph: method dispatch, imports,
initialization и build constraints требуют ручной оценки. Одинаковые токены
не подтверждают поведенческую совместимость production runtime.

## Возвращённые проверки

Аудит выявил ослабление нескольких tests/helpers, исправленное в этом этапе:

- YAML/TOML canonical fixtures вновь используют реальную embedded модель
  при штатном пороге 0,3 и keyed SecretID/Fingerprint. Recording scorer сохранён
  как дополнительный вариант; TOML проверяет nil, filesystem и embedded rules.
- TOML comment occurrences снова имеют разные непустые OccurrenceID. YAML alias
  declarations/uses имеют общий SecretID и разные OccurrenceID.
- Noise helpers допускают `generic_high_entropy` → `generic_api_key` только
  для десяти точных fixture names. LSP читает исходные released fixtures из
  scan/testdata; размеченные данные не меняются.
- Dense LSP redaction проверяет фактически используемый prefix. Entropy tuning
  использует исходное значение и проверяет именно `generic_high_entropy`,
  сохраняя default → raised threshold → restored default assertions.
- Вернулись четыре исходных determinism inputs; они проверяются вместе с текущим
  input в empty/code contexts по 100 раз.
- Исходные raw occurrence counts 3/9 проверяются через `MatchOccurrencesN`;
  текущие default dedup assertions сохранены.
- `--bundled` вновь проверяется через настоящий scan parser, а не только
  через validation уже собранной структуры флагов.

Изменения касаются тестов и инструмента аудита. Production Go-код, модель,
пороги и корпуса не менялись, поэтому новая quality/performance оценка здесь
не выполнялась.

## Проверки и оставшиеся границы

Выборка изменённых tests/fuzz seed tests на 13 packages: на reference и candidate
по 163 top-level pass и три skip. Пропущены исторические `mlfeatures.TestParity`,
`mlfeatures.TestCompressionRatioDivergence`, `mlmodel.TestParity`: отсутствует
опциональный локальный research fixture. Reference запускался с CGO, candidate
без CGO. Эти skips не считаются подтверждением parity.

Полные tests пяти изменённых packages проходят. Целевые race checks, Go 1.26.11,
lint этих packages и vet инструмента аудита проходят. Benchmark bodies включены
в inventory, но benchmark performance в этом этапе не измерялся.

Evidence:

- `evidence/1.5.0-same-name-test-inventory-20261116.json`.
- `evidence/1.5.0-same-name-restored-assertions-20261116.json`.

Первый этап оставлял same-name assertions/helpers открытыми. Следующий этап
завершил сопоставление, описанное ниже. Release factory, hosted CI,
публикация и внешняя acceptance остаются отдельными этапами.

## Завершённая карта assertions и helpers

Для всех 130 нетривиальных тел сохранены точные source paths, token hashes и
review profiles с исходными assertions и явными изменениями. Отдельно разобраны
15 изменённых/удалённых helpers и шесть введённых adapters. Остальные 841 тело
совпадают по токенам, 38 отличаются эквивалентной записью строковых констант.
Неизменённые либо эквивалентные тела учитываются вместе с просмотренными helpers,
а не как самостоятельное доказательство поведения production runtime.

Исходный JSON-fuzz потерял четыре seeds и проверки `locate`, декодирования
canonical value непосредственно из физического JSON span и длины byte map.
Эти assertions возвращены вместе с текущими public-binding, UTF-8 и per-byte
проверками; расширенный лимит 64KiB сохранён. Fuzz с лимитом 10s выполнил 14768
проверок за 11,669s без ошибки. Перед разделением credentials и markers helper
теперь проверяет точное ожидаемое число `response_truncated/scan/intake`,
отсутствие secret identity и provider verdict. Он не скрывает произвольную неполноту.

Сопоставление подтвердило отдельные намеренные изменения: английский UI,
scoped flag schemas, точные Base64 source quanta, более строгую literal intake,
уточнение десяти generic types и текущую Go-flate-v2/51-feature модель.
Изменившиеся HTML select cases связаны с обновлением x/net v0.52.0 → v0.62.0;
положительный ресурс и отрицательный чужой base проверяются отдельным тестом.
Равенство raw scores старой и новой модели не заявляется.

## Исправленная регистрация политики

Ручной `RegisterPolicy` в тесте скрывал реальную регрессию: пустой `Pipeline.Run`
и прямой `Findings` не регистрировали политику. CLI терял `detection_policy` и
`rules` scopes, а несериализуемая policy могла пройти без нужной неполноты.
Без ручной подготовки исходный assertion воспроизводимо падал.

Теперь обе точки входа регистрируют policy. Возвращаемый контекст передаёт
регистрацию workers и HTTP batch: digest не пересчитывается для каждого Item.
Marker привязан к конкретным pipeline и coverage ledger. Новый ledger или другой
pipeline получают свою регистрацию; без report ledger внешняя policy не вызывается.
Fixture с 64 Items и четырьмя workers проверяет однократный вызов policy, полноту
и точное число обработанных Items.

Обновлённый native coverage runner проверяет JSON/SARIF, stdin/file, stdout/stored,
empty directory, обязательные policy scopes и invalid-policy baseline guard.
На родительском binary — 0/90; после исправления — 90/90 под OS network deny.
Baseline sentinel при invalid policy сохраняется, exit code — 2.

## Итоговая локальная квалификация

Полный Go-прогон текущего runtime: 1587 top-level passes и 12 явных skips.
На неизменённой пересборке reference с CGO: 1006 passes и шесть skips.
В evidence перечислены все skips: live tests не включались, внешние research
fixtures не подставлялись. Девять benchmark declarations здесь не измерялись;
два `TestMain` не имеют отдельных событий pass, а исторический `!cgo`
compressor-integrity test относится к уже разобранной замене WASM/zlib.

Full Go, целевые race checks, Go 1.26.11 и полный lint проходят. Все 22 запуска
released native suites проходят. Pinned quality gate прошёл с теми же IDs:
1661/2094 positive hits и 61/982 hard-negative hits. Новая performance-оценка
здесь не заявляется; ограничение работы policy дополнительно проверяется счётчиком.
Report identity — 39/39, pretty pipe/file/PTY/color — 40/40. Все 694 tool blobs
reference повторно сверены после полного Go-прогона.

Карта и точные логи: `evidence/1.5.0-same-name-assertion-map-20261116.json`.
Закрыт source/assertion аудит same-name bodies/helpers на darwin/arm64.
Общий пункт восстановления runtime-контрактов, остальные целевые платформы,
release artifacts, hosted CI и внешняя acceptance этим не закрываются.
