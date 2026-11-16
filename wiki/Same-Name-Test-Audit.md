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

Родительский аудит same-name assertions/helpers остаётся открытым. Его нельзя
закрыть по этому inventory или по проходу выборки. Release factory, hosted CI,
публикация и внешняя acceptance также остаются отдельными этапами.
