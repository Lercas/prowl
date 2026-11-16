# Сопоставление 45 released Go-контрактов

Инвентаризация имён выявила 45 Test/Fuzz declarations из 1.4.0, имён которых
не было в кандидате. Сверка assertions дала три результата:

- 30 проверок восстановлены с адаптацией к текущим API.
- 11 уже проверяются под другими именами; для них сохранены точные ссылки
  на функции и hashes файлов. Selftest вновь требует минимум два полных случая.
- 4 относятся к намеренной замене ML/compression: Go-flate-v2, текущая модель
  с 51 признаком и точные `<=` split semantics вместо старого tolerance shim.
  Legacy compression invariance и равенство старых/новых raw model scores не заявляются.

Карта: `evidence/1.5.0-reference-assertion-map-20261116.json`.
Она закрывает эту инвентаризацию имён, но не доказывает совместимость всех
изменённых same-name test bodies/helpers. Удалённые native runners отдельно
восстановлены и квалифицированы ниже.
Родительская проверка выпущенных контрактов остаётся открытой.

## Восстановленные assertions

JSON: реальные embedded ML и keyed identities для canonical values; escaped
data pragmas; allowlist с canonical значениями; Base64 composition; отдельные
inner occurrences и credential в object keys; typed-rule corpus; Unicode,
document/value limits, плотные 8002 scalars и отмена. Duplicate keys сохраняют
находки и markers неполноты: это намеренно более строгая отчётность 1.5.
Модель квалифицируется со штатным порогом 0,3 вместо legacy 0,5.

Также возвращены overlap dominance/50k disjoint spans, Base64 noise/work/depth,
reconstruction identity и URL privacy, staged bytes/immutable provenance,
oversize/filesystem coverage, explicit directory symlink root, настоящий
асинхронный отказ MCP при blocked input и восемь одновременно заблокированных
Jira bulk requests. Unicode transport checks используют реальный bounded HTTP
decode, сохраняя исходные chunk sizes, valid/invalid Unicode и byte identity.

Все 45 оригинальных проверок и дополнительный canonical JSON test проходят на
неизменённом пересобранном теге: 46 top-level passes без skips. Сверены все 694
tool blobs тега, дополнительных Go-файлов в reference checkout нет.

## Исправление pretty-отчёта

Старый renderer кандидата игнорировал coverage и выводил зелёное
`✓ no secrets found` для пустого, filtered и metadata-only incomplete результата.
CLI terminal path также не передавал coverage. Регрессия воспроизведена unit
assertions и настоящим CLI до исправления.

Теперь:

- Empty input: `no objects to scan`.
- Подавленные находки: `no findings after filters and suppressions`.
- Полный чистый скан: `✓ no secrets found`.
- Неполнота: предупреждение и до пяти metadata diagnostics; уже показанный
  input gap не повторяется как та же code/path metadata.
- Кандидаты без provider verdict явно названы неподтверждёнными.

Диагностика очищает управляющие байты терминала. Остаток счётчика указывает на JSON coverage
metadata, не обещая неограниченный список. Gate, JSON/SARIF, детекция и ML не менялись.

```sh
python3 scripts/check_pretty_coverage_contract.py /path/to/prowl
```

40 native checks: десять состояний через pipe, report file, настоящий PTY без
цвета и цветной PTY, ширина 100 columns. Проверяются quiet mode, redaction,
baseline/pragma/display suppression, missing/oversize/malformed inputs и exit codes.
Runner выполнен под OS network deny. Full Go, targeted race, минимум Go и lint
проходят; Unicode fuzz с лимитом 10s выполнил 208769 проверок.

Точные ревизии и границы: `evidence/1.5.0-reference-assertions-20261116.json`.
Новая quality/performance оценка здесь не заявляется: изменился human renderer,
а модель, JSON/SARIF writers и scan/detect runtime сохранены. Публикация,
hosted CI и внешняя acceptance остаются отдельными этапами.

## Удалённые native runners

12 исходных файлов 1.4.0 сохранены без изменений с SHA-256 manifest.
Новый `scripts/check_released_native_contracts.py` выполняет 11 suites
на каждом binary, включая обе noise fixtures. На source `98170a0` прошли
все 11 candidate и 11 reference запусков; reference не получает адаптаций.
Quick runner проверил 61 сценарий кандидата и 54 исходных сценария reference:
семь дополнительных проверок защищают incomplete exit 2 при boolean `=false`.

Найдены две реальные регрессии. `help all` вновь формируется из актуальной
схемы команд и вложенных флагов без загрузки конфигурации или установки модели.
Summary теперь считает findings после baseline/gitleaksignore и восстановления
LIVE-находок для gate. Дополнительный тест сверяет count отчёта, summary
и exit code с обоими suppressors и `--fail-on-verified`.

Английские сообщения, явные boolean values, markers неполноты и десять уточнений
generic type адаптированы явно. Corpus generators и исходные noise bytes
не менялись; markers проверяются до отделения от credential assertions.
Legacy model-score parity не заявляется. Все CLI Go-тесты, целевые race checks,
минимум Go 1.26.11 и lint проходят. Detector/ML runtime не менялся.

Границы optional hook, informational benchmark, Docker factory и сетевой
изоляции перечислены в [описании runner](../scripts/compat14/README.md).
Точные adapters, binary/source hashes и результаты:
`evidence/1.5.0-released-native-contracts-20261116.json`.
Изменённые same-name Go test bodies/helpers остаются открыты.
