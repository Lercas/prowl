# Контракты rules API между 1.4.0 и 1.5.0

Добавлена воспроизводимая проверка экспортированных matching API пакета rules.
Runtime не изменён: новая работа содержит tests, read-only inventory helper
и документацию. Бинарники и модель повторно не собирались; detector quality,
provider behavior и общий переход на 1.5.0 этим пунктом не квалифицируются.

## Исходники и inventory

Reference — неизменённый тег `v1.4.0`,
`f72ea02d0295e764bec5a32359240e77192073fc`. Все 694 его `tool/` blobs сверены
с Git object hashes до и после проверки. Supplemental файл подключён через
Go overlay: физически в reference он не создаётся. `go list` подтверждает
виртуальный `XTestGoFiles`, JSON test events — реально выполненные assertions.

Текущий baseline — `1984d87`; test/helper commit — `f9b76f0`.
Новый `scripts/compat14/api_inventory.go` разбирает все не-test Go source files
без применения build tags и комментариев. Он считает funcs/methods,
exported type/value declarations; одинаковый AST не доказывает поведение.

| Объявления | Число |
| --- | ---: |
| Reference | 501 |
| Candidate | 690 |
| Общие, неизменённый AST | 398 |
| Общие, изменённый AST | 90 |
| Удалённые | 13 |
| Добавленные | 202 |

Это новый срез после последних исправлений, а не перезапись прежнего inventory
с 93 изменениями. Удалённые 13 имён совпадают с ранее описанными намеренными
заменами в [Report-Write-Contract.md](Report-Write-Contract.md).

Из 90 changed declarations восемь относятся к rules: `Engine.Filter`,
`Engine.MatchN`, `Template.Match`, `Engine`, `Template`, `Matcher`, `Extractor`
и `LoadEmbedded`. Новая матрица проверяет первые семь через exported APIs.
`LoadEmbedded` со строгим `KnownFields(true)` остаётся отдельным изменением
schema validation; новая cross-release матрица его не квалифицирует.
Общий поведенческий аудит остальных declarations остаётся открытым.

## Проверенные контракты

Один supplemental файл `tool/internal/rules/released_api_test.go` компилируется
на обеих версиях. Общая матрица — 402 test/subtest passes на каждой, без skips:

- AND/OR внутри word matcher и между matchers, positive/negative words;
- Unicode case conversion и malformed UTF-8, standalone `Template.Match`;
- стандартный Go regexp oracle для regex/byte spans, multiline и capture groups
  с явным `group: 0/1`, лимиты −1/0/1/2/10 и `truncated`;
- `Engine.Match`, `MatchN`, фильтрация IDs/tags/severity после построения lazy
  index, последующее исключение последнего правила;
- заявленное разделение value/occurrence режимов в 1.5.

В последнем пункте есть одна явная API-адаптация: 1.4 `MatchN` сохраняет разные
source spans одного значения, 1.5 default схлопывает их по value. В 1.5
`MatchOccurrencesN` сохраняет все позиции. Тест проверяет обе стороны различия
и все поля hits; одинаковое число passes не объявляется default count parity.
Поведение соответствует уже сохранённым occurrence tests и assertion map.

## Отдельный исправленный случай

Пустая строка — допустимое positive word condition (`strings.Contains(s, "")`).
В 1.4 Engine не активировал положительное AND-правило с таким anchor, хотя
standalone matching считал условие выполненным. Текущий word index содержит
явный empty-word presence bit.

Отдельная extension-матрица — 57 passes на candidate. На неизменённом reference
наблюдаются ровно десять failing subcases: AND, positive empty word, два inner
conditions и пять текстов с regex hit. Оставшиеся 46 subcases проходят;
parent test ожидаемо падает. Этот ненулевой reference exit не скрыт и не считается
успешным прогоном. Общая cross-release матрица этого случая не содержит.

## Проверки и границы

Candidate: 459 supplemental passes (402 общих + 57 extension), полный пакет
rules — 593 passes и один opt-in skip `TestWordIndexCorpusParity`. Targeted race
новых tests + concurrent word-index test — 460 passes без skips. На Go 1.26.11
новая матрица — 459 passes; полный rules package на minimum Go также прошёл
до разделения shared/extension wrappers. Lint 2.15.0 проходит.

Все Go tests выполнялись под OS-запретом всей сети. Generic feature/ML threshold,
weights, production code и замороженные evidence-файлы не менялись. Полный
GOROOT corpus, performance, release factory и native/provider suites повторно
не запускались: runtime остался побайтово прежним.

[Машинный отчёт](evidence/1.5.0-rules-api-compatibility-20261116.json).

Повтор inventory из корня checkout:

```sh
GOTOOLCHAIN=go1.27.4 go run scripts/compat14/api_inventory.go \
  /path/to/immutable-v1.4.0/tool tool > /new/path/inventory.json
```

Для reference tests создаётся overlay с единственной заменой отсутствующего
`tool/internal/rules/released_api_test.go` на этот файл из candidate. Shared gate:
`-run '^TestReleasedAPI(WordAndRegexMatrix|RegexSpansAndLimits|SelectionAndOccurrenceModes)$'`.
`TestReleasedAPIEmptyWordActivation` запускается отдельно и на reference должен
дать только перечисленные десять failures; ослабление матрицы не требуется.
