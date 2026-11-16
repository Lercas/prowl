# Границы отчётов и литералов при переходе с 1.4.0

Восстановлены выпущенные контракты, обнаруженные при повторной проверке удалённых
регрессионных тестов 1.4.0:

- `--fail-on-verified` сохраняет LIVE-находку до display-фильтров confidence,
  severity и disabled types. Подтверждённый credential продолжает давать exit 1.
- `--verified-only` оставляет только provider-confirmed LIVE credentials.
  Непроверенные high/critical и inconclusive credentials не выдаются за LIVE.
  Служебные маркеры неполноты сохраняются: пустой список подтверждённых секретов
  не превращает неполную проверку в complete, exit 0 или допустимый baseline.
- Превышение файлового `--max-size` возвращает диагностику `max_size` как для
  явно выбранного файла, так и при обходе каталога. Ошибка чтения остаётся неполной.
- При повреждённом JSON/YAML/TOML сохраняются лексические находки и причина
  `structured literal could not be established`, без provider requests.
- Пароль после cue внутри строкового значения JSON/YAML/TOML сохраняет
  contextual evidence и точные исходные координаты. Cue ищется внутри одного
  scalar, без заимствования из имени поля или соседнего значения. Это находка
  L1 в прозе; гарантия сохранения каждой такой находки любым L2 не заявляется.

Номинация целого parser-established password сохраняется. Короткие, экранированные
и многострочные literals используют прежний путь; новая обработка прозы его не
заменяет. Длинные ASCII/Unicode bindings дополнительно проверены в трёх форматах
без ML и с текущей моделью при штатном пороге 0,3.

## Проверки и адаптация fixtures

`release_contract_test.go` и `filesystem_oversize_diagnostic_test.go` возвращены
из тега без изменений. `binding_precision_test.go` использует immutable Pipeline
вместо удалённого API и явную квалифицированную 51-feature модель. Порог прежнего
ML-теста 0,5 заменён на штатные для 1.5 0,3: модель намеренно заменена в миграции,
поэтому parity с прежней моделью при 0,5 не заявляется. Пороги продукта, baseline
качества и пользовательская установленная legacy-модель не менялись.

`verification_literal_safety_test.go` использует новый Pipeline и учитывает
дополнительные coverage markers 1.5, сохраняя обязательность лексических находок,
их error metadata и отсутствие provider calls. Оригиналы всех четырёх файлов
отдельно проходят на неизменённом пересобранном теге 1.4.0.

```sh
python3 scripts/check_verification_verdict.py /path/to/prowl
```

Расширенный runner проверяет 303 случая на synthetic credentials и собственном
loopback stub: JSON/SARIF, display guards, строгий verified-only, ML, длинные
bindings, structured prose, malformed literals, max-size и baseline protection.
Это локальные проверки; реальные provider accounts и hosted CI ими не подтверждены.
Доказательства: `evidence/1.5.0-released-boundaries-20261116.json`.
