# Byte budgets stdin API

Возвращён выпущенный контракт `source.Stdin(ctx, limits ...int64)`: первый
положительный необязательный аргумент задаёт лимит этого вызова. Без него,
а также при нуле или отрицательном значении, API использует 4 MiB.
`StdinNamed` и `StdinLimited` используют ту же нормализацию.

| Вызов | Лимит |
|---|---|
| `Stdin(ctx)` | 4 MiB |
| `Stdin(ctx, positiveLimit)` | Явный byte limit |
| `StdinNamed(ctx, name)` | 4 MiB |
| `StdinLimited(ctx, 0)` / отрицательное значение | 4 MiB |
| CLI без `--max-size` | Явно переданные 10 MiB |
| CLI с `--max-size N` | Явно переданный N |

CLI не зависит от convenience default API: selector передаёт `c.maxSize` через
`StdinLimited` или `StdinNamed`. Возврат 4 MiB не уменьшает штатные 10 MiB CLI.
Положительный лимит считается по байтам исходного ввода до normalization;
точная граница принимается, дополнительный байт даёт `max_size`/incomplete.
Логическое имя по-прежнему не открывается и не создаёт файл.

## Регрессия

В базе 1.5.0 исчез variadic argument `Stdin`, convenience default вырос с 4 до
10 MiB, а `StdinLimited(0/-1)` возвращал invalid-limit вместо released default.
До исправления четыре сценария с входом 4 MiB + 1 byte не выполняли released
контракт. Изменён только public stdin dispatch; общий reader, cancellation,
parser/extraction и CLI flags сохранены.

Две top-level проверки и девять subcases реально выполнены на candidate и
исходном теге 1.4.0 через canonical Go overlay. Проверены default/nonpositive
budgets, variadic positive override, named/limited explicit 5 MiB и coverage.
Все 694 физических reference `tool/` blobs остались неизменными.

Native runner `scripts/check_stdin_budget_native.py`: 112/112 под OS network deny.
Два настоящих CLI binary получили stdin 5 MiB через pipe: implicit/dash/named/
quick, explicit 4 MiB и exact 5 MiB boundary. Проверены полный input, incomplete
при oversize, отсутствие файла logical label и одинаковые metadata/scopes.
Общая локальная CLI upgrade-матрица с неизменённой пересборкой 1.4.0 — 190/190,
включая structured stdin/UTF-16 и flags/preflight guards.

Результаты полных Go, scoped race/min-Go/lint, static builds и quality gate
записаны в `evidence/1.5.0-stdin-api-budget-20261116.json` вместе с отдельным
bucket cancellation timing failure и его повторными проверками. Причина
этого сбоя не объявляется исправленной данным stdin patch.

API inventory после исправления: 13 намеренных удалений имён и 91 изменённое
объявление относительно 1.4.0. Это не сертификат полного CLI/runtime audit.
Полный переход на 1.5.0, финальная release factory и проверки чужих платформ
остаются открытыми пунктами TODO.
