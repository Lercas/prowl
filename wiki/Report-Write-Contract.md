# Контракт ошибок записи отчёта

`report.Write` и `report.WriteWithCoverage` возвращают ошибку, если destination
принял меньше переданных байт. Для custom `io.Writer`, вернувшего
`n < len(p), nil`, возвращается `io.ErrShortWrite`. При ненулевой исходной
I/O-ошибке сохраняется её cause; после первого отказа повторной записи нет.
Гарантия действует для pretty/default, JSON, SARIF, DefectDojo и alias `dojo`.

В 1.4.0 этот guard был общим для format dispatch. При переносе в 1.5.0 он
остался внутри pretty renderer: остальные четыре machine format spellings
могли вернуть nil после short write. Восстановлен общий wrapper без изменения
форматов, scopes, identity или состава находок. Ошибка неизвестного формата
не маскируется writer guard и не вызывает запись.

Возврат ошибки не отменяет уже принятый destination префикс. Вызывающая сторона
должна считать такой отчёт неуспешным. CLI сохраняет существующий atomic writer
для файлов и ненулевой exit при ошибке stdout/destination.

## Доказательства

Контроль на предыдущем коде воспроизвёл восемь failures: JSON/SARIF/DefectDojo/dojo
на empty и nonempty findings. Pretty уже корректно возвращал ошибку. Три новых
regression tests подтверждённо выполнены на текущем коде и исходном теге 1.4.0:
short writes, 96 комбинаций формата/данных/бюджета/cause/entrypoint и отказ
неизвестного формата. Supplemental test подключён к reference через Go overlay;
все 694 исходных `tool/` blobs физически неизменны. JSON-события подтверждают
имена реально выполненных tests. Первые overlay attempts с `/var` вместо
канонического `/private/var` не запускали tests и исключены из qualification.

Native runner `scripts/check_report_write_native.py` прошёл 135/135 под OS network
deny: успешные private-файлы всех пяти CLI форматов для clean/positive/incomplete
input побайтово совпали с предыдущим binary; broken stdout и directory output
отвергаются. Он проверяет реальные CLI I/O errors, а не выдаёт custom short-write
fixture за наблюдение над обычным OS file.

Full Go suite, scoped race/min-Go/lint и шесть static builds проходят. Foreign
binaries не запускались. Quality gate сохраняет IDs 1661/2094 и FP 61/982.
GOROOT/performance не повторялись: detector/scan/model runtime не менялся.
Хеши source/binaries/logs: `evidence/1.5.0-report-write-20261116.json`.

## Граница API inventory

Read-only AST inventory перед этим patch: 501 released и 690 current exported
объявлений; 13 удалённых и 93 изменённых declarations. Для всех 13 удалённых
найдена намеренная замена:

| Старое объявление | Текущий путь |
|---|---|
| `hermesAuditList.Set/String` | Central CLI schema; private flag.Value adapter больше не нужен |
| `BuiltWithCgo`, `ExtractPortable`, `Model.Portable` | Единый versioned Go extractor/model validation |
| `scan.Findings`, `scan.Run` | Immutable `Pipeline.Findings/Run` |
| `scan.WithOptions`, `scan.SetRevealSecrets` | `New(Options)` и `WithRevealSecrets` |
| `scan.RegisterDetectionPolicy` | `Pipeline.RegisterPolicy` внутри entrypoints |
| `scan.RefreshOccurrence` | Pipeline/model occurrence identity update |
| `losslessJSONReader.Read` | Shared strict JSON validation HTTP worker |
| `verify.Set.PolicyID` | Error-aware `PolicyDigest` и loaded-policy registration |

Это карта удалённых имён, не квалификация всех 93 изменённых declarations.
Регрессия writer найдена именно среди изменённых функций. Общий аудит API,
CLI/runtime contracts, release factory и полный переход на 1.5.0 остаются открыты.
