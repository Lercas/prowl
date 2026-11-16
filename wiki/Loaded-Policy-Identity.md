# Идентичность загруженной ML/verifier policy

P0-проверка перехода с 1.4.0 обнаружила потерю scope digest для ML-модели и
verifier definitions. Путь к файлу не идентифицирует загруженное содержимое:
два полных отчёта без подавлений могли получить одинаковые scopes после замены
модели по тому же пути. Это воспроизведено на предыдущем бинарнике; `remediation-check`
разрешал `absent_in_scope`, хотя policy снимков различалась. Воспроизведение
использовало фактическое удаление synthetic secret из выбранного файла, а не
скрытие присутствующего секрета ML: существующий `filtered` guard сохранён.

## Фиксация снимка

`mlmodel.Model.Digest()` — SHA-256 точных валидированных байтов, из которых
построена модель. `Embedded.PolicyID()` использует этот снимок без повторного
чтения файла; `WithThreshold` разделяет модель и порог. Whitespace-различие
модельного JSON также меняет byte identity, даже если предсказания совпадают.

Общий `Pipeline.RegisterPolicy` добавляет `ml_model` scope с digest, порогом,
local/sidecar признаком и revision `loaded-model-v1`. Это работает и без findings,
включая empty HTTP batches через Go API. Внутренняя оболочка `compare` сохраняет
идентификатор исходной модели. Default L1 scan без ML/verifiers новых scopes не получает.

`verifiers` scope идентифицирует загруженные ID/selectors, extraction/signing,
request URL/method/headers/body, matchers и capability labels. Сериализация YAML
сохраняет binary string bytes, которые JSON заменил бы при invalid UTF-8.
Исходный filename и YAML presentation comments в этот digest не входят.
Замена файла после Load не меняет уже разобранные definitions. Disk и встроенный
snapshot с одинаковыми definitions получают одинаковую identity.
Как и выполнение, регистрация предполагает, что вызывающий код не мутирует
возвращаемые `Verifiers()` entries. Это internal read-only contract, не защита
от произвольной записи памяти вызывающим кодом.

В отчёт попадают только scope hashes; модель, URL/headers/body/sign parameters
и исходный путь не сериализуются. При заданном identity key применяется прежний
HMAC для policy scopes. Model/verifier digest не является подписью или
подтверждением происхождения артефакта.

## Неподтверждённая policy scorer

Scorer без доступного корректного `PolicyID` (включая обычный HTTP sidecar)
получает `unversioned_policy`, а не выдуманную identity его модели. Invalid
threshold тоже не становится стабильной модельной policy. Успешный скан остаётся
complete: это граница доказательства сопоставимости, а не processing error.
`remediation-check` при такой policy не подтверждает отсутствие (`comparable=false`,
`inconclusive`, exit 2), даже если scopes побайтно равны. Наблюдаемое присутствие
и provider observations сохраняются. Повторное использование URL не доказывает
неизменность модели удалённой службы; дополнительных сетевых metadata-запросов нет.

Для versioned embedded модели отсутствие разрешено только при полном совпадении
остальных scopes, complete и unfiltered reports. При drift модели, порога или
verifier definitions отсутствие остаётся inconclusive. Отсутствие само по себе
не подтверждает revocation и не закрывает remediation.

Старые отчёты не переписываются и не получают identity задним числом.
Исторические отчёты без этих digests не переквалифицированы этим изменением.
Содержимое неизменённых historical evidence JSON сохраняется.

## Проверка

```sh
sandbox-exec -p '(version 1)(allow default)(deny network*)(allow network* (local ip "localhost:*"))(allow network* (remote ip "localhost:*"))' \
  python3 -I scripts/check_loaded_policy_native.py /path/to/prowl
```

Runner создаёт только собственные model/verifier fixtures и identity key.
Он проверяет явную и installed модель, тот же путь и другой filename, JSON/SARIF,
drift definitions и порога, matching-policy controls и реальные JSON отчёты для
remediation-check. Verifier и ML sidecar — owned loopback HTTP fixtures;
реальные провайдеры не вызываются. Отдельный denied bind проверяет OS network deny
вне loopback без отправки сетевого пакета.

Локальная квалификация: native 134/134 и прежний correlation runner 46/46;
полный Go-набор, targeted race, Go 1.26.11 и lint проходят. Собраны шесть static
GOOS/GOARCH targets из чистого source commit; foreign binaries не исполнялись.
Все quality result keys, кроме binary SHA, и default corpus digest совпали с
предыдущим кандидатом. Точные hashes и границы —
[evidence](evidence/1.5.0-loaded-policy-20261116.json).

Полный P0-аудит остаётся открыт: в частности, `detector_config` и произвольные
allow/config callbacks требуют отдельного сопоставления с released policy boundaries.
Финальные Docker assets, signing/publication, hosted CI и реальные provider accounts
этим локальным этапом не квалифицированы.
