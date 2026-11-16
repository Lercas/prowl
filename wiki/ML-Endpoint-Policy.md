# Политика ML sidecar endpoint

`--ml-url` передаёт сырые значения кандидатов и модельный контекст выбранному
HTTP sidecar. По умолчанию разрешён только loopback: literal loopback IP или
`localhost`, закреплённые за выбранным host/port. В локальном режиме HTTP proxy
не используется. Общая `safehttp.AllowPrivate` при этом не меняется, и
`PROWL_ALLOW_PRIVATE_IPS=1` для выбранного локального sidecar не нужен.

Удалённый сервис требует явного `--ml-allow-remote` и HTTPS. Userinfo, непустые query/fragment, неподдерживаемая схема и отсутствующий host отклоняются общим
`safehttp.InferenceClient`. Remote opt-in сохраняет стандартные TLS/SSRF guards.
Любые redirect, включая same-origin, запрещены: scoring body и health request
не перенаправляются к другому пути или сервису.

CLI проверяет выбранный endpoint при разборе flags, до Config/source acquisition,
открытия отчёта, baseline и индекса. Недопустимый endpoint даёт exit 2, не выводит
URL credentials/query и не меняет существующие артефакты. Флаг не включает ML
сам по себе; при выбранной in-process модели сохраняется её прежний приоритет.

## API

Возвращён выпущенный `mlscore.NewWithPolicy(url, threshold, allowRemote)`:
ошибка policy возвращается до HTTP. Legacy `mlscore.New` сохраняет сигнатуру
`*Client`; недопустимый endpoint создаёт inert client, у которого `Health` и
`Score` возвращают initialization error до transport, включая пустой batch.

`Local()` sidecar остаётся false: это не in-process model. Sidecar не сообщает
immutable model identity и по-прежнему получает `unversioned_policy` в coverage;
сертификация отсутствия по такому scorer не разрешена.

Уже выбранный sidecar может отказать или вернуть redirect. L2 остаётся precision
aid: ошибка scoring сохраняет все кандидаты L1 и прежнюю completeness исходного
scan, а не подавляет находки. Это отличается от отклонённого endpoint, при котором
CLI вообще не запускает scan. Health/Score transport errors сохраняют cause для
классификации и не печатают provider-controlled diagnostics или credentials.

## Регрессия и квалификация

Выпущенный тег 1.4.0 содержит flag и `NewWithPolicy`. Их отсутствие в базе 1.5.0
обнаружено при сверке CLI. Контрольный тест прежнего исходника дважды достиг
owned transport для remote HTTPS без opt-in: Health и Score приняли endpoint.
Внешних запросов не было. После исправления оба вызова отклоняются до transport.

Go checks покрывают local/remote/scheme/credential policy, explicit HTTPS opt-in
с owned transport, локальный service без global SSRF bypass, proxy, Health/Score,
и 301/302/303/307/308 same-origin/cross-origin redirect. Существующие response
validation/error tests сохранены; transport fixtures используют валидный
explicit-opt-in URL, invalid URL credentials проверяются отдельно до transport.

Native runner `scripts/check_ml_endpoint_policy_native.py`: 64/64,
JSON/SARIF × file/structured stdin, raw transfer только выбранному owned local
service, сохранность report/baseline/index на preflight, redirects и fail-open.
OS sandbox запрещает внешнюю сеть; настоящий удалённый HTTPS сервис не проверялся.
Loaded-policy suite — 134/134; local CLI upgrade с неизменённой пересборкой
1.4.0 — 190/190. Все 694 reference tool blobs сверены с тегом. Все 62 common flag
names представлены в текущих declarations/aliases; это lexical inventory,
не доказательство поведенческого соответствия всех команд.

Полный Go suite, scoped race/min-Go/lint и шесть static builds проходят. Чужие
платформы не запускались. Quality gate сохраняет все прежние IDs: 1661/2094,
FP 61/982. GOROOT/performance не запускались повторно: detector/scan/model runtime
не менялся; этот пакет меняет sidecar transport и CLI preflight.

Хеши и scope: `evidence/1.5.0-ml-endpoint-policy-20261116.json`.
Остальные CLI/runtime contracts, финальная release factory и полный переход
на 1.5.0 остаются открытыми пунктами TODO.
