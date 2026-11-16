# Вердикты проверки credentials

`verification.status` описывает наблюдение провайдера. `verified: true` появляется
только при совпадении положительного matcher выбранного verifier. Если matcher
не совпал, HTTP 401 означает `invalid` / `verified: false`; иной ответ не доказывает
отзыв ключа и остаётся `error` с причиной `provider response inconclusive`.
Ошибки сети, неполное тело, throttling и 5xx также не означают «ключ мёртв».

В 1.5 неопределённая проверка сохраняет неполное coverage, exit 2 и запрет записи
baseline, включая `--verified-only`. Это более строгая политика отчётности, чем
у пересобранного тега 1.4.0; совместимость provider verdict проверяется отдельно
от требования к ledger/exit. Наличие положительного matcher и статуса 401
рассматривается в прежнем порядке: явно заданный положительный matcher сильнее.

Generic password/API-key/semantic candidates не имеют установленной provider
identity и не отправляются провайдеру по случайному слову или префиксу внутри
значения. Сохранён выпущенный fallback `generic_high_entropy` только с явным
provider prefix в начале значения. Typed provider findings продолжают работать.

До cache lookup извлечение companions из обычного текста проверяет все найденные
значения: повтор одного допустим, разные значения неоднозначны. На одну роль
разрешено не более 1024 regex matches. Неоднозначный или вышедший за этот лимит
контекст не заимствует cached LIVE
результат. Structured literals и межфайловые components используют свои точные
parser-established bindings. Cache по-прежнему различает все фактические переменные;
неопределённый ответ не кэшируется как окончательный и допускает новый запрос.

## Проверки перехода

Из тега 1.4.0 без изменений возвращены `verdict_contract_test.go` и `cache_test.go`.
До исправления они воспроизводят ошибочные dead-вердикты, отправку generic values
и заимствование cached LIVE при неоднозначном companion. Дополнительные тесты
проверяют восстановление после неопределённого ответа и границу 1024/1025 matches.

```sh
python3 scripts/check_verification_verdict.py /path/to/prowl
```

Runner использует собственные `PROWL_HOME`, synthetic credentials и loopback stub.
Проверяются JSON/SARIF, ML, tri-state `verified`, coverage, redaction, live gate и
защита baseline. Для сравнения только provider verdict старого бинарника:
`--legacy-verdict-only` отключает новую модель и записывает прежние coverage/exit,
не выдавая их за квалификацию строгой политики 1.5.

Это локальная проверка контрактов, а не acceptance реальных provider accounts.
Доказательства: `evidence/1.5.0-verification-verdicts-20261116.json`.
