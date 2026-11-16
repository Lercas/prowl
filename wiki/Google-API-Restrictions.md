# Ограничения Google API key

CLI `domain` и `mobile` поддерживают отдельный opt-in metadata-аудит:

```sh
prowl domain example.com --authorized --audit-public --audit-google-restrictions
prowl mobile owned.apk --authorized --audit-public --audit-google-restrictions --format json
```

Перед запуском оператор устанавливает `PROWL_GOOGLE_AUDIT_TOKEN` через защищённый
источник, например passage. Значения credentials не передаются в аргументах команды
и не записываются в конфигурацию сканера. Токен должен иметь OAuth scope
`cloud-platform.read-only` или `cloud-platform` и IAM permissions
`apikeys.keys.lookup` / `apikeys.keys.get` для соответствующего проекта.
Без корректного token новый режим отказывает до acquisition domain/mobile.
Наличие переменной окружения само по себе не включает аудит.

## Что именно читается

Для выжившего после ML типизированного Google key выполняются максимум два GET:

1. `https://apikeys.googleapis.com/v2/keys:lookupKey?keyString=...` определяет
   resource name по найденному ключу. Ответ должен содержать согласованные
   `parent` и `name` с numeric project, `locations/global` и допустимым key ID.
2. `https://apikeys.googleapis.com/v2/projects/.../locations/global/keys/...`
   читает metadata именно этого resource. Имя в ответе проверяется повторно.

Обе операции используют отдельный OAuth оператора. Найденный ключ отправляется
только как аргумент lookup в Google control plane. Сканер не вызывает ListKeys,
GetKeyString, создание/изменение ключей, Maps/Gemini/Translate или иные data API.
Host фиксирован; resource из ответа не становится произвольным endpoint.
Redirects запрещены, DNS/IP guards и bounded timeout сохранены.

Протокол основан на официальных методах
[LookupKey](https://docs.cloud.google.com/api-keys/docs/reference/rest/v2/keys/lookupKey)
и [GetKey](https://docs.cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys/get).
Схема [Key/Restrictions](https://docs.cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys)
используется для различения API targets и client union.

## Интерпретация результата

Результат находится в `public_key_audit`, отдельно от liveness. `verified: true`
и успешный `verification` этот режим не устанавливает.

| Статус | Установленный факт |
|---|---|
| `unrestricted` | Не настроено хотя бы одно измерение: client restrictions или API targets |
| `restrictions_configured` | Оба измерения представлены известными, непустыми полями metadata |
| `inconclusive` | Metadata недоступна, неоднозначна, неизвестна или нарушает контракт/лимит |

`checks` разделяет `google_client_restrictions` и `google_api_restrictions`.
Capabilities `google_client_unrestricted` / `google_api_unrestricted` указывают
конкретное отсутствующее измерение. Browser, server IP/CIDR, Android app/fingerprint
и iOS bundle restrictions распознаются как конфигурационные формы.

Наличие полей не доказывает действенность или достаточную узость policy. Например,
широкий browser pattern остаётся настроенным полем, а не сертификатом безопасности.
Пустой client subtype/list, несколько client subtypes, null вместо ожидаемого
значения, неизвестная форма или регистр поля дают `inconclusive`; семантика
«всем разрешено» или «всем запрещено» для них не угадывается. Пустой/отсутствующий
`apiTargets` означает отсутствие API targets в наблюдённой metadata.

Service-account-bound authorization keys и удалённые ресурсы не квалифицируются
этим начальным контрактом. Ошибка IAM, отключённый API, purged key, transport failure
или HTTP denial не означают отсутствие ограничений и не означают безопасность.
Проверка intended use, effective access, IAM окружения и пригодности ключа для
конкретного приложения остаётся отдельной задачей.

## Сосуществование с Firebase

Прежние Firebase read probes продолжают выполняться по установленным bindings.
OAuth Google не отправляется в RTDB/Storage/Firestore; Firebase key по-прежнему
не отправляется в unauthenticated rules probes. Google restriction observations
добавляются отдельными `checks`. Агрегированный provider становится `google`.

При частичном сбое общий статус — `inconclusive`, но известные Firebase public-read
или Google unconfigured observations сохраняются в checks и occurrences. Вывод
остаётся неполным, exit 2 и baseline guard действуют. Отсутствие Firebase bindings
не препятствует lookup самого типизированного Google key: metadata lookup не
заимствует companions из другого объекта.

## Privacy, cache и лимиты

OAuth credential фиксируется конструктором auditor до передачи workers. Публичного
метода замены токена нет; cache одного invocation не переиспользуется с другим
оператором. Наблюдения deduplicate по точному ключу в памяти, concurrent waiters
получают defensive copies. Inconclusive ответ не становится persistent verdict.

Lookup и metadata GET расходуют по одному запросу из общего бюджета 32. Общий
лимит параллельных probes — четыре; response body — 64 KiB, JSON — depth 16 и
4096 tokens. Дубликаты/escaped aliases, trailing JSON, invalid encoding и неизвестные
поля restriction schema не превращаются в успешный ответ.

`public_key_audit` и его checks не копируют operator token, исходный API key,
resource name/project number, referrers, IPs, Android/iOS identifiers или response
messages. Disclosure самой находки с `--show-secrets` сохраняет обычный контракт.
Scope — opaque digest;
reasons/capabilities имеют фиксированный словарь. Изменение audit policy отражается
в coverage только при явном включении нового режима. Прежняя audit policy и обычный
scan без этого флага сохраняются. Credential baseline не подавляет audited findings.

## Квалификация и остаток

Owned HTTP Pipeline tests проверяют успешный Lookup/Get, Google/Firebase composition,
post-ML ordering, JSON/SARIF/pretty и privacy; transport tests — fixed authority,
authentication, отсутствие redirects, cache/concurrency, ошибки и общий request budget.
Native runner `scripts/check_google_restrictions_cli.py` проверяет реальные CLI guards,
pre-acquisition token validation и сохранность существующих файлов. В JSON/SARIF ±ML
под OS network deny новый режим остаётся честно inconclusive и не пишет baseline;
присутствие OAuth env без opt-in не включает Google audit.

Успешные Google responses квалифицируются собственным HTTP fixture, а не положительным
ответом Google в native CLI. Real-account acceptance остаётся открытым: нужны owned
тестовые ключи с ограничениями и без них и разрешённый operator credential. Проверки
не меняют ключи или provider settings. Source/binary hashes и результаты:
`evidence/1.5.0-google-restrictions-20261116.json`.
