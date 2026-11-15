# Read-only аудит Firebase

`domain` и `mobile` поддерживают `--audit-public --authorized`. Для найденных
Google API keys аудит ищет явную Firebase-конфигурацию: настройки одного объекта
JSON/YAML/TOML, статической JS-группы либо стандартного Android
`google-services.json`. Обычный Google key без такой конфигурации не получает
фиктивный Firebase-результат.

```sh
prowl mobile owned.apk --audit-public --authorized --format json
prowl domain owned.example --audit-public --authorized \
  --audit-firestore-collection public \
  --audit-firestore-collection teams/owned-record/notes --format sarif
```

`--audit-firestore-collection` принимает до восьми явных путей коллекций базы
`(default)`. Путь состоит из нечётного количества сегментов: `collection` либо
`collection/document/collection`. Выбор применяется к подходящим проектам,
наблюдённым в конфигурациях; флаг не является утверждением, что все такие проекты
или коллекции обязательно найдены. Имена коллекций не перебираются и не угадываются.
Без `--audit-public` этот флаг запрещён; без `--authorized` команда отказывает до
чтения конфигурации, источника, отчёта или обращения к провайдеру.

## Что проверяется

| Сервис | Запрос | Граница наблюдения |
|---|---|---|
| RTDB | GET корня `/.json?shallow=true` из `databaseURL` | Принято ли одно неаутентифицированное чтение корня |
| Storage | GET списка корня известного bucket, `maxResults=1` | Принято ли неаутентифицированное перечисление; объекты не скачиваются |
| Firestore | GET явной коллекции, `pageSize=1`, проекция одного поля | Принят ли конкретный неаутентифицированный запрос коллекции `(default)` |

Google API key служит привязкой находки к конфигурации. В Firebase-запросах он
**не передаётся**: отсутствуют Authorization, cookies, App Check token, API-key
headers и query key. Проверяется доступ без аутентификации, не работоспособность
ключа и не его ограничения Google API. Поля `verified` и `verification` не меняются.

RTDB допускает только HTTPS URL корня на `*.firebaseio.com` или региональном
`*.firebasedatabase.app`, без userinfo, порта, query, fragment или вложенного пути.
Явный database URL не выводится из project ID; принадлежность произвольной RTDB
инстанции проекту по одному имени не доказывается. Storage принимает явное имя bucket либо `gs://bucket`, включая custom buckets.
Даже имя, похожее на чужой hostname, становится только частью пути фиксированного
`firebasestorage.googleapis.com`; оно не меняет authority запроса. Принадлежность
bucket проекту по одному имени не доказывается. Произвольные endpoint не поддерживаются.

Firestore проверяется только при явном выборе коллекции. Проекция
`prowlAuditMetadataOnly` уменьшает ответ, но не гарантирует отсутствие данных:
такое поле теоретически может существовать. Никакие значения поля не попадают
в отчёт. Запросы Firestore и Storage расходуют обычные квоты и могут тарифицироваться;
режим предназначен для разрешённых оператором ресурсов.

## Привязки и ограничения

Имена полей сопоставляются без учёта регистра и разделителей `_`, `-`, `.`:
`projectId` / `firebaseProjectId`, `databaseURL` / `firebaseDatabaseURL`,
`storageBucket` / `firebaseStorageBucket`, `authDomain` / `firebaseAuthDomain`.
Неизвестное, пустое или конфликтующее значение компонента адреса/project ID не подменяется
другим alias. Для уже опознанной Firebase-конфигурации отсутствие нужной привязки даёт
`inconclusive`, без запроса.

Для Android используется только документированная связь
`project_info` → `client[].api_key[].current_key` в файле `google-services.json`.
Ключ в `notes`, другом дереве или неподходящем поле не заимствует этот project ID,
даже если его значение совпадает. Проверяются присутствующие в конфиге ключи;
активный Android package/build variant не выбирается и не эмулируется.

Firestore требует явного project ID из 6–30 строчных латинских букв, цифр и дефисов.
Явные RTDB URL и Storage bucket не нуждаются в угадывании project ID. Если project ID
присутствует, его неизвестное или некорректное значение не игнорируется.
Парные компоненты из отдельных файлов/деклараций, специфичный TypeScript/JSX,
XML/plist и dex не связываются. Именованные Firestore databases, известные object get и вложенные RTDB-пути остаются вне этой
проверки. Отказ root/list не доказывает, что другой путь или операция закрыты.

## Интерпретация отчёта

`public_key_audit.provider = firebase`. Массив `checks` содержит отдельные
наблюдения `rtdb`, `storage`, `firestore` с идентификатором `scope`, статусом,
причиной и, при принятом чтении, `data_state = present|empty`. Scope — SHA-256
по `service + NUL + canonical request URL`, не открытый project/path из ответа.
Pretty показывает статусы каждой проверки; JSON, SARIF и occurrences сохраняют
полные отдельные наблюдения.

- `public_read_allowed`: конкретное чтение без аутентификации принято. Это не
  автоматически утечка: данные могут намеренно быть публичными.
- `read_denied`: конкретный запрос отклонён с распознанным 401/403. Это не вывод
  о безопасности других путей, get/list, запросов с иными условиями или всех правил.
- `inconclusive`: привязка, сеть, протокол или лимит не дали достоверного результата.
  Если другие проверки уже наблюдали доступ, этот факт сохраняется в `checks`
  и статических `capabilities`. Частичный результат не превращается в успешное
  полное покрытие: exit 2 и запрет baseline.

Credential baseline не подавляет находки с `public_key_audit`, включая результаты
в occurrences: тот же ключ может сопровождать уже изменившиеся права ресурса.
Запись нового baseline пропускает такие находки и не принимает их credential
identity для последующего обычного скана. Это относится также к Algolia.
Явные фильтры отчёта и `.gitleaksignore` сохраняют собственную семантику.

Пустой ответ 200 не доказывает утечку записей. RTDB `shallow` может вернуть
само значение JSON-примитива; тела ответов ограничены 64 КиБ, проверяются на
корректный Unicode, дубли и ресурсные лимиты и отбрасываются после классификации.
Не выводятся имена записей/объектов, содержимое, pagination tokens, сырые URL
ошибок или провайдерские сообщения. `--show-secrets` по-прежнему может раскрыть
исходную находку, но не значения ответов Firebase.

Общие с Algolia лимиты команды: до 32 попыток HTTP-запросов, четыре одновременно,
не более 10 секунд на запрос; редиректы запрещены. Неаутентифицированные проверки
одного URL объединяются независимо от значения Google key. Ошибки не кешируются
как окончательный результат; отменённый caller не получает кешированное успешное
наблюдение. Изменение списка коллекций меняет policy scope; сами пути в policy
не публикуются. ML, если включён, применяется до аудита: отфильтрованные им
кандидаты не порождают запросов.

## Основания контракта

- [Firebase API keys](https://firebase.google.com/docs/projects/api-keys): ключи
  приложения и защита данных правилами — разные механизмы.
- [RTDB REST](https://firebase.google.com/docs/reference/rest/database): shallow
  ограничивает глубину объекта, но возвращает исходные примитивы.
- [Firestore listDocuments](https://firebase.google.com/docs/firestore/reference/rest/v1/projects.databases.documents/listDocuments)
  и [DocumentMask](https://firebase.google.com/docs/firestore/reference/rest/v1/DocumentMask):
  ограничение страницы и проекция не дают глобального утверждения о правилах.
- [Storage list](https://firebase.google.com/docs/storage/web/list-files) и
  [официальный SDK](https://github.com/firebase/firebase-js-sdk/blob/main/packages/storage/src/implementation/requests.ts):
  перечисление зависит от Rules Version 2; get и list различаются.
- [Android Google services schema](https://firebase.google.com/docs/android/google-services-plugin-and-file):
  project_info относится к клиентам проекта, API key находится в client/api_key.

Реальные аккаунты и полные security rules не квалифицированы. Успешный HTTP
контракт проверяется на собственном локальном fixture; для нативной проверки
используется OS network deny. Финальные release images и установленная локальная
ML-модель относятся к отдельной квалификации.

Локальная нативная матрица — 39/39; проверены L1 и ML с явной portable-моделью
(51 признак), три запланированных сервиса, minimal RTDB/custom bucket, Android,
отказы до транспорта, CLI preflight, JSON/SARIF/pretty, opt-out и сохранность
baseline. Во всех шести ML-фикстурах кандидат сохранился; это не общая оценка
recall. Full Go, race, lint, Go 1.26.11 и четыре целевых fuzz-прогона проходят.
[Evidence](evidence/1.5.0-firebase-audit-20261115.json) разделяет source/binary/model
и границы Docker-кандидата. Существующая установленная модель не изменялась.
