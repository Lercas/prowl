# Аудит публичного доступа Supabase

`domain` и `mobile` поддерживают opt-in `--audit-public --authorized` с явным
списком до восьми таблиц: `--audit-supabase-table NAME`. Таблицы не угадываются,
OpenAPI и каталоги не запрашиваются. Выбор применяется к подходящим найденным
конфигурациям; оператор должен иметь разрешение на каждый такой проект.

```sh
prowl mobile owned.apk --audit-public --authorized \
  --audit-supabase-table public_posts --format json
```

## Запрос и ключи

Один `HEAD https://PROJECT.supabase.co/rest/v1/TABLE?limit=1` на таблицу:
GET-эквивалентное чтение без тела ответа. Заголовки — ключ в `apikey`,
`Accept: application/json`, `Accept-Profile: public`. Нет пользовательского JWT,
Authorization, cookies, count, RPC, записи, вложенных запросов и pagination.
Обычное чтение может запускать серверные политики/предзапросы и расходовать квоту;
код этих политик сканер не контролирует.

URL — только HTTPS root managed-проекта с 20-символьным ref из строчных букв/цифр,
без userinfo, порта, query, fragment или вложенного пути. Custom/self-hosted
endpoints не поддерживаются. Таблица — один ASCII identifier длиной 1–63,
начинающийся с буквы/подчёркивания; только schema `public`. Все редиректы запрещены.

- `sb_publishable_` с 20–128 URL-safe символами после префикса — синтаксический
  допуск, не подтверждение действительности. Только в audit-режиме добавляется
  субъект `supabase-publishable-key`, severity `info`: ключ сам по себе не утечка.
- Legacy JWT: header только `alg=HS256, typ=JWT`, payload только `iss=supabase`,
  `ref`, `role=anon`, целые положительные `iat`/`exp`, signature 32 байта.
  Base64url каноничен, JSON без дублей и с лимитами. Подпись локально не
  аутентифицируется; ref обязан совпасть с явным URL. Claims не доказывают валидность.

`sb_secret_`, service-role, user-session JWT и расширенные legacy-claims этим
аудитом не отправляются и не получают фиктивного успешного результата.
Прежние независимые находки детектора сохраняются.

## Привязка

Точное полное значение кандидата и URL — только из одного объекта JSON/YAML/TOML
или поддержанной статической JS-группы. Имена: `supabaseUrl`, `supabaseProjectUrl`,
`NEXT_PUBLIC_SUPABASE_URL`, `VITE_SUPABASE_URL`, `REACT_APP_SUPABASE_URL`,
`EXPO_PUBLIC_SUPABASE_URL`; регистр и разделители `_-.` несущественны.
Пустые, неизвестные или конфликтующие aliases не заменяются другой настройкой.
Соседние объекты/файлы не заимствуются. Без URL или таблиц — `inconclusive`, без
запроса. XML/plist/dex, `.env` и связи отдельных деклараций не добавлены.

Аудит выполняется после ML. Сохранены прежние ML-исключения, включая структурно
проверенные JWT; остальные кандидаты могут быть отфильтрованы моделью.
С verification-флагами режим не совмещается. MCP/HTTP/LSP его не включают.

## Наблюдения

`public_key_audit.provider = supabase`, `checks[].service = supabase-table`.
Scope — SHA-256 по service + NUL + canonical URL. Cache identity дополнительно
включает ключ: credentials не разделяют результат доступа. Общие лимиты с
Firebase/Algolia — 32 попытки за invocation, четыре одновременно, до 10 секунд.

- `public_read_allowed`: HEAD принят без пользовательской сессии; HTTP 200/206,
  JSON media type и ожидаемый bounded Content-Range.
- `read_denied`: конкретный HEAD отклонён HTTP 403, без утверждения о причине,
  действительности ключа или правах других операций.
- `inconclusive`: 401/404/429, сеть, иной статус, неоднозначные заголовки,
  лимит или небезопасная привязка. Другие успешные checks/capabilities сохраняются,
  но итог неполный, exit 2 и запрет записи baseline.

Принятие запроса и пустой результат **не доказывают отсутствие RLS**, читаемые
строки или непреднамеренную публикацию. Сервер может скрыть строки политикой либо
намеренно открыть их. INSERT/UPDATE/DELETE, другие schemas/filters/роли и RLS
configuration не квалифицируются. `verified`/`verification` не меняются.
Credential baseline не скрывает audit-находки и не принимает их identity.

Тела ответов не читаются. Audit metadata не содержит raw URL, имён таблиц,
response headers/row counts, записей и provider messages. Обычные source-поля
сохраняют прежнюю семантику redaction и явного `--show-secrets`.

## Основания и квалификация

- [Supabase API keys](https://supabase.com/docs/guides/getting-started/api-keys):
  роли, отличие grants от RLS и пустой результат при политике.
- [Supabase Data API](https://supabase.com/docs/guides/api/creating-routes):
  managed endpoint и `apikey` header.
- [PostgREST HEAD](https://docs.postgrest.org/en/stable/references/api/tables_views.html):
  эквивалент GET без тела.
- [PostgREST range/count](https://docs.postgrest.org/en/stable/references/api/pagination_count.html):
  limit/Content-Range; полный count здесь не запрашивается.

Реальные аккаунты/RLS требуют отдельной квалификации на разрешённом ресурсе.
Локальные fixture и OS network-deny проверки не заменяют её.
