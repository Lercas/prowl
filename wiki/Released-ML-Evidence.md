# Удержание прямых credential bindings при ML

Выпущенный каскад 1.4.0 удерживал часть кандидатов с точным credential binding,
когда модель оценивала их как хеши или обычные слова. При миграции этот контракт
потерялся: новый каскад сохранял 201 из 308 released positive cases.

Восстановлен ограниченный слой nomination retention. При проверке используется
имя фактически соседнего assignment либо binding, установленный structured parser.
Прежнее имя в обученном ML-контексте может принадлежать первому полю minified-строки;
оно не используется как доказательство для удержания другого значения.
Локальное поле `Record.DirectBinding` не входит в признаки, sidecar JSON или feedback.

## Область удержания

- Пароль: только `generic_password`, стадия `L1-regex`, не менее шести байт и
  password/passphrase/passwd/pwd либо поддержанное языковое имя пароля.
  Сохранены released формы `pass`, `pw`, suffix `_pass`, `_pw`, `.pass`, `.pw`.
- Hex-ключ: 32–128 hex-символов, точный secret binding и соответствующая
  lexical/entropy/key-стадия. Имя `checksum` и произвольный контекст не защищают значение.
- AssemblyAI/Together/Linode: provider-qualified имя ключа/токена и rule nomination.
- Deepgram/Twitch: конкретные варианты provider credential binding плюс длина
  40/30 символов и ASCII base36-представление из установленного rule-контракта.
  Имена вроде `deepgram_checksum` и `twitch_user_id` не подходят.
- Сохранены released format guards для Netlify `nfp_` и Sentry DSN с обеими
  32-символьными credential-компонентами.

Parser-normalized JSON/YAML/TOML используют тот же контракт. Contextual password
guesses, semantic candidates, недоказанные имена и новые значения короче шести байт
сохраняют обычное решение модели. Для последних действуют прежние short-password
и short-key tests. Сохранение кандидата не меняет confidence и не делает его LIVE;
провайдерская проверка остаётся отдельным этапом.

## Квалификация

Оба released корпуса неизменны: 308 positives сохраняются с настоящей embedded-моделью,
334 negatives не дают находок. Два ambiguous cases остаются только кандидатами.
Все исходные feature vectors и численные model scores совпали с предыдущей ревизией:
это восстановление политики каскада, не переобучение или снижение порога.

Нативный runner проверяет CLI со штатным порогом 0,3 и отдельные JSON/SARIF случаи
с порогом 1. Последние подтверждают удержание независимо от высокой оценки модели.

```sh
python3 scripts/check_released_noise_ml.py /path/to/prowl
```

Диагностика score/features без raw values, source lines и binding names:

```sh
cd tool
PROWL_NOISE_MODEL_AUDIT=/absolute/output.json \
  go test ./internal/scan -run '^TestReleasedNoiseModelAudit$' -count=1
```

Закреплённый quality gate: 1661/2094, FP 61/982. По сравнению с предыдущим
кандидатом добавлены 101 positive ID без потерь и четыре false-positive ID:
`pb-03856`, `pb-05784`, `pb-10408`, `pb-19952`. Пределы 1554/61 сохранены.
Корпус, модель, пользовательская installed-модель и baseline не менялись.
Исторические performance receipts не являются новым измерением этой ревизии.

Точные ревизии, logs и границы — `evidence/1.5.0-ml-evidence-20261116.json`.
Результат локальный; он не доказывает hosted CI, provider-account acceptance
или готовность опубликованного релиза.
