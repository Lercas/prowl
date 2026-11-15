# Происхождение находок в контейнерных образах

Источник `image` в 1.5.0 отделяет выбранный tar/OCI-directory/registry ref/stdin,
наблюдаемые manifest/config bytes, распакованный слой и отдельный файл.
Отображаемые пути `<image>|layerN:file` и `<image>|image:config/field` сохраняются.
Acquisition scope использует revision `1.5.0-image-source-v1`.

## Digest и преобразования

- `image_digest` — SHA-256 наблюдаемого `RawManifest`. Для Docker-save библиотека
  строит manifest представления image; это не hash внешнего tar или `manifest.json`
  формата Docker-save и не доказательство registry-подписи.
- `config_digest` — SHA-256 прочитанных raw config JSON bytes. Поля config и history
  выводятся из того же разобранного snapshot. Несовпадение с известным SHA-256
  descriptor даёт неполноту, сохраняя доступный текст.
- `digest` у файла — SHA-256 сырых байтов member до декодирования; у config view —
  SHA-256 конкретного отображаемого текста (`Env`, labels, history и т. п.).
- `layer_diff_id` — SHA-256 полного распакованного TAR-потока, включая байты,
  прочитанные TAR-reader и последующее дочитывание. Он фиксируется только после
  EOF, успешного закрытия и отсутствия отмены. Это не digest сжатого blob;
  поле `layer_digest` этим источником не подменяется.

`source_transform` различает `image-file`, `image-text-decoded` и
`image-config-rendered`. Координаты относятся к конкретному тексту; для UTF-16
они не выдаются за byte offsets исходного member. SHA-256 diff ID сверяется
с доступным соответствующим `rootfs.diff_ids`. Несовпадение или неподдерживаемый
expected digest не сертифицирует image complete. Уже полностью прочитанный слой
может сохранить свой **наблюдаемый** digest при ошибке в descriptor.

OCI metadata blobs проверяются по SHA-256/SHA-512 content-address до помещения
в общий bounded cache. Повреждённые blobs не становятся доверенными metadata.
Это не отдельная квалификация подписей, всех registry-auth режимов или wire-level
digest сжатых layers.

## Идентичность и финализация

SARIF `artifactLocation.uri`, provenance `source_url` и индекс используют
source-declared URI с `image+file`, `image+oci`, `image+ref` или `image+stdin`.
Fragment разделяет image slot, config view или слой/member. Локальный источник
имеет абсолютный выбранный путь; stdin не получает случайное имя временного spool.
Registry ref разбирается до загрузки; неверный ref не отражает случайно вставленные
URL credentials/query в ошибке.

Private identity отделена от display path. Одинаковые относительные labels из
разных acquisition не заимствуют flatten-index друг друга. Физический TAR ordinal
разделяет повторные entry в occurrence ID и HMAC места индекса; номер и внутренняя
ссылка acquisition scope не экспортируются. Значение сохраняет общий secret/value ID.

Layer digest становится известен после обработки Items. `MarkFinalImage` выполняется
после drain, до дедупликации: добавляет наблюдаемый `layer_diff_id`, пересчитывает
keyed occurrence identity тем же report key и назначает `in_final_image`.
Внутренний вызов с keyed findings должен передавать тот же key третьим аргументом;
без него изменённый occurrence ID очищается, а не сохраняется как корректный.
Ledger digest ограничен 10000 слоями на acquisition.

JSON и SARIF сохраняют `in_final_image` в summary и отдельных occurrences:
`true` — путь принадлежит этой entry в вычисленном flattened image,
`false` — замещён/whiteouted, отсутствие — неизвестно. Это не утверждение,
что image запущен, развёрнут или что найденный ключ live.

## Disclosure и ошибки

`instruction` — сырой build-history контекст: в нём может быть другой секрет,
которого нет в текущем файле. Он выводится только с явным `--show-secrets`, как
и source context. В этом режиме поле сохраняется в JSON/SARIF и occurrences;
по умолчанию оно отсутствует. Отдельное сканирование history и маскирование
самих находок продолжают работать.

Новая acquisition не наследует metadata/locator предыдущего producer. Ошибки
загрузки, metadata, TAR, checksum/close или budget сохраняют неполноту, код 2
и baseline guard. Сырые registry/OS/parser ошибки не отражаются в CLI.
При неполноте flatten verdict остаётся unknown; валидный текст и его известные
hashes не выдаются за доказательство полного image.

## Воспроизведение и границы

```sh
python3 scripts/check_image_provenance.py /path/to/prowl
```

Матрица создаёт собственные Docker-save, OCI-directory и stdin fixtures,
отдельный `PROWL_HOME` и index. Проверенный macOS `deny network*` блокирует
loopback control. Используются синтетические значения и явная Go-модель с 51
признаком. Docker daemon, registry, production и клиентские образы не меняются.
Актуальная повторная квалификация, включая fixed performance gate, —
`evidence/1.5.0-image-provenance-20261116.json`.
Отчёт `evidence/1.5.0-image-provenance-20261115.json` сохраняет историю прежнего
дискового блокера; его временные артефакты больше недоступны. Новые native matrices
сохранены рядом с актуальным evidence, а не только во временных каталогах.
Это source/native darwin-arm64 квалификация. Итоговые Docker/Linux images,
registry/runtime acceptance, hosted CI и публикация релиза остаются отдельными задачами.
