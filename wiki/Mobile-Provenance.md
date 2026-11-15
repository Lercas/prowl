# Происхождение находок APK/IPA

Mobile intake 1.5.0 сохраняет отображаемый путь `app.apk!/entry`, а область
идентичности отделяет от имени архива. Два `app.apk` в разных каталогах больше
не получают одинаковые fingerprints и позиции индекса только из-за basename.
Путь и текст для ML остаются прежними.

SARIF `artifactLocation.uri` и JSON/SARIF `provenance.source_url` задают публичный локатор:

- `mobile+file:///absolute/app.apk#/entry` — явно выбранный локальный архив;
- `mobile+https://host/app.apk#/entry` — исходный HTTP(S) URL загрузки;
- `mobile+payload:/logical-name#/entry` — заимствованные байты `MobileBytes`,
  без утверждения, что они получены с диска или по сети.

Fragment в этих URI — имя ZIP-member. Спецсимволы кодируются как компоненты URI;
он не является query/fragment сетевого запроса. Из публичного URL загрузки
удаляются credentials и query. Путь временной загрузки в идентичность не входит.
Перенаправление не превращает конечный URL в доказанную исходную ревизию.

`provenance.digest` — SHA-256 точных распакованных байтов одного member после
успешного чтения до EOF и проверки ZIP CRC, до декодирования текста или извлечения
строк. Это не digest целого APK/IPA, подписи пакета или установленного приложения.
Одинаковое содержимое двух members даёт одинаковый digest.

`source_transform=mobile-text-decoded` обозначает декодированный текст;
`mobile-printable-strings` — склеенные печатные последовательности бинарного
member. Координаты относятся к этому текстовому представлению, не к байтам DEX,
AXML, binary plist или Mach-O. Printable strings дают кандидатов, но не доказывают
связь полей конфигурации: составная верификация и публичный аудит не получают
companions из такого представления. Независимая проверка отдельного ключа остаётся
возможной при явном `--verify`.

С report identity key приватный селектор загрузки (включая credentials/query)
входит в HMAC fingerprint и occurrence identity. Одинаковый запрос сохраняет
идентичность при новой временной директории; разные селекторы не сливаются даже
при одинаковом публичном URI. Без ключа fingerprint использует только публичный
URI, не публикует hash приватного селектора. Значение по-прежнему имеет общий
`secret_id` независимо от архива. Внутренний ordinal ZIP central-directory
разделяет повторные записи в keyed occurrence и индексе; номер не экспортируется.
Report и index keys сохраняют отдельные namespaces.

Scope `mobile` использует policy revision `1.5.0-mobile-source-v1` и digest
выбранного приватного селектора с настройками чтения. При report identity key
policy также HMAC. Старые parent filesystem/repo/bucket provenance не переносятся
на новую mobile acquisition. Общая `DetectionRevision` не меняется: изменены
контракт этого источника и обработка его производного представления.

Ошибка загрузки, отсутствующий файл или неверный ZIP возвращают неполный
JSON/SARIF с диагностикой `mobile_acquisition_failed`, exit 2 и запретом записи
baseline. Секреты из URL и сырые HTTP/OS ошибки в такой отчёт не попадают;
digest содержимого при неудавшейся acquisition не придумывается.

Воспроизводимая нативная проверка:

```sh
python3 scripts/check_mobile_provenance.py /path/to/prowl
```

Runner создаёт отдельный `PROWL_HOME`, report/index keys и синтетические APK/IPA.
Локальные сценарии выполняются под проверенным macOS `deny network*`; загрузка
проверяется отдельно на собственном loopback HTTP server без provider flags.
Результаты и границы квалификации — в
`evidence/1.5.0-mobile-provenance-20261115.json`. Это не проверка реальных мобильных
пакетов, удалённых провайдеров, Linux/Docker, hosted CI или production runtime.
