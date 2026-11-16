# Целостность выбранных шаблонов

`scan` использует выбранные наборы rules/verifiers. Если рядом есть
`MANIFEST.sha256`, проверяются именно захваченные для компиляции bytes:
изменённый, отсутствующий или не перечисленный YAML-файл отклоняет набор.
Повреждённый manifest, повтор пути, выход за корень и небезопасные файловые
представления также не дают успешного скана. Неполный скан возвращает exit 2
и не перезаписывает baseline.

Manifest-less локальные пользовательские наборы поддержаны намеренно.
`--rules-dir` и `--verifiers` явно выбирают набор; `--bundled` исключает
невыбранные установленные overlays и проверяет встроенный snapshot.
Команды `rules/verifiers list` и `validate` также проверяют manifest.

Checksum manifest обнаруживает несогласованность файлов. Он не является
цифровой подписью и не аутентифицирует источник, который может изменить и YAML,
и manifest. Для стороннего `--source` требуется отдельный `--allow-unsigned`;
это политика доверия, а не доказательство безопасности шаблонов.

## Воспроизведение

```sh
python3 scripts/check_template_integrity_contract.py /path/to/prowl
```

Runner создаёт собственный временный `PROWL_HOME`, не меняет установленную
библиотеку пользователя и не выполняет update. Сценарии для rules и verifiers:
manifest отсутствует, корректен, сохраняет пробелы в имени; hash mismatch,
unlisted/missing file, malformed/duplicate/unsafe path, directory или symlink
вместо manifest, внешний symlink вместо template. Проверяются installed/explicit
selection, list/validate, baseline guard и явный bundled fallback.

Локальная матрица 182/182 прошла как на кандидате 1.5.0, так и на неизменённом
теге 1.4.0, пересобранном из 694 проверенных Git blobs. Оба запуска выполнены
с OS network deny. Это проверка локального CLI; live-provider acceptance,
удалённая установка/обновление и подписи опубликованных assets сюда не входят.
Целевые Go-тесты отдельно проверяют captured-byte consistency, bounds и trust
policy. Доказательства: `evidence/1.5.0-template-integrity-20261116.json`.
