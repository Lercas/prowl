# Контекст проверки декодированных credentials

Верификация typed primary из декодированного blob использует содержимое именно
этого blob. Внешний encoded source, соседний blob и промежуточная оболочка не
подставляют companion-поля. Два вхождения одного ключа с разными companions
получают собственные вердикты и отдельные occurrence metadata.

Восстановленный released test воспроизводит прежнюю ошибку на двух Base64 blobs
и вложенном Base64. Дополнительные проверки охватывают hex, gzip+Base64,
zlib+Base64 и Base64 поверх hex. Значение primary обязано точно совпасть с
подтверждённым диапазоном decoded snapshot до provider call. Неоднозначность
companions проверяется прежним bounded extractor до cache lookup.

JWT claims, mobile-derived/unbound views и cross-file components сохраняют
свои более строгие guards: они не получают разрешение заимствовать компоненты
из внешней конфигурации. Это не добавляет новые provider verifiers или source
adapters и не меняет порядок ML/verification.

## Память и приватность

Контекст нелинейного декодирования хранится отдельно от ML/disclosure context,
не экспортируется в Finding и не меняет observed source coordinates.
Захват включён только при выбранном verifier registry. Обычный L1/ML scan
не удерживает дополнительный private context и не ограничивается его бюджетом.

Каждый из двух нелинейных sweeps ограничен 32 MiB удерживаемых decoded contexts.
При исчерпании бюджета проход прекращается с признаком неполноты. Это предел
содержимого конкретного sweep, а не точный предел Go heap всего процесса;
существующие per-blob decode/depth/output budgets действуют отдельно.
Дополнительный private context не передаётся в JSON/SARIF или SQLite.
Политика явного раскрытия `--show-secrets` остаётся прежней.

## Воспроизведение

```sh
python3 scripts/check_decoded_verification_contexts.py /path/to/prowl
```

Runner использует synthetic credentials и собственный loopback stub. Матрица
228/228 включает шесть вариантов кодирования, JSON/SARIF, ML, default/verify-all/
index ordering, dedupe с отдельными вердиктами occurrences и отказ заимствовать
внешний companion при его отсутствии в blob.

Четыре исходных теста `verification_pipeline_test.go` проходят на пересобранном
неизменённом 1.4.0. Адаптация к 1.5 использует immutable Pipeline и исключает
служебные coverage markers только из legacy counts в двух YAML assertions.
Markers сохраняются в production result; успешное полное покрытие этих YAML
сценариев не заявляется. Проверки исходных spans, числа HTTP requests,
раздельных вердиктов и occurrence IDs сохранены.

Доказательства: `evidence/1.5.0-verification-contexts-20261116.json`.
Локальный stub не подтверждает acceptance реальных provider accounts или hosted CI.
