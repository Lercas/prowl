# Изоляция настроек детектора

`scan.New` сохраняет снимок трёх настроек L1: `generic_entropy_min`,
`placeholder_max_entropy` и `max_matches_per_file`. Изменение другого Pipeline,
workspace или legacy defaults не меняет уже созданный Pipeline.

CLI и LSP создают `detect.NewWithTuning` из built-in defaults и выбранного Config.
Нулевые и отрицательные значения сохраняют defaults; они не наследуют настройки
предыдущего Config. После создания значения не перечитываются из Config.
Защитный tuning lookup при отсутствующем L1-детекторе возвращает built-in
defaults. Это не добавляет поддержку scan без детектора: непустой scan
по-прежнему завершается как incomplete.

Снимок сохраняется для nested Base64, JWT, normalized/literal views, static
reconstruction, template merge и общего candidate cap. Проверка placeholder
перед provider verification использует настройки исходного кандидата, включая
structured literals, decoded context и component batches. Compiled detector engine
и concurrency-safe scratch pools могут совместно использоваться снимками.

`Detector.PolicyDigest()` включает все три эффективных значения при отличии от
built-in defaults. Digest defaults сохранён, поэтому старые default scope IDs
не меняются. Разные настройки без Config также дают разные detection policy scopes
и не позволяют сертифицировать `absent_in_scope` между разными policies.
Ошибка сериализации policy по-прежнему делает scan неполным.

## Legacy API

`detect.New` и `detect.ApplyTuning` сохраняют прежний контракт прямого вызова:
изменение defaults влияет на следующий direct detector Scan. Каждый такой Scan
атомарно захватывает одну согласованную тройку настроек на входе; вложенные проходы
используют ту же тройку. `ApplyTuning` не меняет уже созданные Pipeline или
`NewWithTuning`. Standalone compatibility helpers также читают legacy defaults.

## Проверки и границы

Регрессионный тест на исходном коде воспроизвёл влияние поздней смены entropy floor
на уже созданный Pipeline. Новые проверки покрывают отдельные thresholds и cap,
вложенные producers, scope comparison, derived Pipeline, независимость CLI/LSP
и конкурентные обновления legacy defaults. Provider tests используют только owned
loopback HTTP endpoint, реальные ключи или providers не вызываются.

Final source: полный Go suite, targeted race/min-Go regression cases и lint;
до defensive nil-detector lookup также прошли полные race/min-Go suites четырёх
изменённых packages. Native config policy — 289/289 под OS network deny.
Quality IDs и GOROOT digest сохранены. Три alternating performance pairs против
фиксированной базы: время +15,17% при лимите 20%, bytes −2,10%, allocations +3,06%.
Шесть static builds собраны; чужие платформы не запускались.

Квалификация и хеши артефактов: `evidence/1.5.0-detector-tuning-20261116.json`.

Операционные `forge.SetMaxPages`, `verify.SetConcurrency` и
`source.SetCloneTimeout` ещё используют process-wide defaults. Их границы требуют
отдельного аудита; этот результат не завершает полный переход на 1.5.0.
