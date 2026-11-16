# Снимок конфигурации и allowlist

В P0-аудите перехода с 1.4.0 воспроизведена потеря `detector_config` scope и
признака `filtered` для конфигурации с подавлениями. Разные allowlist/config
по одному пути получали одинаковые scopes двух полных unfiltered отчётов;
`remediation-check` разрешал `absent_in_scope`. Synthetic secret действительно
удалялся из выбранного файла: речь о неверном равенстве policy, а не об обходе
существующего guard при фактическом подавлении находки.

## Итоговая policy

`scan.Options.Config` описывает уже применённую конфигурацию. Таксономия,
источники и CLI limits по-прежнему настраиваются их владельцами до `scan.New`.
Конструктор делает immutable snapshot деклараций и действующей allowlist
после импортов/merges правил; изменяемый исходный `Config` не сохраняется.
Снимок копирует slices/maps и scalar pointer, а compiled regexes разделяет
как read-only зависимости. Внутренние regexes недоступны внешнему вызывающему коду.

`detector_config` scope с revision `loaded-config-v1` включает декларации и
эффективные values/paths/regexes/stopwords. Декларация без compiled state не
заимствует identity действующей allowlist. YAML encoding сохраняет binary strings;
filename, исходные YAML bytes и presentation comments исключены.
В JSON/SARIF попадают только scope hashes, с прежним HMAC при identity key.
Значения исключений и regexes не раскрываются через metadata.

CLI source adapters, `compare`, HTTP worker и LSP передают эту конфигурацию.
LSP сохраняет Pipeline построенного workspace, а не перечитывает config на
каждую диагностику. `WithRevealSecrets` и внутренние child scans используют
тот же снимок. Изменение исходного объекта после `New`, включая MergeAllowlist,
не меняет уже запущенную allow policy.

Как в 1.4.0, наличие enable/disable или allowlist declarations помечает отчёт
`filtered`, даже если исключения не сработали и input пуст. Это консервативная
граница для подтверждения отсутствия. Неприменённые небезопасные match-all
исключения тоже остаются declared suppression; защитный отказ от их выполнения
сохраняется. Custom detectors сами по себе не считаются подавлением.

## Callback и ошибки

Прежний `Options.Allow` остаётся доступным без изменения порядка фильтрации.
Без описанной конфигурации он получает `unversioned_policy` target `allow`:
успешный скан complete, но сравнение не сертифицирует отсутствие. Наблюдаемое
присутствие сохраняется. Указание одновременно Config и произвольного Allow
не позволяет приписать чужой policy digest callback: скан завершается неполным
до callback/ML/provider, в том числе для пустого stream.

Snapshot ограничен 100000 string entries и 32 МиБ суммарных исходных строк;
canonical YAML тоже не более 32 МиБ. Input считается до копирования, сериализованный
размер проверяется отдельно. Это содержательные bounds, не точный лимит Go heap.
Ошибка/лимит дают `configuration_policy_failed`, неполноту, exit 2 и запрет baseline.
Metadata не отражает исходный сериализационный error с возможными private values.

Снимок не переводит process-wide detection tuning/operational setters в per-Pipeline
состояние и не аутентифицирует произвольные callbacks. Эти границы, как и остальные
P0-контракты, требуют собственной проверки. Исторические evidence JSON не меняются
и не переквалифицируются задним числом.

## Локальная проверка

```sh
sandbox-exec -p '(version 1)(allow default)(deny network*)' \
  python3 -I scripts/check_config_policy_native.py /path/to/prowl
```

Runner использует только созданные им config/gitleaks/identity fixtures и явную
каноническую Go-модель. Проверяются default controls, конфигурационный drift,
unused suppressions, файл с другим именем, imported allowlist, JSON/SARIF ±L2,
remediation и baseline при budget failure. Провайдеры не вызываются.

Квалификация: native 289/289, coverage 90/90, HTTP 57/57, MCP 80/80,
LSP 2332/2332, предыдущий loaded-policy runner 134/134 и correlation 46/46.
В coverage/HTTP runners точные множества scope kinds расширены только новым
`detector_config`; остальные assertions сохранены. Полный Go, targeted race,
минимум Go 1.26.11 и lint проходят. Шесть static builds подтверждены build-info;
foreign execution не заявляется. Quality result keys, кроме binary SHA, и default
corpus digest прежние. [Доказательства](evidence/1.5.0-config-policy-20261116.json).
