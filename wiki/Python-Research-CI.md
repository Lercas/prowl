# Python research: подготовка CI

## Состояние

По явному выбору владельца канонический локальный репозиторий —
`/Users/sugar/dev/prowl-research`, commit `a3e586151b8a5337b4a3e91ab5e18aa4e353f9e8`.
29 файлов source/CI/provenance, без корпусов и весов моделей. Рабочее дерево чистое,
remote при локальной квалификации отсутствует. Публикация, push и hosted CI пока
не выполнялись, поэтому общий пункт TODO остаётся открытым.

В `.gitignore` Prowl явно исключены `src/`, `tests/`, `references/` и `pyproject.toml`:
репозиторий содержит только сканер. Добавить здесь вызов двух локальных тестов
недостаточно: в чистом checkout соответствующих файлов нет. Исходный Python-код
не добавлялся в Git сканера и не изменялся. Research workflow размещён отдельно;
Docker CI сканера квалифицируется собственным этапом.

## Применённый пакет

Временный архив утрачен при внешней очистке. Все 18 исходных source/test файлов
сохранились с прежними hashes; четыре CI-файла восстановлены byte-identically
из сохранённых данных подготовки и сверены с manifest. Stable SHA-256 seed
сохранён. Оригиналы scanner checkout не изменялись.

В новом репозитории есть `README.md`, `AGENTS.md`, `import-manifest.json`,
`package-manifest.json` и `qualification/20261116.json`. Lock с hashes заново
собран из тех же direct pins: NumPy 2.4.6, PyYAML 6.0.3, pytest 9.1.0.
Его command header нормализован для нового проекта; восстановление прежнего
архива byte-for-byte не заявляется. Новая матрица Python 3.12.13/3.14.9 × seeds
0/1 — 4×41. Все 15 imports происходят из нового checkout, оба virtualenv изолированы.
Проверены OS network deny контрольным запросом и actionlint 1.7.12.
Текущий evidence — `evidence/1.5.0-python-research-canonical-20261116.json`.

## Исторический handoff

Исторический архив, теперь недоступен: `/tmp/prowl-python-research-ci-20261115-v2.tar.gz`

SHA-256: `a49df7a895d3b92d95cdff87c4df06dc12f8725f5712264c97762ff173f2832b`

27 файлов, 42452 байт. Включены только два исходных теста,
15 импортируемых модулей (включая package markers), taxonomy и файлы CI.
`import-manifest.json` хранит исходные/пакетные hashes; `package-manifest.json`
проверяет точный состав архива. Корпуса, веса моделей и неиспользуемый research-код
не включены. Это handoff для размещения, а не альтернативный источник продукта.

В копии исправлен случайный между процессами seed `hash(type_id)`: используется
SHA-256. Добавлен запрет сети при collection и во время тестов; два теста подтверждают
отказ DNS/соединения. Зависимости зафиксированы версиями и hashes. GitHub workflow
закрепляет Actions по SHA, использует `contents: read` и не сохраняет credentials.

## Проверка

Матрица Python 3.12/3.14 × hash seed 0/1: четыре прогона по 41 тесту
(39 исходных и два теста сетевого guard). Затем архив распакован в новый каталог:
оба интерпретатора снова прошли 41/41 под OS network deny. Проверены hashes всех
файлов и реальные `module.__file__`: все 15 imports `src.*` происходят из распакованного
архива, а не из исходного Prowl checkout. Actionlint 1.7.12 проходит и на распакованном
workflow. Нативные версии Python и зависимости записаны в evidence.

## Осталось

1. После отдельного разрешения создать/подключить внешний research-репозиторий
   и отправить проверенный локальный commit.
2. Проверить фактическую матрицу hosted Linux CI. Локальные macOS результаты
   и наличие workflow не заменяют исполнение на runner.

Эти unit-тесты прежнего Python research-кода не доказывают parity с Go-flate-v2,
качество L2, работу sidecar, точность ProwlBench или готовность релиза 1.5.0.
[Evidence](evidence/1.5.0-python-research-ci-handoff-20261115.json).
