# Выпуск Prowl начиная с 1.5.0

Сборку, архивы, SPDX SBOM и `checksums.txt` описывает `tool/.goreleaser.yaml`.
Workflow `.github/workflows/release.yml` использует этот конфиг, подписывает результаты
и обновляет Homebrew. Actions закреплены по SHA; инструменты — GoReleaser 2.20.2,
Syft 1.57.1, cosign 3.1.4 и Go 1.27.4.

## До публикации

Рабочее дерево должно быть зафиксировано и пройти обычный CI, включая snapshot
релиза и static-ML smoke. Теги `v1.5.0` и `tool/v1.5.0` должны указывать на один
проверенный коммит: второй нужен Go-модулю в подкаталоге `tool/`.
Публикация требует отдельного разрешения владельца; создание локального snapshot
не разрешает push, создание внешнего релиза или обновление tap.

Для стабильного релиза нужен секрет GitHub Actions `HOMEBREW_TAP_GITHUB_TOKEN`
с правом Contents: write в `Lercas/homebrew-tap`. Обычный `GITHUB_TOKEN` ограничен
репозиторием Prowl и не заменяет его. Preflight завершает workflow до публикации,
если секрет отсутствует. Значения секретов в журнал не выводятся.

## Локальный snapshot

Указанные версии GoReleaser и Syft должны быть доступны в `PATH`. Скрипт требует
новый выходной каталог и не удаляет предыдущие результаты:

```sh
snapshot_root=$(mktemp -d /tmp/prowl-release.XXXXXX)
GOTOOLCHAIN=go1.27.4 python3 scripts/release/snapshot.py \
  --dist "$snapshot_root/artifacts" --version 1.5.0-dev
python3 scripts/release/verify_artifacts.py "$snapshot_root/artifacts"
python3 scripts/release/homebrew.py --tag v1.5.0-dev \
  --checksums "$snapshot_root/artifacts/checksums.txt" --output "$snapshot_root/prowl.rb"
ruby -c "$snapshot_root/prowl.rb"
python3 -m unittest discover -s scripts/release -p 'test_*.py'
```

Snapshot пропускает подпись и публикацию. Он использует тот же конфиг, меняя
только выходной каталог и snapshot-версию. `dist` в GoReleaser не поддерживает
шаблоны; скрипт создаёт отдельную временную копию конфига с абсолютным путём.
Модульные теги `tool/*` исключены из определения версии GoReleaser.

Комплект содержит шесть архивов: Linux/macOS/Windows × amd64/arm64, по одному SPDX
SBOM на архив и `checksums.txt` с SHA-256 архивов и SBOM. В каждом архиве находятся
бинарник, лицензия, оба README и руководство CLI в `docs/README.md`.
Проверка отклоняет отсутствующую платформу, повреждённый файл, пустой SBOM и SBOM
без модуля Prowl или переносимого компрессора.
Каждый обязательный member архива должен быть единственным непустым обычным файлом:
повторное имя, каталог вместо бинарника, ссылка или специальный файл отклоняются
даже при совпадении SHA-256 всего архива. Допускается один пустой directory entry
`docs` или `docs/`; обычный файл с этим именем и оба варианта одновременно запрещены.
Дополнительно verifier читает не более 64 KiB префикса binary member и проверяет
формат и 64-bit machine относительно имени архива: Linux ELF64 little-endian с
SYSV/Linux ABI и amd64/AArch64, thin Mach-O 64 executable для macOS, PE32+ console
executable с соответствующей machine для Windows. Foreign ELF ABI, FAT/shared
Mach-O, PE DLL/GUI/32-bit, повреждённые header offsets и неверный CPU отвергаются.
Unix TAR-бинарник должен иметь executable bit. Синтетический или чужой файл с верным
форматом не становится от этого Prowl: application identity, подписи, build metadata
и фактическое исполнение проверяются отдельно. Generic SYSV ELF header сам по себе
не устанавливает Linux GOOS.

## Порядок релизного workflow

1. `qualify`: проверка тегов и секрета tap, `go vet`, race-тесты, статическая сборка
   и проверка ML, маскирования значений в выводе и несовместимой старой модели.
2. `binaries`: GoReleaser создаёт **draft** GitHub Release, шесть архивов, SBOM и
   checksums. Cosign подписывает `checksums.txt` через GitHub OIDC. Workflow скачивает
   draft обратно, проверяет подпись, хеши и состав.
3. `docker`: сборка двух платформ под версионным тегом, подпись digest индекса,
   отдельный SPDX SBOM для каждого платформенного digest и cosign-attestation.
   Подписи и attestations проверяются. Файлы SBOM и digest добавляются в draft
   вместе с отдельными подписанными `prowl-image-checksums.txt`.
4. `publish`: повторная проверка обоих подписанных списков, всех файлов и SBOM,
   генерация и проверка Ruby-формулы. Только после этого draft становится публичным.
   Для стабильной версии обновляются `latest` и `Formula/prowl.rb` в tap.
   Предварительная версия не меняет стабильный канал.

Формула по-прежнему обслуживает macOS и Linux, оба процессорных семейства. Её
генератор использует проверенный подписанный список SHA-256. Устаревший блок
GoReleaser `brews` удалён из конфига; переход на cask и удаление существующей
формулы не требуются.

При сбое до `publish` GitHub Release остаётся draft, стабильные каналы не
обновляются. Версионный образ уже может присутствовать в GHCR. При сбое после
публикации возможен частичный результат между GitHub, GHCR и Homebrew: это
отдельные сервисы. Workflow не удаляет и не перезаписывает выпущенные assets
автоматически. Сначала проверяются результаты завершившихся jobs; восстановление
с удалением или заменой внешних данных требует отдельного согласования.

## Проверка скачанного релиза

Скачайте все assets в один каталог и используйте точную версию в identity:

```sh
identity='https://github.com/Lercas/prowl/.github/workflows/release.yml@refs/tags/v1.5.0'
issuer='https://token.actions.githubusercontent.com'
cosign verify-blob --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" \
  --bundle checksums.txt.sigstore.json checksums.txt
cosign verify-blob --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" \
  --bundle prowl-image-checksums.txt.sigstore.json prowl-image-checksums.txt
python3 /path/to/prowl/scripts/release/verify_artifacts.py . --image-sboms
digest=$(cat prowl-image-digest.txt)
cosign verify --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" \
  "ghcr.io/lercas/prowl@$digest"
```

Успех локального snapshot доказывает упаковку и содержимое SBOM. Он не доказывает
GitHub OIDC, права GHCR/tap, результат внешней публикации или установку Homebrew.

Синтаксис и модель доверия сверены с документацией
[GoReleaser](https://goreleaser.com/customization/sign/sign/),
[SBOM](https://goreleaser.com/customization/sbom/) и
[Sigstore](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/).


## Локальная квалификация snapshot 2026-11-16

Из чистого `43ec3252d0cf809d925ee27a35d5aa9091bf4d70` собран
`1.5.0-dev.43ec325`: шесть архивов и шесть SPDX SBOM, один checksums manifest и
macOS/Linux Homebrew formula с `ruby -c`. Использованы Go 1.27.4, GoReleaser 2.20.2
и Syft 1.57.1. Pinned инструменты загружены из официальных release assets с проверкой
соответствующих checksum manifests. Snapshot пропустил signing/publication.

Все шесть binaries извлечены из проверенных архивов: формат и CPU проверены gate,
независимо прочитаны Go build info с точными GOOS/GOARCH, `CGO_ENABLED=0`, Go 1.27.4,
VCS commit и `vcs.modified=false`. Windows amd64/arm64 этим инспектированы и собраны,
но не исполнены.

Архивные macOS arm64 и amd64 прошли static embedded ML, redaction и отказ legacy
модели под OS network deny; amd64 исполнялся через Rosetta. На обоих совпали точные
quality metrics/IDs текущего source: 1661/2094, FP 61/982. Linux arm64 и amd64
исполнили архивные binaries в nonroot, read-only Docker carriers с `--network none`:
version/bundled snapshot, static ML/redaction, legacy rejection и 7 selftest cases.
Carrier images взяты по существующим immutable IDs; это не новая сборка Dockerfile
или квалификация текущих Docker Action images.

На старом verifier воспроизведены три acceptance gaps с корректными checksums:
wrong architecture, wrong executable container и отсутствие Unix executable bit.
Дополнительно настоящий архивный Linux arm64 binary помещён в копию Linux amd64
архива с пересчитанным checksums manifest. Старый verifier принял комплект; новый
отверг именно ELF machine mismatch. Исходный положительный snapshot не изменён.
Release helpers: восемь test methods, 22 layout, 30 platform-header и 15 malformed-
header subcases, пять whole-release negative variants. Config check и actionlint проходят.

Это локальный snapshot конкретного commit, а не финальный опубликованный v1.5.0.
Теги, GitHub OIDC, hosted jobs, Windows runtime, текущая Docker factory, GHCR/tap и
установка Homebrew остаются отдельными непроверенными стадиями. Последующие изменения
source потребуют соответствующей переквалификации final release.

Артефакты и exact hashes:
`evidence/1.5.0-release-platform-qualification-20261116.json`.

Структурные константы сверены с [Go ELF](https://go.dev/src/debug/elf/elf.go),
[Go Mach-O](https://go.dev/src/debug/macho/macho.go) и
[Microsoft PE/COFF](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
