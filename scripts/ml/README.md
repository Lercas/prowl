# Переносимая L2-модель

Модель обучается на признаках из того же Go-экстрактора, который работает в Prowl.
Признак `compression_ratio_go_flate_v2` — отношение длины закрытого потока raw
DEFLATE уровня 6 из закреплённого `github.com/klauspost/compress/flate` v1.20.4 к длине
UTF-8-значения; для пустой строки — 0. Стандартный `compress/flate` меняет длину
потоков между Go 1.25 и 1.27, поэтому его версия не подходит для стабильного признака.
Системная zlib и Python-экстрактор для этого признака не используются.

```sh
python3 -m venv /tmp/prowl-ml-training
/tmp/prowl-ml-training/bin/pip install -r scripts/ml/requirements.txt
(cd tool && GOTOOLCHAIN=go1.27.4 CGO_ENABLED=0 go build -o /tmp/prowl-ml-features ./cmd/prowl-ml-features)
OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=4 /tmp/prowl-ml-training/bin/python \
  scripts/ml/train_portable.py \
  --corpus /path/to/corpus.jsonl --extractor /tmp/prowl-ml-features \
  --out /path/to/new-candidate-directory
```

Вход — JSONL-записи с `value`, `context`, `text`, `label_binary`, `label_type`
и необязательным `span`. Корпус хранится отдельно от Git и не публикуется.
Каталог результата должен быть новым: обучение не заменяет установленную модель.
В признаки, отчёт и prediction-fixture сырые значения не записываются.

Разбиение 70/15/15 проводится по связным группам значений и шаблонов: ни одинаковое
значение, ни шаблон носителя не могут пересекать части. При больших связанных
группах фактические размеры частей отличаются от указанных долей.
Контрольная zlib-модель обучается на тех же данных. Сложность переносимой модели
выбирается из 31, 63 и 127 листьев по F1 validation-части при пороге 0,3.
Разница F1 до 0,0001 считается ничьей: выбирается меньшая модель, чтобы микроскопический
выигрыш не увеличивал её сложность. Test-часть не участвует в выборе модели.

Гейт допускает снижение PR-AUC, precision, recall и F1 максимум на 0,005 относительно
контрольной модели. При неуспехе остаётся отчёт, но кандидат не экспортируется.
При успехе создаются `model_binary_go.json`, `prediction_golden.json` и
`qualification.json`. До подключения кандидата необходимо проверить Go/Python
prediction-parity, идентичность признаков поддерживаемых Go-toolchain и статическую
сборку с `--ml`. Числа отчёта описывают перенос L2 на данном корпусе, а не качество
на произвольных пользовательских источниках.

Старые модели с признаками `compression_ratio` и `compression_ratio_go_flate_v1`
несовместимы. Обновление compress с v1.18.6 до v1.20.4 изменило 12735 из 525102
значений признака на квалификационном корпусе; поэтому модель переобучается.
Prowl должен отклонять
их с сообщением о переобучении; переименование поля в старом JSON недопустимо.

Проверка splitter:

```sh
python -m unittest discover -s scripts/ml -p 'test_*.py'
```

Для канонических JSON/YAML/TOML-значений есть отдельная генерация аннотаций и
захват фактических ML-records через Pipeline. Аннотация содержит документ, логический
`path`, ожидаемое значение и метку. `prowl-ml-corpus` не открывает `path`: сканирует
переданный текст, требует ровно одного соответствующего кандидата и переносит его
реальный контекст. Уже подавленные L1 отрицательные примеры пропускаются. Исходные
byte offsets переводятся в символьные `span`, которыми пользуется Python splitter.

```sh
set -e
canonical_dir="$(mktemp -d /tmp/prowl-canonical.XXXXXX)"
(cd tool && GOTOOLCHAIN=go1.27.4 CGO_ENABLED=0 go build -o /tmp/prowl-ml-corpus ./cmd/prowl-ml-corpus)
python3 scripts/ml/canonical_fixtures.py --out "$canonical_dir/annotations.jsonl"
/tmp/prowl-ml-corpus < "$canonical_dir/annotations.jsonl" > "$canonical_dir/corpus.jsonl"
OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=4 .venv/bin/python scripts/ml/train_portable.py \
  --corpus data/processed/corpus_flywheel.jsonl \
  --augmentation "$canonical_dir/corpus.jsonl" \
  --reference-report tool/internal/mlmodel/testdata/portable_qualification.json \
  --extractor /tmp/prowl-ml-features --out "$canonical_dir/model"
```

При `--augmentation` исходное разбиение сохраняется. Связанные значением или
шаблоном новые записи следуют исходной части; группа, связывающая разные исходные
части, целиком исключается. Независимые группы делятся отдельно. Отчёт содержит
метрики общего набора, исходных val/test и augmentation. `--reference-report`
проверяет hash корпуса, seed, threshold и размеры исходных частей, затем требует
отсутствия регрессии более 0,005 относительно ранее квалифицированной модели по
PR-AUC, precision, recall и F1. Порог 0,3 не меняется; test не выбирает сложность модели.

Аннотации и corpus содержат значения и остаются локально вне Git. Генератор
использует только синтетические строки; пять проваленных проверочных значений
не включаются в дополнение. Файлы метрик, features и prediction-golden значений
не содержат. При провале любого гейта модель не экспортируется.

Экспортированного кандидата можно проверить без замены установленной модели:

```sh
python3 scripts/check_structured_literals.py /path/to/prowl \
  --model /path/to/candidate/model_binary_go.json
```

Это отдельная нативная матрица. Успех обучения сам по себе не заменяет её, Go parity,
проверку исходного ProwlBench и остальные релизные гейты.
