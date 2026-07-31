# OCR изображений и PDF

Prowl умеет опционально распознавать PNG, JPEG, WebP и страницы PDF без текстового слоя:

```bash
prowl scan screenshots/ scanned-contract.pdf --ocr
```

OCR не заменяет обычный сканер. Сначала VLM возвращает точный видимый текст, затем этот текст проходит
через стандартный каскад Prowl: детекторы, L2 `--ml` при необходимости и live-проверку `--verify`.
Это работает и для изображений/PDF внутри архивов, почтовых вложений, дерева репозитория и Git history.

## Почему Qwen3.6-27B

Для Prowl важна колонка `img→text`, а не общий балл задач понимания документа. В актуальной таблице
[MWS Vision Bench](https://github.com/mts-ai/MWS-Vision-Bench) на русскоязычных бизнес-документах:

| Профиль | validation `img→text` | private test `img→text` | Применение |
|---|---:|---:|---|
| `mlx-community/Qwen3.6-27B-4bit` | 0.863 | 0.861 | рекомендуемый локальный профиль |
| `mlx-community/Qwen3-VL-8B-Instruct-4bit` | 0.780 | 0.779 | лёгкий профиль при дефиците памяти |

Оригинальные модели Qwen распространяются по Apache-2.0. MLX 4-bit варианты занимают примерно
16 ГБ и 5.8 ГБ соответственно. Это плановые ориентиры по размерам файлов моделей, а не измерение
пикового расхода памяти в Prowl:

- [Qwen3.6-27B](https://huggingface.co/Qwen/Qwen3.6-27B) и
  [MLX 4-bit](https://huggingface.co/mlx-community/Qwen3.6-27B-4bit);
- [Qwen3-VL-8B-Instruct](https://huggingface.co/Qwen/Qwen3-VL-8B-Instruct) и
  [MLX 4-bit](https://huggingface.co/mlx-community/Qwen3-VL-8B-Instruct-4bit).

Облачные модели не выбраны дефолтом: секрет-сканер не должен без отдельного решения отправлять
потенциально чувствительные документы третьей стороне.

## Локальный запуск на Apple Silicon

Нужны [MLX-VLM](https://github.com/Blaizzy/mlx-vlm) и Poppler для рендера PDF:

```bash
brew install poppler

python3 -m venv .venv-ocr
source .venv-ocr/bin/activate
pip install -U mlx-vlm

mlx_vlm.server \
  --model mlx-community/Qwen3.6-27B-4bit \
  --host 127.0.0.1 \
  --port 8080
```

В другом терминале:

```bash
prowl scan evidence/ --ocr --format json
```

Для более лёгкого профиля:

```bash
mlx_vlm.server \
  --model mlx-community/Qwen3-VL-8B-Instruct-4bit \
  --host 127.0.0.1 \
  --port 8080

prowl scan evidence/ --ocr \
  --ocr-model mlx-community/Qwen3-VL-8B-Instruct-4bit
```

## Флаги

| Флаг | Назначение |
|---|---|
| `--ocr` | включить OCR; дефолтный endpoint `http://127.0.0.1:8080/v1/chat/completions` |
| `--ocr-url URL` | OpenAI-compatible `/v1/chat/completions`; сам включает OCR |
| `--ocr-model MODEL` | имя модели в запросе; сам включает OCR |
| `--ocr-all-pages` | OCR всех страниц PDF, а не только страниц без текстового слоя |
| `--ocr-max-pages N` | лимит OCR-страниц на один PDF, по умолчанию 20 |
| `--ocr-timeout DUR` | таймаут одного запроса, по умолчанию `2m` |
| `--ocr-allow-remote` | явное разрешение отправлять документы не на loopback |

Токен endpoint читается только из `PROWL_OCR_API_KEY`; в argv его передавать нельзя.

## Безопасность и полнота

- Дефолтный endpoint ограничен loopback. Редиректы отключены, а DNS-результат локального адреса
  проверяется перед соединением.
- Не-loopback endpoint требует одновременно `--ocr-allow-remote` и HTTPS.
- В тело запроса попадает изображение целиком, поэтому удалённый OCR следует считать передачей
  потенциального секрета внешней системе.
- PDF передаётся `pdftocairo` через stdin, PNG забирается через stdout; временные файлы не создаются.
- Размер входа, изображения, ответа, число страниц и время запроса ограничены.
- Ошибка endpoint, рендера или пропущенные из-за лимита страницы делают сканирование неполным:
  Prowl завершится с кодом 2, а не выдаст ложный clean exit.
- OCR сейчас поддержан командами `scan`, `repo` и `org`. Остальные команды отклоняют `--ocr` явно.

По умолчанию Prowl не печатает распознанный текст или исходное изображение в лог. Найденные значения
остаются замаскированы, пока пользователь явно не включит `--show-secrets`.
