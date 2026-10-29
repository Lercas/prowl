# Запись терминала Prowl

[Смотреть MP4](prowl-terminal.mp4) · [Исходная запись терминала](terminal.cast).

Это непрерывная запись интерактивного Bash в настоящем псевдотерминале (PTY).
Скрипт вводит команды посимвольно, оболочка выполняет их, а весь вывод PTY
сохраняется с исходными временными метками в формате asciicast v2.
`agg` отображает эту запись как обычный терминал; FFmpeg кодирует её в H.264 MP4.
В кадре только команды и их вывод, без поясняющих комментариев и слайдов.
Скорость воспроизведения — 1×; паузы происходят во время самой записи.

В сессии показаны исходные файлы, сканирование каталога и ZIP, маскированные
находки с позициями, JSON одной находки, код завершения 1 при `--fail-on high`,
исправление демонстрационных файлов и повторный запуск с нулём находок и кодом 0.
`fix-demo.py` меняет только одноразовый пример: заменяет значения в конфиге ссылками
на переменные окружения, убирает токен из лога и пересобирает ZIP.

Все ключи синтетические. ML и проверка через API провайдера не включены.
Работоспособность ключей не утверждается. В реальном инциденте ключи нужно отозвать
и проверить историю и артефакты. `PROWL_HOME` и окружение примера изолированы.

В [recording.json](recording.json) находятся команды, длительность, путь временного
примера и SHA-256 бинарника. В [findings.json](findings.json) — маскированный отчёт.

## Повторная запись

Нужны Python 3, Go, agg и FFmpeg. Из корня проекта:

```sh
(cd tool && go build -o /tmp/prowl-terminal-bin ./cmd/prowl)
python3 scripts/record-terminal-demo.py \
  --binary /tmp/prowl-terminal-bin --out /tmp/prowl-terminal-new
agg --font-family Menlo --font-size 22 --theme github-dark \
  --idle-time-limit 30 --last-frame-duration 1 --no-loop \
  /tmp/prowl-terminal-new/terminal.cast /tmp/prowl-terminal-new/terminal.gif
ffmpeg -i /tmp/prowl-terminal-new/terminal.gif -an \
  -vf 'pad=ceil(iw/2)*2:ceil(ih/2)*2' -c:v libx264 -crf 18 \
  -pix_fmt yuv420p -movflags +faststart /tmp/prowl-terminal-new/prowl-terminal.mp4
```

Для Linux замените `Menlo` на установленный моноширинный шрифт с кириллицей.
Выходной каталог должен быть новым. Запись остаётся локальной; загрузка на GitHub
и публикация не выполняются.
