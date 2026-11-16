# Восстановление порядка статических строк

`scan --reconstruct` распознаёт полные JS-цепочки над доказанной строкой:

```js
const accessKeyId = "PYSD1UXPYEOYGFANAIKA".split("").reverse().join("");
const password = "R 3 m o t e S e c r e t 9 !".split(" ").join("");
```

Поддерживаются строковые separator/joiner и одна необязательная `reverse()`
между `split` и `join`. Аргументы могут быть строковыми литералами, уже поддержанными
статическими выражениями или известными immutable `const` из текущей ограниченной
области. Доступны скобки и последующие полные цепочки. Другие методы, regex,
callbacks, computed calls, omitted arguments и `split` с аргументом limit
не вычисляются. JS runtime, imports и произвольный `eval` не включаются.

Это явная семантика наблюдаемого consumer, а не эвристический разворот любого
текста или удаление всех пробелов. Без `--reconstruct` новый проход не работает.
Сохраняются прежние ограничения JS/TS-совместимого синтаксиса и immutable bindings;
полный анализ TypeScript и изменяемого состояния не добавлен.

## Unicode и лимиты

Пустой separator делит строку на UTF-16 code units, а не Unicode code points.
Суррогатные половины сохраняются до окончательного `join`; повреждённый результат
не заменяется U+FFFD и не становится credential. Скан помечается неполным,
CLI возвращает 2, запись baseline запрещена. Сверка включает 288 случаев Node
v22.23.4: literals, parentheses, constants, пустые и непустые separators/joiners,
reverse, astral symbols и malformed UTF-16. Ещё 279 прежних Node-reference случаев
сохраняются без замены fixtures.

До 4096 split parts на операцию; итог до 64 КиБ, общий input до 1 МиБ,
до 512 результатов, до 128 source spans/transform steps и прежняя глубина 8.
Исчерпание лимита сохраняет неполноту. Для непустого separator используется
bounded SplitN вместо квадратичного поиска через почти совпадающие строки.

Интерпретация использует стандартные intrinsics. Наблюдаемое обращение к
`String.prototype`/`Array.prototype`, включая прямую quoted-property форму,
запрещает новый проход с признаком неполноты: методы могли быть заменены.
Скрытые/косвенные runtime monkeypatches, предшествующие скрипты и host effects
не моделируются; это статическая интерпретация исходника, не доказательство
фактического значения во время исполнения.

Семантика сверена с [String.prototype.split](https://tc39.es/ecma262/multipage/text-processing.html#sec-string.prototype.split),
[Array.prototype.reverse](https://tc39.es/ecma262/multipage/indexed-collections.html#sec-array.prototype.reverse)
и [Array.prototype.join](https://tc39.es/ecma262/multipage/indexed-collections.html#sec-array.prototype.join).
Генератор Node fixtures выполняет только собственные синтетические выражения,
не входы сканера.

## Детекция и исходные координаты

Результат проходит общий L1 → optional L2 → optional verification pipeline,
обычные taxonomy/config suppression, pragmas и общий match budget.
Типизированные секреты сохраняют логическую identity; evidence и finding range
ссылаются на исходное выражение и литералы, включая separators/joiners.
Приватная HMAC identity вычисляется по восстановленному значению.

Именованный generic-пароль номинируется только из фактически разобранного
`const password = ...` или другого имени, принимаемого выбранной taxonomy.
Имя не заимствуется из соседних `const` и не наследуется от значения другой
константы. Это также исправляет потерю имени для прежних поддержанных
статических выражений. Non-password имя не подавляет самостоятельные пароли
внутри декодированного текста. Номинация не обходит отключение типа, placeholders,
password hashes или ML. Для полного именованного пароля ML получает доказанное
имя и существующий parser-literal флаг; веса, feature ABI и порог модели не меняются.

Companion bindings для verification берутся из исходного текста по прежнему
контракту; decoded data не создаёт новых credentials companions. Public audit
также не получает фиктивную JS-object привязку от нового string-order evaluator.
При включённой реконструкции detection policy содержит
`reconstruction_revision=static-string-order-v2`; default policy не меняется.

Общие generic percent/HTML без установленного consumer, произвольный разворот
или разряжение текста, отдельные изменяемые массивы и JWE остаются открыты.
