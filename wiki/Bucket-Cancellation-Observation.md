# Наблюдение завершения bucket cancellation

В квалификации stdin/source повторялся отказ
`TestBucketCancellationDoesNotWaitForChildPipes`: канал результата не был выбран
за 500 ms. Это не доказывает, что ребёнок пережил отмену. Историческая причина
этого отказа остаётся неподтверждённой.

Изолированный baseline на неизменённом parent прошёл 100/100 race-повторов;
сбой в этой серии не воспроизведён. Сам acceptance test имел отдельную
неоднозначность: при одновременно готовых result и timer `select` мог выбрать
любой канал. Поэтому результат проверки зависел от выбора ветки, а не от
записанного времени завершения операции.

Тест теперь фиксирует время возврата `SyncBucket` в worker, начинает deadline
непосредственно перед `cancel` и проверяет фактическое завершение не позднее
500 ms. Если timer выбран при уже готовом result, result всё равно оценивается
по timestamp. Готовый поздний result не проходит; `nil` и посторонняя ошибка
не считаются отменой — требуется `context.Canceled`. При отсутствии результата
сохраняются timeout failure и освобождение test-owned child barrier.

Граница 500 ms не увеличена. Поведенческий критерий стал строже: старый select
мог принять поздний готовый result; новый проверяет его timestamp. Startup и
cleanup budgets сохранены. Production cancellation/process-group code не менялся.

## Проверки

- Готовые result/timer: 1000 повторов для early, exact-boundary, late, nil error
  и unrelated error. Отдельно проверен timer без result.
- 20/20 интеграционных race-повторов bucket cancellation с новым наблюдением.
- Counterfactual Go overlay меняет только Cancel на kill прямого parent,
  сохраняя deferred group cleanup. Такая сборка ожидаемо отвергается тем же
  тестом на deadline 500 ms; child barrier освобождается при failure.
- Полные source/ownedcmd suites на Go 1.27.4, race, Go 1.26.11 и scoped lint
  проходят. Existing ownedcmd descendant/EOF checks не менялись.

Изменены только два `_test.go`. Git manifest всех остальных файлов `tool/`
побайтно равен parent. CLI/runtime binaries, quality/performance matrices и
cross-builds не пересобирались и не выдаются за заново квалифицированные.

Evidence: `evidence/1.5.0-bucket-cancellation-observation-20261116.json`.
Это исправление неоднозначности acceptance test, а не доказательство причины
исторического timeout. Полный переход на 1.5.0 и остальные пункты TODO остаются
в работе.
