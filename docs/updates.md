# Обновление без потери данных

## Нативная установка / WSL2

Распакуйте проверенный новый пакет в отдельный каталог:

```bash
$HOME/ProjectTimeMachine/bin/ptm update /absolute/new-release
```

Новые код/venv/dependencies и синтетический engine self-test готовятся до остановки
своего экземпляра. Затем он останавливается через kernel pidfd после проверки PID identity либо своей
user-службе; чужие службы/процессы не затрагиваются. Exclusive maintenance lock запрещает
одновременный запуск. Неподдерживаемый вручную запущенный сервер нужно штатно остановить.

До миграции сохраняются проверенные SQLite Backup API копии registry/history, counts,
fingerprints старых колонок и конфигурация. Миграции сначала репетируются на копиях,
проверяют integrity/FK и сохранность старых строк; только затем применяются к state.
Смена current release — atomic symlink replacement на локальном Linux filesystem.
Старые releases и checkpoints сохраняются, настройки и пути данных не сбрасываются.
Скопированный runtime сверяется с источником. Файлы/каталоги нового release и checkpoint
фиксируются fsync до публикации manifest/current; ошибка синхронизации запрещает переход.

Это checkpoint **метаданных приложения**, не ещё одна полная копия всех CAS/архивов.
Большие backups/content и внешние encryption keys не перемещаются и не изменяются.
Их отдельная внешняя копия необходима для защиты от отказа диска. Не удаляйте keys,
old releases, updates или migration-backups во время восстановления обновления.

Если обновление прервалось до завершения, запуск заблокирован:

```bash
$HOME/ProjectTimeMachine/bin/ptm recover-update
$HOME/ProjectTimeMachine/bin/ptm start
```

Это явное восстановление схемы/кода приложения, не откат наблюдаемого проекта. Текущие
DB/sidecars сохраняются отдельно как superseded, копии проверяются до применения.
Повторное прерывание допускает повтор recovery, если файлы не менялись извне.
Checkpoint должен быть целым. Если состояние изменено после прерывания, обе копии
сохраняются, автоматическая перезапись запрещена.

После completed update и нового запуска произвольный downgrade БД запрещён: новые
снимки/jobs/recovery journal нельзя потерять возвратом старого registry. Сохраните
текущее state, разберите совместимость схемы и используйте совместимый исправленный
релиз. Общей транзакции filesystem/нескольких SQLite нет; это журналируемая процедура,
не обещание полной атомарности.

Для отдельной копии метаданных остановите свой экземпляр и выполните `ptm backup-state`.
Прямое копирование работающей SQLite без Backup API не используйте.

## Docker

Из **нового** распакованного каталога:

```bash
python3 scripts/docker_upgrade.py --install-dir /absolute/old-compose-directory
```

Сохраняется .env старой установки с абсолютными bind paths. Helper проверяет labels
целевого PTM container, сохраняет прежний image tag, собирает новый image и выполняет
временный self-test. Затем останавливает только app выбранного compose project,
создаёт проверенный checkpoint и rehearsal через offline maintenance CLI, применяет
миграции и запускает app с healthcheck. Для нестандартного project name укажите
`--project-name`. Не запускайте новый compose без прежней .env: иначе получите отдельную
пустую установку вместо обновления.

После interrupted prepare-upgrade сервер не стартует. С остановленным app:

```bash
docker compose run --rm --no-deps app python -B -m app.maintenance_cli recover-update
```

Верните совместимый сохранённый image и запустите свой compose. После completed
deployment/новых записей автоматического DB rollback нет. Старые images/checkpoints
не удаляются helper. Docker volumes сохраняются; `down -v`, prune и удаление bind
directories для обновления не нужны и не выполняются.
