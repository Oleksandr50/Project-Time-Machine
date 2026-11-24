# Первый проект и восстановление

1. Откройте локальный URL, выберите язык и создайте уникальные логин/пароль администратора.
2. Поместите одноразовый проект в разрешённый каталог либо добавьте существующий корень
   через `ptm allow-root`. В Projects добавьте отдельный проект по абсолютному пути.
3. Создайте Metadata snapshot через Analysis. Проверьте исключения; databases/user data
   не исключаются автоматически только из-за расширения.
4. Создайте Full Backup, дождитесь успешной проверки. Настройте secret/encryption policy
   до архивирования реальных секретов; encryption key храните отдельно и сохраняйте вне диска.
5. Измените тестовый файл, создайте Checkpoint либо Incremental и сравните snapshots.
6. В Restore выберите точку и файл/проект/новый каталог, изучите preview. Остановите
   сервисы и запись, явно подтвердите RESTORE. Приложение сначала проверит страховку.
7. Проверьте байты и журнал. При прерывании не удаляйте workspace: запустите новое
   подтверждённое recovery. Автоматический rollback не выполняется.
8. Настройте daily/weekly расписание. Очистка backup по умолчанию выключена.
9. Добавьте Viewer/Operator и выдайте только нужные проекты; restore требует отдельного
   разрешения. Просмотрите сессии/журнал входов. Не используйте реальные проекты для
   первого опыта восстановления.

Metadata Only не означает recoverable. Backup создаёт отдельный Recoverable snapshot
только после проверки сохранённых байтов. Исчезнувший archive остаётся Missing в истории.
Подробности: backups.md, restore.md, analysis-audit.md.
# Version 0.7.7: compact history and confirmed deletion

Dashboard activity, warnings and job lists show at most four entries before internal scrolling. The backup table shows at most five data rows with sticky column headers; search, sorting and pagination remain available. Older records are retained in history.

Administrators can permanently delete a disabled project from Projects. The confirmation page shows its name and source path and requires the exact project name. Cancellation changes nothing. Deletion removes only the project's PTM-managed state, archives and verified owned restore workspaces; the source files and global audit remain. Running operations or unfinished recovery block deletion. Noncanonical legacy storage bindings require a separate reviewed migration and are rejected by automatic deletion.

Administrators can delete an individual backup from its Actions column after confirming its ID. Protected points, incremental parents, active jobs and references from restore history or live previews block deletion. No automatic cascade is performed. Independent metadata snapshots remain; snapshots tied to the removed point become unavailable.

Deletion has a durable journal under the configured state directory's `deletions` folder. A filesystem/database error is reported as failure. Open a new confirmation to retry incomplete cleanup. A project undergoing incomplete cleanup cannot be reattached. Safety checkpoints made before application updates remain independent and are not erased by project deletion.
