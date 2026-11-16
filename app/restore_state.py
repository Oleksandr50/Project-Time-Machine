"""Durable leases shared by all writers, including restart recovery."""
from . import projects

ACTIVE=('queued','preparing','applying','interrupted','undoing')


def ensure_clear(pid,owner=None):
    from .backup_storage import BackupError
    with projects.registry() as conn:
        row=conn.execute("SELECT id FROM restore_operations WHERE project_id=? AND state IN ('queued','preparing','applying','interrupted','undoing')",(pid,)).fetchone()
    if row and row['id']!=owner:raise BackupError('restore_pending')


def workspaces(pid):
    if pid is None:return set()
    with projects.registry() as conn:return {r[0] for r in conn.execute('SELECT work_path FROM restore_operations WHERE project_id=?',(pid,))}
