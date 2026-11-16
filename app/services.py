from __future__ import annotations

from datetime import datetime

from pathlib import Path
from typing import Any

import os

from .config import settings
from . import db
from .analyzer import create_snapshot, save_snapshot, compare_snapshots, create_backup, save_backup


def ensure_db() -> None:
    db.init_db()


def get_latest_snapshot_id(conn) -> int | None:
    r = conn.execute("SELECT id FROM snapshots ORDER BY id DESC LIMIT 1").fetchone()
    return int(r["id"]) if r else None


def run_analysis(description: str = "",tick=lambda:None) -> dict[str, Any]:
    from .backup_storage import project_lock,capacity
    with project_lock(settings.project_id),capacity():
        return _run_analysis(description,tick)


def _run_analysis(description: str = "",tick=lambda:None) -> dict[str, Any]:
    ensure_db()
    snap = create_snapshot(description=description,tick=tick)
    tick()

    with db.db_conn() as conn:
        prev_id = get_latest_snapshot_id(conn)
        sid = save_snapshot(conn, snap)

        changes = 0
        if prev_id is not None:
            diff = compare_snapshots(conn, prev_id, sid)
            changes = len(diff["added"]) + len(diff["deleted"]) + len(diff["modified"]) + len(diff["renames"])
            conn.execute("UPDATE snapshots SET changes_from_prev=? WHERE id=?", (changes, sid))
            # persist events
            for p in diff["added"]:
                conn.execute(
                    "INSERT INTO file_events(created_at,snapshot_a,snapshot_b,event_type,path_b,size_b,sha256_b,comment) VALUES (?,?,?,?,?,?,?,?)",
                    (snap.created_at, prev_id, sid, "created", p, None, None, "Добавлен файл"),
                )
            for p in diff["deleted"]:
                conn.execute(
                    "INSERT INTO file_events(created_at,snapshot_a,snapshot_b,event_type,path_a,size_a,sha256_a,comment) VALUES (?,?,?,?,?,?,?,?)",
                    (snap.created_at, prev_id, sid, "deleted", p, None, None, "Удалён файл"),
                )
            for p in diff["hash_changed"]:
                conn.execute(
                    "INSERT INTO file_events(created_at,snapshot_a,snapshot_b,event_type,path_a,path_b,comment) VALUES (?,?,?,?,?,?,?)",
                    (snap.created_at, prev_id, sid, "hash_changed", p, p, "Изменился SHA-256"),
                )
            for a, b in diff["renames"]:
                conn.execute(
                    "INSERT INTO file_events(created_at,snapshot_a,snapshot_b,event_type,path_a,path_b,comment) VALUES (?,?,?,?,?,?,?)",
                    (snap.created_at, prev_id, sid, "renamed", a, b, "Предположительное переименование по совпадению SHA-256"),
                )
        else:
            diff = None

    languages={'.py':'Python','.js':'JavaScript','.jsx':'JavaScript','.ts':'TypeScript',
               '.tsx':'TypeScript','.php':'PHP','.java':'Java','.cs':'C#', '.html':'HTML','.css':'CSS',
               '.yaml':'Configuration','.yml':'Configuration','.toml':'Configuration','.ini':'Configuration'}
    if settings.project_id is not None:
        from .projects import set_detected_languages
        set_detected_languages(settings.project_id,{languages[Path(f.path).suffix.lower()] for f in snap.files
                                                  if Path(f.path).suffix.lower() in languages and f.file_category=='active'})
    # Portable metadata has its own configured directory. SQLite remains authoritative.
    import json
    import tempfile
    metadata={'format_version':1,'project_id':settings.project_id,'snapshot_id':sid,
              'created_at':snap.created_at,'description':snap.description,
              'content_status':'incomplete' if any(f.sha256 is None for f in snap.files) else 'metadata_only',
              'files':[{'path':f.path,'size':f.size,'mtime':f.mtime,'sha256':f.sha256,
                        'category':f.file_category,'content_available':False} for f in snap.files]}
    settings.metadata_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=settings.metadata_dir,delete=False) as handle:
            temporary=handle.name
            json.dump(metadata,handle,ensure_ascii=False)
            handle.flush();os.fsync(handle.fileno())
        os.replace(temporary,settings.metadata_dir/f'{sid}.json')
        temporary=None
    finally:
        if temporary is not None: Path(temporary).unlink(missing_ok=True)
    # Generate report file
    report_path = settings.reports_dir / "current_state.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(render_report(snap, sid, diff), encoding="utf-8")

    return {
        "snapshot_id": sid,
        "changes_from_prev": changes,
        "report_path": str(report_path),
    }


def render_report(snap,sid,diff):
    from .i18n import tr
    from .ui import bytes_label
    lines=['# '+tr('nav.report'),f'{tr("common.project")}: {settings.agent_root.name}',
           f'{tr("common.path")}: {settings.agent_root}',f'{tr("common.snapshot")}: {sid}',
           f'{tr("common.date")}: {snap.created_at}','']
    for key,value in [('common.files',snap.total_files),('common.python',snap.python_files),
                      ('common.functions',snap.functions_count),('common.classes',snap.classes_count),
                      ('common.size',bytes_label(snap.total_bytes)),('common.hash',snap.baseline_digest)]:
        lines.append(tr(key)+': '+str(value))
    lines+=['',tr('snapshots.hint'),'','## '+tr('nav.audit'),tr('audit.hint')]
    for severity in ('critical','high','medium','low','info'):
        lines.append(tr('severity.'+severity)+': '+str(sum(a.get('severity')==severity for a in snap.audit)))
    if diff:
        lines+=['','## '+tr('nav.compare')]
        for key in ('added','deleted','modified','renamed'):
            lines.append(tr('compare.'+key)+': '+str(len(diff['renames' if key=='renamed' else key])))
    return '\n'.join(lines)+'\n'


def create_and_store_backup(snapshot_id: int | None = None) -> dict[str, Any]:
    """Compatibility-only legacy tar entry point; new web jobs use backups.create."""
    from .backup_storage import project_lock,capacity
    with project_lock(settings.project_id),capacity():
        return _legacy_backup(snapshot_id)


def _legacy_backup(snapshot_id=None):
    ensure_db()
    b = create_backup(snapshot_id=snapshot_id)
    with db.db_conn() as conn:
        bid = save_backup(conn, b)
    b["backup_id"] = bid
    return b


def list_snapshots(conn) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM snapshots ORDER BY id DESC LIMIT 200"
    ).fetchall()
    labels={'metadata_only':'Metadata Only','recoverable':'Recoverable','incomplete':'Incomplete','unavailable':'Unavailable'}
    result=[dict(r) for r in rows]
    for row in result: row['content_status_label']=labels[row['content_status']]
    return result


def list_backups(conn) -> list[dict[str, Any]]:
    from .archives import availability
    result=[dict(r) for r in conn.execute('SELECT * FROM backups ORDER BY id DESC LIMIT 200')]
    for row in result: row['availability']=availability(row['archive_path'])
    return result


def snapshot_summary(conn, snapshot_id: int) -> dict[str, Any]:
    r = conn.execute("SELECT * FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
    if not r:
        raise KeyError(snapshot_id)
    return dict(r)


def audit_summary(conn, snapshot_id: int) -> dict[str, int]:
    rows = conn.execute(
        "SELECT severity, COUNT(*) as c FROM audit_findings WHERE snapshot_id=? GROUP BY severity",
        (snapshot_id,),
    )
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in rows:
        if r["severity"] in out:
            out[r["severity"]] = r["c"]
    return out


def functions_list(conn, snapshot_id: int, risk: str | None = None, q: str | None = None, limit: int = 2000) -> list[dict[str, Any]]:
    sql = "SELECT * FROM python_entities WHERE snapshot_id=? AND kind IN ('function','async_function')"
    params: list[Any] = [snapshot_id]
    if risk:
        sql += " AND risk_level=?"
        params.append(risk)
    if q:
        sql += " AND (name LIKE ? OR qualname LIKE ? OR path LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    sql += " ORDER BY path, lineno LIMIT ?"
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def files_tree(conn, snapshot_id: int, prefix: str = "") -> list[dict[str, Any]]:
    # simple prefix listing
    rows = conn.execute(
        "SELECT path,size,mtime,sha256,file_type,lines,is_secret FROM snapshot_files WHERE snapshot_id=? AND path LIKE ? ORDER BY path LIMIT 4000",
        (snapshot_id, f"{prefix}%"),
    ).fetchall()
    return [dict(r) for r in rows]


def file_detail(conn, snapshot_id: int, rel_path: str) -> dict[str, Any]:
    r = conn.execute(
        "SELECT * FROM snapshot_files WHERE snapshot_id=? AND path=?",
        (snapshot_id, rel_path),
    ).fetchone()
    if not r:
        raise KeyError(rel_path)
    d = dict(r)
    # add entities for python
    ents = conn.execute(
        "SELECT kind,name,qualname,lineno,signature,docstring,decorators,imports,calls,risk_level,risk_reasons FROM python_entities WHERE snapshot_id=? AND path=? ORDER BY lineno",
        (snapshot_id, rel_path),
    ).fetchall()
    d["entities"] = [dict(e) for e in ents]
    return d


def list_events(conn, limit: int = 2000) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM file_events ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def compare(conn, a_id: int, b_id: int) -> dict[str, Any]:
    return compare_snapshots(conn, a_id, b_id)


def list_logs() -> list[Path]:
    from .scanner import iter_files
    return sorted(p for p,_ in iter_files(settings.agent_root) if p.suffix.lower()=='.log')


def list_sqlite_files() -> list[Path]:
    from .scanner import iter_files
    return sorted(p for p,_ in iter_files(settings.agent_root) if p.suffix.lower() in {'.db','.sqlite','.sqlite3'})


def safe_rel_agent_path(p: Path) -> str:
    return str(p.relative_to(settings.agent_root))


def is_secret_for_display(rel: str) -> bool:
    # same as analyzer.is_secret_path but without import cycle
    from .analyzer import is_secret_path

    return is_secret_path(rel)
