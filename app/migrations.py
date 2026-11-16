"""Transactional, versioned SQLite migrations with pre-migration online backup."""
from __future__ import annotations
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import os
import sqlite3
import time
import uuid
from .schema import HISTORY_SCHEMA


class MigrationError(RuntimeError):
    pass


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')


def check(conn):
    if conn.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
        raise MigrationError('SQLite integrity_check failed')
    if conn.execute('PRAGMA foreign_key_check').fetchone():
        raise MigrationError('SQLite foreign_key_check failed')


def counts(conn):
    return {name: conn.execute('SELECT COUNT(*) FROM "'+name.replace('"','""')+'"').fetchone()[0]
            for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('schema_migrations','schema_info')")}


def statements(conn, script):
    statement = ''
    for line in script.splitlines(True):
        statement += line
        if sqlite3.complete_statement(statement):
            conn.execute(statement)
            statement = ''
    if statement.strip(): conn.execute(statement)


def registry_v1(conn):
    conn.execute('CREATE TABLE IF NOT EXISTS projects(id INTEGER PRIMARY KEY, path TEXT UNIQUE NOT NULL, enabled INTEGER NOT NULL DEFAULT 1)')
    existing = {r[1] for r in conn.execute('PRAGMA table_info(projects)')}
    columns = {'name':"TEXT NOT NULL DEFAULT ''", 'description':"TEXT NOT NULL DEFAULT ''",
               'category':"TEXT NOT NULL DEFAULT 'other'", 'created_at':"TEXT NOT NULL DEFAULT ''",
               'updated_at':"TEXT NOT NULL DEFAULT ''", 'scan_settings':"TEXT NOT NULL DEFAULT '{}'",
               'exclusion_rules':"TEXT NOT NULL DEFAULT '[]'", 'history_path':'TEXT',
               'backup_path':'TEXT', 'report_path':'TEXT', 'detected_languages':"TEXT NOT NULL DEFAULT '[]'"}
    from .config import DEFAULT_EXCLUSIONS
    for name, declaration in columns.items():
        if name not in existing: conn.execute(f'ALTER TABLE projects ADD COLUMN {name} {declaration}')
    now=utcnow()
    for pid,path in conn.execute('SELECT id,path FROM projects').fetchall():
        conn.execute('UPDATE projects SET name=?,created_at=?,updated_at=?,exclusion_rules=?,scan_settings=? WHERE id=?',
                     (Path(path).name or path,now,now,json.dumps(DEFAULT_EXCLUSIONS),json.dumps({'python_analysis':True}),pid))


def history_v2(conn):
    conn.execute("ALTER TABLE snapshots ADD COLUMN content_status TEXT NOT NULL DEFAULT 'metadata_only' CHECK(content_status IN ('metadata_only','recoverable','incomplete','unavailable'))")
    conn.execute('ALTER TABLE snapshots ADD COLUMN project_id INTEGER')
    conn.execute("ALTER TABLE snapshots ADD COLUMN category_metrics TEXT NOT NULL DEFAULT '{}'")
    conn.execute("ALTER TABLE snapshot_files ADD COLUMN file_category TEXT NOT NULL DEFAULT 'legacy'")
    conn.execute('CREATE TABLE content_objects(digest TEXT PRIMARY KEY, size INTEGER NOT NULL CHECK(size>=0), storage_key TEXT UNIQUE NOT NULL, verified_at TEXT)')
    conn.execute('CREATE TABLE snapshot_content(snapshot_id INTEGER NOT NULL, path TEXT NOT NULL, object_digest TEXT, PRIMARY KEY(snapshot_id,path), FOREIGN KEY(snapshot_id,path) REFERENCES snapshot_files(snapshot_id,path), FOREIGN KEY(object_digest) REFERENCES content_objects(digest))')


def registry_v2(conn):
    statements(conn, """
CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL COLLATE NOCASE UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('administrator','operator','viewer')),
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)), auth_version INTEGER NOT NULL DEFAULT 1,
 language TEXT NOT NULL DEFAULT 'ru' CHECK(language IN ('ru','en','pl','uk')), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE sessions(id INTEGER PRIMARY KEY AUTOINCREMENT, digest TEXT NOT NULL UNIQUE,
 user_id INTEGER REFERENCES users(id), user_version INTEGER, created_at REAL NOT NULL,
 last_seen REAL NOT NULL, expires_at REAL NOT NULL, revoked_at REAL, peer TEXT NOT NULL);
CREATE TABLE project_access(user_id INTEGER NOT NULL REFERENCES users(id), project_id INTEGER NOT NULL REFERENCES projects(id),
 can_restore INTEGER NOT NULL DEFAULT 0 CHECK(can_restore IN (0,1)), PRIMARY KEY(user_id,project_id));
CREATE TABLE auth_settings(id INTEGER PRIMARY KEY CHECK(id=1), setup_completed INTEGER NOT NULL DEFAULT 0,
 network_enabled INTEGER NOT NULL DEFAULT 0 CHECK(network_enabled IN (0,1)));
INSERT INTO auth_settings(id) VALUES(1);
CREATE TABLE login_limits(scope TEXT PRIMARY KEY, window_start REAL NOT NULL, attempts INTEGER NOT NULL);
CREATE TABLE user_audit(id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, actor_id INTEGER REFERENCES users(id),
 event TEXT NOT NULL, target_id INTEGER, project_id INTEGER, peer TEXT NOT NULL, result TEXT NOT NULL, details TEXT NOT NULL DEFAULT '{}');
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_user_audit_date ON user_audit(id);
""")


def registry_v3(conn):
    conn.execute("CREATE TABLE user_preferences(user_id INTEGER PRIMARY KEY REFERENCES users(id), locale TEXT NOT NULL, theme TEXT NOT NULL DEFAULT 'system' CHECK(theme IN ('system','dark','light')), scale INTEGER NOT NULL DEFAULT 100 CHECK(scale BETWEEN 80 AND 140))")
    conn.execute('INSERT INTO user_preferences(user_id,locale) SELECT id,language FROM users')


def registry_v4(conn):
    statements(conn, """
CREATE TABLE backup_policies(project_id INTEGER PRIMARY KEY REFERENCES projects(id), secret_policy TEXT NOT NULL DEFAULT 'warn' CHECK(secret_policy IN ('local','exclude','warn')), key_id TEXT NOT NULL DEFAULT '', auto_delete INTEGER NOT NULL DEFAULT 0 CHECK(auto_delete IN (0,1)), keep_last INTEGER NOT NULL DEFAULT 20 CHECK(keep_last>=1), min_age_days INTEGER NOT NULL DEFAULT 30 CHECK(min_age_days>=0));
CREATE TABLE job_schedules(id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER NOT NULL REFERENCES projects(id), actor_id INTEGER NOT NULL REFERENCES users(id), task TEXT NOT NULL CHECK(task IN ('backup','snapshot','verify','retention')), kind TEXT NOT NULL DEFAULT 'full' CHECK(kind IN ('full','incremental')), interval_seconds INTEGER NOT NULL CHECK(interval_seconds IN (86400,604800)), next_run REAL NOT NULL, enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)), UNIQUE(project_id,task));
CREATE TABLE jobs(id TEXT PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), actor_id INTEGER REFERENCES users(id), actor_version INTEGER, task TEXT NOT NULL, kind TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', point_id TEXT, state TEXT NOT NULL CHECK(state IN ('queued','running','succeeded','failed','cancelled','interrupted')), created_at REAL NOT NULL, started_at REAL, finished_at REAL, heartbeat REAL, cancel_requested INTEGER NOT NULL DEFAULT 0, progress_bytes INTEGER NOT NULL DEFAULT 0, total_bytes INTEGER NOT NULL DEFAULT 0, progress_files INTEGER NOT NULL DEFAULT 0, total_files INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, not_before REAL NOT NULL DEFAULT 0, error_code TEXT NOT NULL DEFAULT '', result_point_id TEXT, schedule_id INTEGER REFERENCES job_schedules(id), scheduled_for REAL, UNIQUE(schedule_id,scheduled_for));
CREATE INDEX idx_jobs_dispatch ON jobs(state,not_before,created_at);
""")


def history_v3(conn):
    conn.execute('ALTER TABLE snapshots ADD COLUMN backup_point_id TEXT')
    statements(conn, """
CREATE TABLE backup_points(id TEXT PRIMARY KEY, backup_id INTEGER UNIQUE NOT NULL REFERENCES backups(id), snapshot_id INTEGER UNIQUE REFERENCES snapshots(id), job_id TEXT UNIQUE, kind TEXT NOT NULL CHECK(kind IN ('full','incremental','checkpoint','pre_restore')), parent_id TEXT REFERENCES backup_points(id), manifest_sha256 TEXT NOT NULL, key_id TEXT NOT NULL DEFAULT '', protected INTEGER NOT NULL DEFAULT 0 CHECK(protected IN (0,1)), state TEXT NOT NULL DEFAULT 'available' CHECK(state IN ('available','deleting','deleted')), verified_at TEXT NOT NULL, last_error TEXT NOT NULL DEFAULT '');
CREATE TABLE backup_point_objects(point_id TEXT NOT NULL REFERENCES backup_points(id), digest TEXT NOT NULL, storage_key TEXT NOT NULL, size INTEGER NOT NULL, stored_size INTEGER NOT NULL, PRIMARY KEY(point_id,digest));
""")


def registry_v5(conn):
    statements(conn, """
CREATE TABLE restore_previews(id TEXT PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), user_id INTEGER NOT NULL REFERENCES users(id), session_digest TEXT NOT NULL, user_version INTEGER NOT NULL, token_digest TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL, used_at REAL, spec_json TEXT NOT NULL);
CREATE TABLE restore_operations(id TEXT PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), actor_id INTEGER NOT NULL REFERENCES users(id), actor_version INTEGER NOT NULL, session_digest TEXT NOT NULL, job_id TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('queued','preparing','applying','committed','interrupted','undoing','rolled_back','failed','superseded')), created_at REAL NOT NULL, updated_at REAL NOT NULL, target_path TEXT NOT NULL, work_path TEXT NOT NULL, work_identity TEXT, nonce TEXT NOT NULL, spec_json TEXT NOT NULL, safety_point_id TEXT, recovery_point_id TEXT, error_code TEXT NOT NULL DEFAULT '');
CREATE UNIQUE INDEX idx_restore_project_lease ON restore_operations(project_id) WHERE state IN ('queued','preparing','applying','interrupted','undoing');
CREATE INDEX idx_restore_target ON restore_operations(target_path);
CREATE TABLE restore_steps(operation_id TEXT NOT NULL REFERENCES restore_operations(id), seq INTEGER NOT NULL, kind TEXT NOT NULL, path TEXT NOT NULL, aux TEXT NOT NULL, details TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0, undone INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(operation_id,seq));
ALTER TABLE jobs ADD COLUMN restore_op_id TEXT REFERENCES restore_operations(id);
""")


def history_v4(conn):
    for name in ('rule_id','fingerprint','explanation','remediation','analyzer_id','file_category','occurrences'):
        conn.execute("ALTER TABLE audit_findings ADD COLUMN "+name+" TEXT NOT NULL DEFAULT ''")
    conn.execute("ALTER TABLE python_entities ADD COLUMN analyzer_id TEXT NOT NULL DEFAULT 'python'")
    conn.execute("ALTER TABLE snapshots ADD COLUMN analysis_info TEXT NOT NULL DEFAULT '{}'")
    statements(conn, """
CREATE INDEX idx_audit_fingerprint ON audit_findings(snapshot_id,fingerprint);
CREATE TABLE audit_reviews(fingerprint TEXT PRIMARY KEY, status TEXT NOT NULL CHECK(status IN ('open','false_positive')), actor_id INTEGER NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE audit_review_events(id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('open','false_positive')), actor_id INTEGER NOT NULL, created_at TEXT NOT NULL);
""")


MIGRATIONS = {'registry': [(1,'universal-projects',registry_v1),(2,'authorization',registry_v2),(3,'interface-preferences',registry_v3),(4,'durable-backup-jobs',registry_v4),(5,'restore-journal',registry_v5)],
              'history': [(1,'legacy-history',lambda c: statements(c,HISTORY_SCHEMA)),
                          (2,'snapshot-content-status',history_v2),(3,'verified-backup-points',history_v3),(4,'explainable-analysis',history_v4)]}


@contextmanager
def migration_lock(path):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('a+b') as handle:
        if os.name == 'nt':
            import msvcrt
            handle.seek(0); handle.write(b'0'); handle.flush(); handle.seek(0)
            msvcrt.locking(handle.fileno(),msvcrt.LK_LOCK,1)
        else:
            import fcntl
            fcntl.flock(handle,fcntl.LOCK_EX)
        try: yield
        finally:
            if os.name == 'nt':
                handle.seek(0); msvcrt.locking(handle.fileno(),msvcrt.LK_UNLCK,1)
            else: fcntl.flock(handle,fcntl.LOCK_UN)


def migrate(path: Path, kind: str, backup_dir: Path, project_id=None):
    path=Path(path); backup_dir=Path(backup_dir)
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    try:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
    except FileExistsError: pass
    with migration_lock(path.with_suffix(path.suffix+'.migration.lock')):
        conn=sqlite3.connect(path,timeout=30)
        try:
            conn.execute('PRAGMA foreign_keys=ON')
            target=MIGRATIONS[kind][-1][0]
            version=conn.execute('PRAGMA user_version').fetchone()[0]
            journal=conn.execute("SELECT 1 FROM sqlite_master WHERE name='schema_info'").fetchone()
            if journal:
                row=conn.execute('SELECT kind,version FROM schema_info WHERE id=1').fetchone()
                if row != (kind,version): raise MigrationError('Schema identity/version mismatch')
                applied=[r[0] for r in conn.execute('SELECT version FROM schema_migrations ORDER BY version')]
                if applied != list(range(1,version+1)): raise MigrationError('Incomplete migration journal')
            elif version: raise MigrationError('Unrecognized versioned database')
            if version>target: raise MigrationError('Database was created by a newer application')
            if version==target: return
            conn.execute('BEGIN IMMEDIATE')  # prevent writes between backup and migration
            check(conn)
            before=counts(conn)
            expected = {'registry': {'projects': {'id','path','enabled'}},
                        'history': {'snapshots': {'id','agent_root','created_at','total_files'},
                                    'snapshot_files': {'snapshot_id','path','sha256'},
                                    'python_entities': {'snapshot_id','path','kind'},
                                    'audit_findings': {'snapshot_id','category'},
                                    'file_events': {'id','event_type'}, 'backups': {'id','archive_path','sha256'}}}[kind]
            if before:
                for table,required in expected.items():
                    columns={r[1] for r in conn.execute('PRAGMA table_info("'+table+'")')}
                    if not required <= columns: raise MigrationError('Unsupported legacy schema: '+table)
            backup=None
            if before:
                backup_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
                backup=backup_dir/(path.stem+'-v'+str(version)+'-'+uuid.uuid4().hex+'.sqlite')
                fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.close(fd)
                deadline=time.monotonic()+60
                def progress(*_):
                    if time.monotonic()>deadline: raise MigrationError('SQLite backup timeout')
                with sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True) as source:
                    with sqlite3.connect(backup) as dest:
                        source.backup(dest,pages=256,progress=progress)
                        check(dest)
                        if counts(dest)!=before: raise MigrationError('Backup counts changed')
                with backup.open('rb') as handle: os.fsync(handle.fileno())
                digest=hashlib.sha256(backup.read_bytes()).hexdigest()
                sha=backup.with_suffix('.sqlite.sha256'); sha.write_text(digest+'  '+backup.name+'\n');sha.chmod(0o600)
            conn.execute('CREATE TABLE IF NOT EXISTS schema_info(id INTEGER PRIMARY KEY CHECK(id=1),kind TEXT NOT NULL,version INTEGER NOT NULL)')
            conn.execute('CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY,name TEXT NOT NULL,applied_at TEXT NOT NULL,backup_path TEXT,counts_before TEXT NOT NULL,counts_after TEXT NOT NULL)')
            for number,name,operation in MIGRATIONS[kind]:
                if number<=version: continue
                previous=counts(conn)
                operation(conn)
                if kind == 'history' and number == 2 and project_id is not None:
                    conn.execute('UPDATE snapshots SET project_id=?',(project_id,))
                if kind == 'registry' and number == 1:
                    # One-time legacy layout binding, outside runtime project selection.
                    old_history = path.parent / 'agent_history.sqlite'
                    for pid,source_path in conn.execute('SELECT id,path FROM projects').fetchall():
                        history = path.parent / 'projects' / str(pid) / 'history.sqlite'
                        if old_history.exists():
                            with sqlite3.connect(old_history.resolve().as_uri()+'?mode=ro',uri=True) as legacy:
                                root = legacy.execute('SELECT agent_root FROM snapshots ORDER BY id LIMIT 1').fetchone()
                            if (root and root[0] == source_path) or (root is None and pid == 1): history = old_history
                        conn.execute('UPDATE projects SET history_path=? WHERE id=?',(str(history),pid))
                after=counts(conn)
                if any(after.get(table)!=count for table,count in previous.items()):
                    raise MigrationError('Migration changed existing row counts')
                check(conn)
                conn.execute('INSERT INTO schema_migrations VALUES(?,?,?,?,?,?)',
                             (number,name,utcnow(),str(backup) if backup else None,json.dumps(previous),json.dumps(after)))
            conn.execute('INSERT OR REPLACE INTO schema_info VALUES(1,?,?)',(kind,target))
            conn.execute('PRAGMA user_version='+str(target))
            check(conn)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally: conn.close()
