"""Universal project registry. Disabling never deletes source/history/archives."""
from contextvars import ContextVar
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
import json
import sqlite3
from .config import base_settings, DEFAULT_EXCLUSIONS
from .filesystem import validate_project
from .migrations import migrate, utcnow

current_settings = ContextVar('project_settings', default=base_settings)


@contextmanager
def registry():
    path=base_settings.data_dir/'projects.sqlite'
    migrate(path,'registry',base_settings.migrations_dir)
    conn=sqlite3.connect(path,timeout=30);conn.row_factory=sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback();raise
    finally: conn.close()


def decode(row):
    d=dict(row)
    d['detected_languages']=json.loads(d['detected_languages'])
    d['status']='active' if d['enabled'] else 'disabled'
    d['scan_settings']=json.loads(d['scan_settings'])
    d['exclusion_rules']=json.loads(d['exclusion_rules'])
    return d


def list_projects(include_disabled=False,project_ids=None):
    where=[];params=[]
    if not include_disabled:where.append('enabled=1')
    if project_ids is not None:
        if not project_ids:return []
        where.append('id IN ('+','.join('?' for _ in project_ids)+')');params.extend(project_ids)
    with registry() as conn:
        return [decode(r) for r in conn.execute('SELECT * FROM projects '+('WHERE '+' AND '.join(where) if where else '')+' ORDER BY id',params)]


def get_project(project_id, include_disabled=False):
    with registry() as conn:
        row=conn.execute('SELECT * FROM projects WHERE id=? '+('' if include_disabled else 'AND enabled=1'),(project_id,)).fetchone()
    if row is None: raise ValueError('Проект не найден или снят с отслеживания')
    return decode(row)


def validate_path(value):
    return validate_project(value,base_settings)


def validate_options(name,description,category,exclusions,scan):
    if len(name)>200 or len(description)>4000 or not category.strip() or len(category)>80:
        raise ValueError('Название до 200, описание до 4000, категория от 1 до 80 символов')
    if not isinstance(exclusions,(list,tuple)) or len(exclusions)>100:
        raise ValueError('Исключения: не более 100 относительных шаблонов')
    for rule in exclusions:
        if not isinstance(rule,str) or not rule or len(rule)>240 or rule.startswith(('/', '\\')) or '..' in Path(rule).parts or '\\' in rule or '\x00' in rule or ':' in rule:
            raise ValueError('Исключения должны быть относительными glob-шаблонами без ..')
    if not isinstance(scan,dict) or set(scan)-{'python_analysis','analyze_archived','analyze_generated','analyze_dependencies'} or any(type(v) is not bool for v in scan.values()):
        raise ValueError('Некорректные настройки анализа')


def add_project(value,name='',description='',category='other'):
    path=validate_path(value)
    validate_options(name,description,category,base_settings.exclusion_rules,base_settings.scan_settings)
    with registry() as conn:
        conn.execute('BEGIN IMMEDIATE')
        old=conn.execute('SELECT * FROM projects WHERE path=?',(str(path),)).fetchone()
        from .filesystem import inside
        import os
        for operation in conn.execute('SELECT project_id,target_path,work_path,state FROM restore_operations'):
            target=Path(operation['target_path']);work=Path(operation['work_path'])
            if operation['state'] in ('queued','preparing','applying','interrupted','undoing') and (not old or old['id']!=operation['project_id']) and (inside(path,target) or inside(target,path)):
                raise ValueError('engine.restore_target')
            if os.path.lexists(work) and (inside(path,work) or inside(work,path)) and not (old and old['id']==operation['project_id']):
                raise ValueError('engine.restore_target')
        if old:
            from .deletions import pending
            if pending(old['id']):raise ValueError('delete.pending')
        if old and old['enabled']: raise ValueError('Проект уже отслеживается')
        now=utcnow()
        if old:
            conn.execute('UPDATE projects SET enabled=1,updated_at=? WHERE id=?',(now,old['id']))
            return old['id']
        next_id=conn.execute('SELECT coalesce(max(value),0)+1 FROM (SELECT id AS value FROM projects UNION ALL SELECT project_id FROM user_audit)').fetchone()[0]
        pid=conn.execute('INSERT INTO projects(id,path,name,description,category,created_at,updated_at,scan_settings,exclusion_rules) VALUES(?,?,?,?,?,?,?,?,?)',
            (next_id,str(path),name.strip() or path.name,description,category.strip(),now,now,json.dumps(base_settings.scan_settings),json.dumps(base_settings.exclusion_rules))).lastrowid
        conn.execute('UPDATE projects SET history_path=?,backup_path=?,report_path=? WHERE id=?',
            (str(base_settings.data_dir/'projects'/str(pid)/'history.sqlite'),
             str(base_settings.backups_dir/'projects'/str(pid)),str(base_settings.reports_dir/'projects'/str(pid)),pid))
        return pid


def update_project(project_id,name,description,category,exclusions,scan):
    validate_options(name,description,category,exclusions,scan)
    if not name.strip(): raise ValueError('Укажите название')
    get_project(project_id,include_disabled=True)
    with registry() as conn:
        conn.execute('UPDATE projects SET name=?,description=?,category=?,exclusion_rules=?,scan_settings=?,updated_at=? WHERE id=?',
            (name.strip(),description,category.strip(),json.dumps(exclusions),json.dumps(scan),utcnow(),project_id))


def remove_project(project_id):
    get_project(project_id)
    with registry() as conn:
        conn.execute('UPDATE projects SET enabled=0,updated_at=? WHERE id=?',(utcnow(),project_id))


def project_settings(project):
    key=str(project['id'])
    # Explicit bindings survive migration; no runtime special case for ID 1.
    history=Path(project['history_path']) if project['history_path'] else base_settings.data_dir/'projects'/key/'history.sqlite'
    return replace(base_settings,agent_root=Path(project['path']),project_id=project['id'],
        data_dir=history.parent,db_path=history,
        backups_dir=Path(project['backup_path']) if project['backup_path'] else base_settings.backups_dir/'projects'/key,
        reports_dir=Path(project['report_path']) if project['report_path'] else base_settings.reports_dir/'projects'/key,
        metadata_dir=base_settings.metadata_dir/'projects'/key,
        exclusion_rules=tuple(project['exclusion_rules']),scan_settings=project['scan_settings'],
        protected_roots=tuple(set(base_settings.storage_roots)))


def set_detected_languages(project_id, languages):
    with registry() as conn:
        conn.execute('UPDATE projects SET detected_languages=?,updated_at=? WHERE id=?',
                     (json.dumps(sorted(languages)),utcnow(),project_id))
