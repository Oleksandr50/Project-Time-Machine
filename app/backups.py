"""Verified backup engine. No code in this module writes to a monitored project."""
from contextlib import ExitStack
from datetime import datetime,timezone
from pathlib import Path
import hashlib
import io
import json
import os
import shutil
import sqlite3
import stat
import tempfile
import uuid
from . import projects,db,scanner
from .config import settings
from .migrations import utcnow
from .backup_storage import (BackupError,ObjectStore,private_dir,project_lock,capacity,
                             ensure_space,fsync_dir,read_private,digest_file,consume,object_aad)
from .backup_storage import load_key
from .backup_capture import inventory,capture,is_sqlite,identity
from .backup_format import canonical,package,write_package,validate_manifest


def policy(project_id):
    default=dict(project_id=project_id,secret_policy='warn',key_id='',auto_delete=0,keep_last=20,min_age_days=30)
    with projects.registry() as conn:
        row=conn.execute('SELECT * FROM backup_policies WHERE project_id=?',(project_id,)).fetchone()
    return dict(row) if row else default


def save_policy(pid,secret_policy,key_id,auto_delete,keep_last,min_age_days,conn=None):
    if secret_policy not in ('local','exclude','warn') or key_id=='plain' or key_id not in ('',*projects.base_settings.encryption_keys):raise BackupError('policy')
    if type(keep_last) is not int or not 1<=keep_last<=100000 or type(min_age_days) is not int or not 0<=min_age_days<=36500:raise BackupError('policy')
    if conn is None:
        with projects.registry() as c:return save_policy(pid,secret_policy,key_id,auto_delete,keep_last,min_age_days,c)
    conn.execute('INSERT INTO backup_policies VALUES(?,?,?,?,?,?) ON CONFLICT(project_id) DO UPDATE SET secret_policy=excluded.secret_policy,key_id=excluded.key_id,auto_delete=excluded.auto_delete,keep_last=excluded.keep_last,min_age_days=excluded.min_age_days',
                 (pid,secret_policy,key_id,int(bool(auto_delete)),keep_last,min_age_days))


def points():
    db.init_db()
    with db.db_conn() as conn:
        return [dict(r) for r in conn.execute('SELECT p.*,b.archive_path,b.sha256,b.archive_size,b.created_at FROM backup_points p JOIN backups b ON b.id=p.backup_id ORDER BY b.id DESC')]


def point(point_id):
    row=next((p for p in points() if p['id']==point_id),None)
    if not row or row['state']!='available':raise BackupError('missing')
    # A registered path may not select any arbitrary configured archive.
    expected=settings.backups_dir/'engine-v1'/(row['id']+'.ptm')
    if Path(row['archive_path'])!=expected:raise BackupError('unsafe_path')
    return row


def verified_chain(point_id,tick=lambda:None,head=None):
    """All ancestors and payloads are checked, including archive bytes and edge digests."""
    result=[];seen=set();current=head or point(point_id)
    while current:
        tick()
        if current['id'] in seen or len(seen)>=256:raise BackupError('chain')
        seen.add(current['id'])
        with package(current['archive_path'],current,settings,tick) as (manifest,_):
            result.append((current,manifest))
        parent=manifest['parent']
        if not parent:break
        try:current=point(parent['id'])
        except BackupError:raise BackupError('chain') from None
        if (current['sha256'],current['manifest_sha256'],current['key_id'])!=(parent['archive_sha256'],parent['manifest_sha256'],manifest['key_id']):
            raise BackupError('chain')
    available={};previous=None
    for record,manifest in reversed(result):
        objects=validate_manifest(manifest)
        if previous is not None:
            parent_objects=validate_manifest(previous)
            if manifest['parent']['id']!=previous['id']:raise BackupError('chain')
            expected=set(objects)-set(parent_objects)
            # Object may have disappeared and returned: include it again, independently.
            if set(manifest['objects'])!=expected:raise BackupError('chain')
            if set(manifest['deleted'])!={f['path'] for f in previous['files']}-{f['path'] for f in manifest['files']}:raise BackupError('chain')
        elif set(manifest['objects'])!=set(objects):raise BackupError('chain')
        for digest in manifest['objects']:available[digest]=(record,objects[digest])
        if any(d not in available or available[d][1]!=size for d,size in objects.items()):raise BackupError('chain')
        previous=manifest
    return result,available


def verify(point_id,tick=lambda:None):
    with project_lock(settings.project_id),capacity():
        return verify_unlocked(point_id,tick)


def verify_unlocked(point_id,tick=lambda:None):
    try:
        chain,_=verified_chain(point_id,tick)
        with db.db_conn() as conn:
            for row,_ in chain:
                conn.execute("UPDATE backup_points SET verified_at=?,last_error='' WHERE id=?",(utcnow(),row['id']))
                conn.execute("UPDATE snapshots SET content_status='recoverable' WHERE backup_point_id=?",(row['id'],))
        return chain[0][1]
    except BackupError as exc:
        with db.db_conn() as conn:
            conn.execute('UPDATE backup_points SET last_error=? WHERE id=?',(exc.code,point_id))
            conn.execute("UPDATE snapshots SET content_status='unavailable' WHERE backup_point_id=?",(point_id,))
        raise


def create(kind='full',description='',actor_id=None,job_id=None,tick=lambda:None,progress=lambda **_:None,commit_check=None):
    if kind not in ('full','incremental','checkpoint','pre_restore') or len(description)>4000:raise BackupError('policy')
    cfg=projects.current_settings.get()
    if cfg.project_id is None or cfg.agent_root is None:raise BackupError('policy')
    with project_lock(cfg.project_id),capacity():
        return _create_locked(kind,description,actor_id,job_id,tick,progress,commit_check)


def _create_locked(kind='full',description='',actor_id=None,job_id=None,tick=lambda:None,progress=lambda **_:None,commit_check=None,options_override=None,restore_context=None):
    """Internal caller owns project lock + capacity throughout backup/restore orchestration."""
    cfg=projects.current_settings.get()
    db.init_db()
    if any(p['state']=='deleting' for p in points()):raise BackupError('interrupted')
    opts=options_override or policy(cfg.project_id)
    store=ObjectStore(cfg,opts['key_id'],tick)
    backup_dir=private_dir(cfg.backups_dir/'engine-v1');workspace=private_dir(cfg.temp_dir)
    parent=None;parent_manifest=None
    if kind=='incremental':
        parent=next((p for p in points() if p['state']=='available' and p['kind']!='pre_restore' and p['key_id']==opts['key_id']),None)
        if not parent:raise BackupError('parent_required')
        chain,_=verified_chain(parent['id'],tick)
        parent_manifest=chain[0][1]
        if parent_manifest['exclusions']!=list(cfg.exclusion_rules) or parent_manifest['secret_policy']!=opts['secret_policy']:
            raise BackupError('parent_policy')
    initial=inventory(cfg,tick)
    if len(initial)>100000:raise BackupError('format')
    ensure_space(workspace,sum(st.st_size for st in initial.values() if stat.S_ISREG(st.st_mode))*3)
    # Independent destination volumes each get a conservative bound, not merely /tmp.
    total=sum(st.st_size for st in initial.values() if stat.S_ISREG(st.st_mode))
    ensure_space(store.root,total+len(initial)*128)
    ensure_space(backup_dir,total+len(initial)*2048+1024*1024)
    progress(total_bytes=total,total_files=sum(stat.S_ISREG(st.st_mode) for st in initial.values()))
    sqlite_paths={rel for rel,st in initial.items() if stat.S_ISREG(st.st_mode) and is_sqlite(cfg.agent_root/rel)}
    sqlite_sidecars={name+suffix for name in sqlite_paths for suffix in ('-wal','-shm','-journal')}
    if any(rel in initial and not stat.S_ISREG(initial[rel].st_mode) for rel in sqlite_sidecars):
        raise BackupError('unsupported_file')
    entries=[];omissions=[];done=0;done_bytes=0
    from .analyzer import is_secret_path
    with tempfile.TemporaryDirectory(prefix='backup-',dir=workspace) as work:
        work=Path(work)
        for rel,st in sorted(initial.items()):
            tick()
            if rel in sqlite_sidecars:continue
            secret=is_secret_path(rel)
            if secret and opts['secret_policy']=='exclude':omissions.append(rel);continue
            if stat.S_ISDIR(st.st_mode):
                entries.append(dict(path=rel,type='dir',mtime_ns=st.st_mtime_ns,mode=stat.S_IMODE(st.st_mode)&0o777))
                continue
            ensure_space(work,st.st_size*3)
            for attempt in range(3):
                try:
                    item=capture(cfg.agent_root/rel,store,work,tick);break
                except BackupError as exc:
                    if exc.code!='source_changed' or attempt==2:raise
            item.update(path=rel,type='file',secret=bool(secret),category=scanner.category(rel))
            entries.append(item);done+=1;done_bytes+=item['size']
            progress(progress_files=done,progress_bytes=done_bytes)
        # No silently omitted file from a racing scan. Each non-SQLite file must still match capture.
        final=inventory(cfg,tick)
        if any(rel in final and not stat.S_ISREG(final[rel].st_mode) for rel in sqlite_sidecars):
            raise BackupError('unsupported_file')
        # SQLite Backup API captured a verified standalone database. Its transient
        # WAL/SHM/rollback journals are intentionally absent from the manifest and
        # may be created/deleted by live writers after that per-file capture.
        if set(initial)-sqlite_sidecars!=set(final)-sqlite_sidecars:raise BackupError('source_changed')
        for entry in entries:
            if entry['type']=='file' and not entry['sqlite']:
                st=final[entry['path']]
                if identity(initial[entry['path']])!=identity(st) or st.st_size!=entry['size'] or st.st_mtime_ns!=entry['mtime_ns']:raise BackupError('source_changed')
    progress(total_files=done,total_bytes=done_bytes,progress_files=done,progress_bytes=done_bytes)
    point_id=job_id or uuid.uuid4().hex
    files_by_sha={entry['sha256']:entry for entry in entries if entry['type']=='file'}
    previous_sha={e['sha256'] for e in parent_manifest['files'] if e['type']=='file'} if parent_manifest else set()
    manifest=dict(format='ptm-backup',version=1,id=point_id,project_id=cfg.project_id,
                  project_name=projects.get_project(cfg.project_id)['name'],created_at=utcnow(),actor_id=actor_id,
                  description=description,kind=kind,key_id=store.key_id,secret_policy=opts['secret_policy'],
                  exclusions=list(cfg.exclusion_rules),omitted_secrets=omissions,
                  consistency='per-file; SQLite Backup API; other live services require native backup',
                  files=entries,objects=sorted(set(files_by_sha)-previous_sha),
                  parent=dict(id=parent['id'],archive_sha256=parent['sha256'],manifest_sha256=parent['manifest_sha256']) if parent else None,
                  deleted=sorted({e['path'] for e in parent_manifest['files']}-{e['path'] for e in entries}) if parent_manifest else [])
    if restore_context is not None:manifest['restore_context']=restore_context
    validate_manifest(manifest)
    fd,raw=tempfile.mkstemp(prefix='.pending-',suffix='.ptm',dir=backup_dir);os.close(fd);temp=Path(raw)
    final_path=backup_dir/(point_id+'.ptm')
    try:
        manifest_sha=write_package(temp,manifest,store,tick)
        with temp.open('rb') as stream:os.fsync(stream.fileno())
        archive_sha=digest_file(temp,tick)
        candidate=dict(id=point_id,key_id=store.key_id,sha256=archive_sha,manifest_sha256=manifest_sha,archive_path=str(temp))
        verified_chain(point_id,tick,head=candidate)  # exact same parser used after publication
        (commit_check or tick)()
        # Preserve orphan archives on crashes; a UUID is never overwritten.
        os.link(temp,final_path,follow_symlinks=False);fsync_dir(backup_dir)
        # Publication of point/snapshot/references/legacy compatibility row is one SQLite transaction.
        with db.db_conn() as conn:
            warning='engine.secrets_warning' if any(e.get('secret') for e in entries) and not store.key else ''
            bid=conn.execute('INSERT INTO backups(created_at,archive_path,archive_size,sha256,warning) VALUES(?,?,?,?,?)',
                             (manifest['created_at'],str(final_path),final_path.stat().st_size,archive_sha,warning)).lastrowid
            files=[e for e in entries if e['type']=='file']
            sid=conn.execute('INSERT INTO snapshots(created_at,description,agent_root,total_files,python_files,total_bytes,functions_count,classes_count,sqlite_files,log_files,baseline_digest,content_status,project_id,backup_point_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                 (manifest['created_at'],description,restore_context['target'] if restore_context else str(cfg.agent_root),len(files),sum(e['path'].endswith('.py') for e in files),
                 sum(e['size'] for e in files),0,0,sum(e['sqlite'] for e in files),sum(e['path'].endswith('.log') for e in files),
                 manifest_sha,'recoverable',cfg.project_id,point_id)).lastrowid
            conn.execute('UPDATE backups SET snapshot_id=? WHERE id=?',(sid,bid))
            conn.execute('INSERT INTO backup_points(id,backup_id,snapshot_id,job_id,kind,parent_id,manifest_sha256,key_id,verified_at) VALUES(?,?,?,?,?,?,?,?,?)',
                         (point_id,bid,sid,job_id,kind,parent['id'] if parent else None,manifest_sha,store.key_id,utcnow()))
            for e in files:
                ext=Path(e['path']).suffix.lower()
                file_type='sqlite' if e['sqlite'] else ('python' if ext=='.py' else ('text' if ext in ('.txt','.md','.json','.js','.ts','.yaml','.yml','.toml','.ini','.html','.css','.php','.java','.cs') else ('log' if ext=='.log' else 'binary')))
                conn.execute('INSERT INTO snapshot_files(snapshot_id,path,size,mtime,sha256,file_type,is_secret,file_category) VALUES(?,?,?,?,?,?,?,?)',
                             (sid,e['path'],e['size'],e['mtime_ns']//10**9,e['sha256'],file_type,int(e['secret']),e['category']))
                if not store.key:
                    conn.execute('INSERT INTO content_objects(digest,size,storage_key,verified_at) VALUES(?,?,?,?) ON CONFLICT(digest) DO UPDATE SET verified_at=excluded.verified_at',
                                 (e['sha256'],e['size'],e['storage_key'],utcnow()))
                    conn.execute('INSERT INTO snapshot_content VALUES(?,?,?)',(sid,e['path'],e['sha256']))
            conn.executemany('INSERT INTO backup_point_objects VALUES(?,?,?,?,?)',
                             [(point_id,sha,e['storage_key'],e['size'],e['stored_size']) for sha,e in files_by_sha.items()])
        return dict(backup_id=bid,point_id=point_id,snapshot_id=sid,archive_path=str(final_path),sha256=archive_sha,manifest=manifest)
    finally:temp.unlink(missing_ok=True)


def read_verified_file(point_id,path,sink,tick=lambda:None):
    """Internal read primitive for engine integration tests/future staging, no destination paths."""
    with project_lock(settings.project_id),capacity():
        chain,available=verified_chain(point_id,tick)
        target=next((e for e in chain[0][1]['files'] if e['path']==path and e['type']=='file'),None)
        if not target:raise BackupError('missing')
        record,_=available[target['sha256']]
        with package(record['archive_path'],record,settings,tick) as (manifest,archive):
            name='objects/'+target['sha256']
            with archive.open(name) as source:
                consume(source,archive.getinfo(name).file_size,load_key(record['key_id'],settings),
                        object_aad(settings.project_id,record['key_id'],target['sha256']),
                        target['sha256'],target['size'],tick,sink)


def protect(point_id,value):
    with project_lock(settings.project_id):
        point(point_id)
        with db.db_conn() as conn:conn.execute('UPDATE backup_points SET protected=? WHERE id=?',(int(bool(value)),point_id))


def retention_candidates(now=None):
    opts=policy(settings.project_id);rows=points();available=[p for p in rows if p['state']=='available']
    keep={p['id'] for p in available[:opts['keep_last']]}|{p['id'] for p in available if p['protected']}
    now=now or datetime.now(timezone.utc).timestamp()
    for p in available:
        if now-datetime.fromisoformat(p['created_at']).timestamp()<opts['min_age_days']*86400:keep.add(p['id'])
    byid={p['id']:p for p in available}
    pending=list(keep)
    while pending:
        item=byid[pending.pop()]
        if item['parent_id'] and item['parent_id'] not in keep:
            if item['parent_id'] not in byid:raise BackupError('chain')
            keep.add(item['parent_id']);pending.append(item['parent_id'])
    return [p for p in reversed(available) if p['id'] not in keep]


def retention(tick=lambda:None):
    """Opt-in only. Journal before unlink, preserve every metadata/history row."""
    with project_lock(settings.project_id),capacity():
        db.init_db()
        if not policy(settings.project_id)['auto_delete']:raise BackupError('retention_disabled')
        candidates=retention_candidates()
        # First prove all kept recovery points, before removing any old archive.
        deleted={p['id'] for p in candidates}
        for p in points():
            if p['state']=='available' and p['id'] not in deleted:verified_chain(p['id'],tick)
        for p in candidates:
            tick()
            with db.db_conn() as conn:conn.execute("UPDATE backup_points SET state='deleting' WHERE id=?",(p['id'],))
            finish_deletion(p)
        return len(candidates)


def finish_deletion(p):
    path=settings.backups_dir/'engine-v1'/(p['id']+'.ptm')
    if str(path)!=p['archive_path']:raise BackupError('unsafe_path')
    # A replaced symlink is never followed, nor used to select a different filename.
    from .filesystem import open_directory
    with open_directory(path.parent) as directory:
        try:os.unlink(path.name,dir_fd=directory)
        except FileNotFoundError:pass
        os.fsync(directory)
    with db.db_conn() as conn:
        conn.execute("UPDATE snapshots SET content_status='unavailable' WHERE backup_point_id=?",(p['id'],))
        conn.execute('DELETE FROM snapshot_content WHERE snapshot_id=?',(p['snapshot_id'],))
    # CAS collection is restricted to objects of this deleted point, checking all references.
    with db.db_conn() as conn:
        for item in conn.execute('SELECT * FROM backup_point_objects WHERE point_id=?',(p['id'],)).fetchall():
            used=conn.execute("SELECT 1 FROM backup_point_objects o JOIN backup_points b ON b.id=o.point_id WHERE o.storage_key=? AND b.state!='deleted' AND b.id!=? LIMIT 1",(item['storage_key'],p['id'])).fetchone()
            extra=conn.execute('SELECT 1 FROM snapshot_content c JOIN content_objects o ON o.digest=c.object_digest WHERE o.storage_key=? LIMIT 1',(item['storage_key'],)).fetchone()
            if used or extra:continue
            # Deletion needs no decryption key, but may only address canonical owned CAS names.
            import re
            if not re.fullmatch('[0-9a-f]{64}',item['digest']) or p['key_id'] and not re.fullmatch('[A-Za-z0-9_-]{1,40}',p['key_id']):raise BackupError('unsafe_path')
            actual=settings.content_dir/'projects'/str(settings.project_id)/(p['key_id'] or 'plain')/item['digest'][:2]/item['digest']
            if actual.relative_to(settings.content_dir).as_posix()!=item['storage_key']:raise BackupError('unsafe_path')
            with open_directory(actual.parent) as directory:
                try:os.unlink(actual.name,dir_fd=directory)
                except FileNotFoundError:pass
                os.fsync(directory)
            conn.execute('DELETE FROM content_objects WHERE digest=? AND storage_key=?',(item['digest'],item['storage_key']))
        conn.execute("UPDATE backup_points SET state='deleted' WHERE id=?",(p['id'],))
