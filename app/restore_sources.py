"""Verified point / recoverable snapshot / registered legacy archive readers."""
from contextlib import contextmanager
from pathlib import Path
import hashlib
import os
import sqlite3
import tarfile
from . import backups,db
from .config import settings
from .archives import open_archive
from .backup_format import canonical,package,validate_manifest
from .backup_storage import (BackupError,CHUNK,consume,load_key,object_aad,relative_name,
                             read_private,private_dir,ensure_space,digest_stream)


def fingerprint(spec):
    return hashlib.sha256(canonical(spec)).hexdigest()


def legacy_entries(row,tick,stage=None):
    entries=[];seen=set();folded=set();prefix=None;total=0
    private_dir(settings.temp_dir)
    with open_archive(row['archive_path']) as stream:
        if digest_stream(stream,tick)[0]!=row['sha256']:raise BackupError('corrupt')
        stream.seek(0)
        try:
            with tarfile.open(fileobj=stream,mode='r|gz') as archive:
                for member in archive:
                    tick()
                    name=relative_name(member.name.rstrip('/'))
                    parts=name.split('/')
                    if prefix is None:prefix=parts[0]
                    if parts[0]!=prefix or not (member.isfile() or member.isdir()) or member.issparse():raise BackupError('unsafe_path')
                    if len(parts)==1:
                        if not member.isdir():raise BackupError('format')
                        continue
                    name='/'.join(parts[1:])
                    if name in seen or name.casefold() in folded:raise BackupError('unsafe_path')
                    seen.add(name);folded.add(name.casefold())
                    if len(seen)>100000 or member.size<0:raise BackupError('format')
                    entry=dict(path=name,type='dir' if member.isdir() else 'file',mode=member.mode&0o777,mtime_ns=int(member.mtime*10**9))
                    if member.isfile():
                        total+=member.size;ensure_space(settings.temp_dir,total)
                        h=hashlib.sha256();size=0;head=b''
                        target=stage.get(name) if stage else None
                        out=target.open('xb') if target else None
                        if out:os.fchmod(out.fileno(),0o600)
                        try:
                            with archive.extractfile(member) as content:
                                for chunk in iter(lambda:content.read(CHUNK),b''):
                                    tick();h.update(chunk);size+=len(chunk)
                                    if not head:head=chunk[:16]
                                    if out:out.write(chunk)
                            if size!=member.size:raise BackupError('corrupt')
                            if out:out.flush();os.fsync(out.fileno())
                        finally:
                            if out:out.close()
                        entry.update(size=size,sha256=h.hexdigest(),sqlite=head==b'SQLite format 3\0')
                    entries.append(entry)
        except (tarfile.TarError,EOFError):raise BackupError('corrupt') from None
    # Fill omitted parent dirs conservatively; reject file/directory collisions.
    byname={e['path']:e for e in entries}
    for e in list(entries):
        for parent in Path(e['path']).parents:
            if str(parent)=='.':continue
            name=parent.as_posix()
            if name in byname and byname[name]['type']!='dir':raise BackupError('unsafe_path')
            byname.setdefault(name,dict(path=name,type='dir',mode=0o755,mtime_ns=0))
    sqlite_paths={e['path'] for e in entries if e.get('sqlite')}
    if any(name+suffix in byname for name in sqlite_paths for suffix in ('-wal','-journal')):
        raise BackupError('restore_legacy_sqlite')
    return list(byname.values())


def inspect(kind,identifier,tick=lambda:None):
    db.init_db()
    if kind=='snapshot':
        try:sid=int(identifier)
        except (ValueError,TypeError):raise BackupError('restore_source')
        with db.db_conn() as conn:
            snap=conn.execute('SELECT * FROM snapshots WHERE id=?',(sid,)).fetchone()
            if not snap or snap['content_status']!='recoverable':raise BackupError('restore_metadata')
            if snap['backup_point_id']:
                result=inspect('point',snap['backup_point_id'],tick)
                result['requested_snapshot']=sid
                return result
            rows=conn.execute('SELECT f.*,c.object_digest,o.storage_key,o.verified_at,o.size AS object_size FROM snapshot_files f LEFT JOIN snapshot_content c ON c.snapshot_id=f.snapshot_id AND c.path=f.path LEFT JOIN content_objects o ON o.digest=c.object_digest WHERE f.snapshot_id=?',(sid,)).fetchall()
        entries=[];objects={}
        for row in rows:
            tick();entry=dict(row)
            if not entry['verified_at'] or entry['sha256']!=entry['object_digest'] or entry['object_size']!=entry['size']:raise BackupError('restore_metadata')
            key=relative_name(entry['storage_key'])
            with read_private(settings.content_dir/key) as stream:
                if digest_stream(stream,tick)!=(entry['sha256'],entry['size']):raise BackupError('corrupt')
            entries.append(dict(path=relative_name(entry['path']),type='file',size=entry['size'],sha256=entry['sha256'],
                                mode=0o644,mtime_ns=entry['mtime']*10**9,sqlite=entry['file_type']=='sqlite'))
            objects[entry['path']]=key
        _parents(entries)
        result=dict(kind='cas',id=str(sid),entries=entries,objects=objects,exclusions=[],secret_policy='local',
                    created_at=snap['created_at'],description=snap['description'] or '')
    elif kind=='point':
        chain,_=backups.verified_chain(str(identifier),tick)
        m=chain[0][1]
        result=dict(kind='point',id=m['id'],entries=m['files'],exclusions=m['exclusions'],secret_policy=m['secret_policy'],
                    chain=[{'id':r['id'],'sha256':r['sha256'],'manifest_sha256':r['manifest_sha256']} for r,_ in chain],
                    created_at=m['created_at'],description=m.get('description',''),backup_kind=m['kind'])
        if m.get('restore_context'):result['restore_context']=m['restore_context']
    elif kind=='legacy':
        try:bid=int(identifier)
        except (ValueError,TypeError):raise BackupError('restore_source')
        with db.db_conn() as conn:
            row=conn.execute('SELECT * FROM backups WHERE id=?',(bid,)).fetchone()
            if not row or conn.execute('SELECT 1 FROM backup_points WHERE backup_id=?',(bid,)).fetchone():raise BackupError('restore_source')
            row=dict(row)
        entries=legacy_entries(row,tick)
        result=dict(kind='legacy',id=str(bid),entries=entries,archive_path=row['archive_path'],sha256=row['sha256'],
                    exclusions=[],secret_policy='warn',created_at=row['created_at'],description='')
    else:raise BackupError('restore_source')
    validate_manifest(dict(format='ptm-backup',version=1,id='0'*32,project_id=settings.project_id,
                           kind='full',parent=None,files=result['entries'],
                           objects=sorted({e['sha256'] for e in result['entries'] if e['type']=='file'}),
                           deleted=[],secret_policy=result['secret_policy']))
    result['fingerprint']=fingerprint(result)
    return result


def _parents(entries):
    known={e['path'] for e in entries}
    for e in list(entries):
        for parent in Path(e['path']).parents:
            name=parent.as_posix()
            if name!='.' and name not in known:
                known.add(name);entries.append(dict(path=name,type='dir',mode=0o755,mtime_ns=0))


def stage(source,paths,tick=lambda:None):
    """paths is an application-owned flat staging map, never a user destination."""
    entries={e['path']:e for e in source['entries']}
    if source['kind']=='point':
        chain,available=backups.verified_chain(source['id'],tick)
        if [dict(id=r['id'],sha256=r['sha256'],manifest_sha256=r['manifest_sha256']) for r,_ in chain]!=source['chain']:
            raise BackupError('restore_stale')
        for row,_ in reversed(chain):
            wanted=[name for name in paths if available[entries[name]['sha256']][0]['id']==row['id']]
            if not wanted:continue
            with package(row['archive_path'],row,settings,tick) as (_,archive):
                for name in wanted:
                    tick();entry=entries[name];member='objects/'+entry['sha256']
                    with archive.open(member) as raw,paths[name].open('xb') as out:
                        paths[name].chmod(0o600)
                        consume(raw,archive.getinfo(member).file_size,load_key(row['key_id'],settings),
                                object_aad(settings.project_id,row['key_id'],entry['sha256']),entry['sha256'],entry['size'],tick,out)
                        out.flush();os.fsync(out.fileno())
    elif source['kind']=='legacy':
        actual=legacy_entries(source,tick,paths)
        if fingerprint(actual)!=fingerprint(source['entries']):raise BackupError('restore_stale')
    else:
        for name,path in paths.items():
            tick();entry=entries[name]
            with read_private(settings.content_dir/relative_name(source['objects'][name])) as raw,path.open('xb') as out:
                path.chmod(0o600)
                consume(raw,entry['size'],None,b'',entry['sha256'],entry['size'],tick,out)
                out.flush();os.fsync(out.fileno())
