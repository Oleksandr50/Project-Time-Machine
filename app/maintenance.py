"""Offline, checked database checkpoints and migration rehearsal. Never reads project sources."""
from contextlib import closing
from pathlib import Path
import hashlib
import json
import os
import sqlite3
import tempfile
import time
from . import migrations


def sync_directory(path):
    from .filesystem import open_directory
    with open_directory(path) as fd:os.fsync(fd)


def private_mkdir(path,exist_ok=False):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts:raise ValueError('Absolute checkpoint directory required')
    if path.is_symlink():raise ValueError('Symlink in checkpoint path')
    if path.exists():
        if not path.is_dir() or not exist_ok:raise FileExistsError(str(path))
        return
    private_mkdir(path.parent,exist_ok=True)
    from .filesystem import open_directory
    with open_directory(path.parent) as fd:
        os.mkdir(path.name,mode=0o700,dir_fd=fd);os.fsync(fd)


def checksum(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()


def fingerprints(conn,columns=None):
    if columns is None:
        tables=[r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('schema_info','schema_migrations')")]
        columns={t:[r[1] for r in conn.execute('PRAGMA table_info("'+t.replace('"','""')+'")')] for t in tables}
    result={}
    for table,fields in columns.items():
        sql='SELECT '+','.join('"'+f.replace('"','""')+'"' for f in fields)+' FROM "'+table.replace('"','""')+'"'
        hashes=[]
        for row in conn.execute(sql):
            raw=json.dumps(row,ensure_ascii=True,default=lambda v:{'bytes':v.hex()},separators=(',',':')).encode()
            hashes.append(hashlib.sha256(raw).digest())
        result[table]=dict(columns=fields,rows=len(hashes),sha256=hashlib.sha256(b''.join(sorted(hashes))).hexdigest())
    return result


def atomic_json(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd,name=tempfile.mkstemp(dir=path.parent,prefix='.write-')
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            json.dump(value,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(name,path)
        d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(d)
        finally:os.close(d)
    finally:
        if os.path.exists(name):os.unlink(name)


def databases(cfg):
    root=Path(cfg.data_dir).resolve();result=[]
    registry=root/'projects.sqlite'
    candidates=set(root.rglob('*.sqlite')) if root.exists() else set()
    if registry.exists():
        with closing(sqlite3.connect(registry.as_uri()+'?mode=ro',uri=True)) as c:
            columns={r[1] for r in c.execute('PRAGMA table_info(projects)')}
            if 'history_path' in columns:
                for row in c.execute('SELECT history_path FROM projects'):
                    if row[0]:
                        p=Path(row[0])
                        if not p.is_absolute() or not p.resolve().is_relative_to(root):raise ValueError('External history requires a separate manual migration')
                        if p.exists():candidates.add(p)
    for p in sorted(candidates):
        if p.is_symlink() or not p.resolve().is_relative_to(root):raise ValueError('Unsafe state path')
        with closing(sqlite3.connect(p.as_uri()+'?mode=ro',uri=True)) as c:
            row=c.execute("SELECT name FROM sqlite_master WHERE name='schema_info'").fetchone()
            if row:kind=c.execute('SELECT kind FROM schema_info').fetchone()[0]
            else:kind='registry' if p==registry else 'history'
            if kind not in migrations.MIGRATIONS:raise ValueError('Unknown database schema')
        result.append((p,kind))
    return result


def checkpoint(cfg,destination):
    """Call only with exclusive lifecycle guard. Content/archives/keys remain untouched."""
    import fcntl
    destination=Path(destination);private_mkdir(destination)
    locked=[]
    try:
        # Also refuse a server launched bypassing the supported lifecycle entrypoint.
        for p in (Path(cfg.data_dir)/'operation-locks').glob('*.lock'):
            fd=os.open(p,os.O_RDWR|os.O_NOFOLLOW);locked.append(fd)
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise ValueError('This instance still has active workers') from None
        entries=[]
        for source,kind in databases(cfg):
            target=destination/'databases'/source.relative_to(cfg.data_dir)
            private_mkdir(target.parent,exist_ok=True)
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
            deadline=time.monotonic()+60
            def progress(*_):
                if time.monotonic()>deadline:raise ValueError('Database checkpoint timeout')
            with closing(sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)) as src,closing(sqlite3.connect(target)) as dst:
                src.backup(dst,pages=128,progress=progress)
                migrations.check(dst)
                before=migrations.counts(src)
                if before!=migrations.counts(dst):raise ValueError('Database checkpoint count mismatch')
                logical=fingerprints(src)
                if logical!=fingerprints(dst):raise ValueError('Database checkpoint row mismatch')
            with target.open('rb') as f:os.fsync(f.fileno())
            sync_directory(target.parent)
            entries.append(dict(relative_path=source.relative_to(cfg.data_dir).as_posix(),kind=kind,sha256=checksum(target),counts=before,fingerprints=logical))
        config_file=os.environ.get('PTM_CONFIG')
        if config_file:
            raw=Path(config_file).read_bytes()
            config=destination/'settings.json';config.write_bytes(raw);config.chmod(0o600)
            with config.open('rb') as f:os.fsync(f.fileno())
        manifest=dict(format_version=1,databases=entries,content_copied=False,archives_copied=False,keys_copied=False)
        atomic_json(destination/'manifest.json',manifest)
        verify_checkpoint(destination)
        return manifest
    finally:
        for fd in locked:os.close(fd)


def verify_checkpoint(destination):
    destination=Path(destination);manifest=json.loads((destination/'manifest.json').read_text())
    if manifest.get('format_version')!=1:raise ValueError('Unsupported checkpoint')
    for item in manifest['databases']:
        rel=Path(item['relative_path'])
        if rel.is_absolute() or '..' in rel.parts:raise ValueError('Unsafe checkpoint path')
        p=destination/'databases'/rel
        if p.is_symlink() or checksum(p)!=item['sha256']:raise ValueError('Checkpoint checksum mismatch')
        with closing(sqlite3.connect(p.as_uri()+'?mode=ro',uri=True)) as c:
            migrations.check(c)
            if migrations.counts(c)!=item['counts']:raise ValueError('Checkpoint counts differ')
            if fingerprints(c)!=item['fingerprints']:raise ValueError('Checkpoint rows differ')
    return manifest


def rehearse(destination):
    import shutil
    destination=Path(destination);manifest=verify_checkpoint(destination)
    with tempfile.TemporaryDirectory(prefix='rehearsal-',dir=destination) as temp:
        for item in manifest['databases']:
            copy=Path(temp)/item['relative_path'];copy.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(destination/'databases'/item['relative_path'],copy)
            migrations.migrate(copy,item['kind'],Path(temp)/'pre-migration')
            with closing(sqlite3.connect(copy)) as c:
                migrations.check(c)
                columns={t:v['columns'] for t,v in item['fingerprints'].items()}
                if fingerprints(c,columns)!=item['fingerprints']:raise ValueError('Rehearsal changed old rows')
    atomic_json(destination/'rehearsal.json',dict(status='passed',databases=len(manifest['databases'])))


def migrate_checked(cfg,destination):
    manifest=verify_checkpoint(destination)
    if json.loads((Path(destination)/'rehearsal.json').read_text()).get('status')!='passed':raise ValueError('Rehearsal required')
    for item in manifest['databases']:
        migrations.migrate(Path(cfg.data_dir)/item['relative_path'],item['kind'],cfg.migrations_dir)


def recover(cfg,destination):
    """Explicit update recovery only, under exclusive guard, before any server restart."""
    import shutil
    destination=Path(destination);manifest=verify_checkpoint(destination)
    for item in manifest['databases']:
        target=Path(cfg.data_dir)/item['relative_path'];private_mkdir(target.parent,exist_ok=True)
        parked_main=destination/'superseded'/item['relative_path']
        if parked_main.exists() and target.exists():
            if checksum(target)!=item['sha256'] or any(Path(str(target)+s).exists() for s in ('-wal','-shm','-journal')):
                raise ValueError('State changed after interrupted recovery; both copies retained')
            continue
        for suffix in ('','-wal','-shm','-journal'):
            old=Path(str(target)+suffix)
            if old.exists():
                parked=Path(str(parked_main)+suffix);private_mkdir(parked.parent,exist_ok=True)
                if parked.exists():raise ValueError('Conflicting recovery state; both copies retained')
                os.replace(old,parked)
                sync_directory(old.parent);sync_directory(parked.parent)
        fd,name=tempfile.mkstemp(dir=target.parent,prefix='.recover-')
        with os.fdopen(fd,'wb') as f,(destination/'databases'/item['relative_path']).open('rb') as src:
            shutil.copyfileobj(src,f);f.flush();os.fsync(f.fileno())
        os.replace(name,target)
        d=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(d)
        finally:os.close(d)
