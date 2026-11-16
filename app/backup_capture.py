"""Stable regular-file reads and SQLite backups using private coherent DB/WAL copies."""
from pathlib import Path
from contextlib import closing
import os
import sqlite3
import stat
import tempfile
import time
from . import scanner
from .backup_storage import BackupError, CHUNK, ensure_space, digest_stream


def identity(st):
    return st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns


def inventory(cfg,tick=lambda:None):
    result={}
    try:
        for path,st in scanner.iter_files(cfg.agent_root,strict=True,include_dirs=True):
            tick()
            rel=path.relative_to(cfg.agent_root).as_posix()
            from .backup_storage import relative_name
            relative_name(rel)
            result[rel]=st
            if len(result)>100000:raise BackupError('format')
    except FileNotFoundError:
        # A disappearing source (including a SQLite journal) is a retryable race,
        # never evidence of a completed backup or an unexplained I/O failure.
        raise BackupError('source_changed') from None
    return result


def stable_copy(path,destination,tick):
    with scanner.open_source(path) as source:
        before=os.fstat(source.fileno())
        for chunk in iter(lambda:source.read(CHUNK),b''):tick();destination.write(chunk)
        if identity(before)!=identity(os.fstat(source.fileno())):raise BackupError('source_changed')
    with scanner.open_source(path) as fresh:
        if identity(before)!=identity(os.fstat(fresh.fileno())):raise BackupError('source_changed')
    return before


def is_sqlite(path):
    with scanner.open_source(path) as stream:return stream.read(16)==b'SQLite format 3\0'


def sqlite_capture(path,target,tick,workspace):
    """No SQLite connection to source: cannot create SHM/checkpoint a monitored DB."""
    for attempt in range(3):
        try:
            with tempfile.TemporaryDirectory(prefix='sqlite-',dir=workspace) as raw:
                raw=Path(raw);main=raw/'capture.sqlite';states={}
                for suffix in ('','-wal','-journal'):
                    item=Path(str(path)+suffix)
                    try:
                        with scanner.open_source(item) as source:
                            st=os.fstat(source.fileno())
                    except FileNotFoundError:
                        states[suffix]=None;continue
                    ensure_space(workspace,st.st_size*2)
                    with (raw/('capture.sqlite'+suffix)).open('xb') as out:
                        (raw/('capture.sqlite'+suffix)).chmod(0o600)
                        states[suffix]=stable_copy(item,out,tick)
                # Both existence and identities must remain stable over the entire capture.
                for suffix,before in states.items():
                    try:
                        with scanner.open_source(Path(str(path)+suffix)) as stream:after=os.fstat(stream.fileno())
                    except FileNotFoundError:after=None
                    if (before is None)!=(after is None) or before is not None and identity(before)!=identity(after):
                        raise BackupError('source_changed')
                deadline=time.monotonic()+30
                def progress(*_):
                    tick()
                    if time.monotonic()>deadline:raise BackupError('sqlite_busy')
                # Private copy is opened read/write so WAL recovery has no side effects on source.
                with closing(sqlite3.connect(main,timeout=1)) as source,closing(sqlite3.connect(target,timeout=1)) as dest:
                    source.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
                    if source.execute('PRAGMA quick_check').fetchall()!=[('ok',)]:raise BackupError('sqlite_invalid')
                    source.backup(dest,pages=256,progress=progress,sleep=0.01)
                    if dest.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:raise BackupError('sqlite_invalid')
                target.chmod(0o600)
                return states['']
        except (BackupError,sqlite3.DatabaseError):
            target.unlink(missing_ok=True)
            if attempt==2:raise BackupError('sqlite_unstable') from None


def capture(path,store,workspace,tick):
    sqlite=is_sqlite(path)
    fd,filename=tempfile.mkstemp(prefix='capture-',dir=workspace);os.close(fd);temp=Path(filename)
    try:
        if sqlite:
            temp.unlink()
            before=sqlite_capture(path,temp,tick,workspace)
        else:
            with temp.open('wb') as out:before=stable_copy(path,out,tick)
        with temp.open('rb') as source:
            digest,size=digest_stream(source,tick);source.seek(0)
            stored=store.put(source,digest,size)
        return dict(sha256=digest,size=size,mtime_ns=before.st_mtime_ns,mode=stat.S_IMODE(before.st_mode)&0o777,
                    sqlite=sqlite,**stored)
    finally:temp.unlink(missing_ok=True)
