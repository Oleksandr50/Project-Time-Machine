"""Anchored POSIX operations and same-filesystem, no-clobber journal primitives."""
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
import ctypes
import errno
import hashlib
import json
import os
import stat
import time
from itertools import chain
from . import projects,scanner
from .filesystem import absolute,validate_project,open_directory,inside,forbidden,private_origin
from .backup_capture import inventory,identity
from .backup_storage import BackupError,CHUNK,relative_name,ensure_space

WORK_PREFIX='.ptm-restore-'


def node(st):
    return dict(dev=st.st_dev,ino=st.st_ino,mode=stat.S_IMODE(st.st_mode)&0o777,
                mtime_ns=st.st_mtime_ns,ctime_ns=st.st_ctime_ns,
                type='dir' if stat.S_ISDIR(st.st_mode) else 'file',size=st.st_size)


def root_id(path):
    with open_directory(path) as fd:
        st=os.fstat(fd);return [st.st_dev,st.st_ino]


def validate_target(cfg,mode,destination=''):
    target=absolute(destination if mode in ('alternate','recovery') else cfg.agent_root)
    try:
        validate_project(target,cfg);exists=True
    except FileNotFoundError:exists=False
    if exists and mode=='alternate':raise BackupError('restore_new_only')
    if not exists:
        validate_project(target.parent,cfg)
        if not target.name or target.name.startswith(WORK_PREFIX):raise BackupError('unsafe_path')
        # lexical validation for missing leaf; parents are opened no-follow above.
        relative_name(target.name)
        if target.is_symlink():raise BackupError('unsafe_path')
    extras=[]
    for project in projects.list_projects(include_disabled=True):
        path=Path(project['path'])
        if project['id']==cfg.project_id:
            if mode=='alternate' and (inside(target,path) or inside(path,target)):raise BackupError('restore_target')
            continue
        if inside(target,path) or not exists and inside(path,target):raise BackupError('restore_target')
        if inside(path,target):extras.append(path.relative_to(target).as_posix())
    if not exists:
        for storage in cfg.storage_roots:
            p=Path(storage).resolve()
            if inside(target,p) or inside(p,target):raise BackupError('restore_target')
    # Another project's alternative destination is also a leased target.
    with projects.registry() as conn:
        for row in conn.execute("SELECT project_id,target_path FROM restore_operations WHERE state IN ('queued','preparing','applying','interrupted','undoing')"):
            p=Path(row['target_path'])
            if row['project_id']!=cfg.project_id and (inside(target,p) or inside(p,target)):raise BackupError('restore_target')
    return target,exists,extras


def state(cfg,tick=lambda:None,secret_policy='local'):
    token=projects.current_settings.set(cfg)
    try:return _state(cfg,tick,secret_policy)
    finally:projects.current_settings.reset(token)


def _state(cfg,tick,secret_policy):
    validate_project(cfg.agent_root,cfg)
    from .analyzer import is_secret_path
    entries={}
    for rel,st in inventory(cfg,tick).items():
        tick()
        if secret_policy=='exclude' and is_secret_path(rel):continue
        e=node(st)
        if e['type']=='file':
            h=hashlib.sha256();head=b''
            with scanner.open_source(cfg.agent_root/rel) as stream:
                before=os.fstat(stream.fileno())
                for chunk in iter(lambda:stream.read(CHUNK),b''):
                    tick();h.update(chunk)
                    if not head:head=chunk[:16]
                if identity(before)!=identity(os.fstat(stream.fileno())) or identity(before)!=identity(st):raise BackupError('restore_stale')
            e['sha256']=h.hexdigest();e['sqlite']=head==b'SQLite format 3\0'
        entries[rel]=e
    return dict(root=root_id(cfg.agent_root),entries=entries)


@contextmanager
def parent_fd(root,rel,expected_root,parents=None):
    relative_name(rel)
    if forbidden(Path(root)/rel) and private_origin(Path(root)/rel) is None:raise BackupError('unsafe_path')
    with open_directory(root) as start:
        if [os.fstat(start).st_dev,os.fstat(start).st_ino]!=expected_root:raise BackupError('restore_stale')
        fd=os.dup(start)
        try:
            prefix=[]
            for part in Path(rel).parts[:-1]:
                prefix.append(part)
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd);fd=child
                if parents is not None and [os.fstat(fd).st_dev,os.fstat(fd).st_ino]!=parents.get('/'.join(prefix)):
                    raise BackupError('restore_stale')
            if os.fstat(fd).st_dev!=expected_root[0]:raise BackupError('restore_mount')
            yield fd,Path(rel).name
        finally:os.close(fd)


def actual(root,rel,expected_root,tick=lambda:None):
    with parent_fd(root,rel,expected_root) as (fd,name):
        try:st=os.stat(name,dir_fd=fd,follow_symlinks=False)
        except FileNotFoundError:return None
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):raise BackupError('unsafe_path')
        result=node(st)
        if stat.S_ISREG(st.st_mode):
            leaf=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            with os.fdopen(leaf,'rb') as stream:
                if identity(st)!=identity(os.fstat(stream.fileno())):raise BackupError('restore_stale')
                h=hashlib.sha256()
                for chunk in iter(lambda:stream.read(CHUNK),b''):tick();h.update(chunk)
                if identity(st)!=identity(os.fstat(stream.fileno())):raise BackupError('restore_stale')
                result['sha256']=h.hexdigest()
        return result


def same(a,b,metadata=False):
    if a is None or b is None:return a is b
    keys=['type','dev','ino']
    if a['type']=='file':keys+=['size','sha256']
    if metadata:keys+=['mode','mtime_ns']
    return all(a.get(k)==b.get(k) for k in keys)


def noreplace(src_fd,src,dst_fd,dst):
    """No unsafe fallback on filesystems without Linux RENAME_NOREPLACE."""
    libc=ctypes.CDLL(None,use_errno=True)
    call=getattr(libc,'renameat2',None)
    if call is None:raise BackupError('restore_atomic')
    call.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    call.restype=ctypes.c_int
    if call(src_fd,os.fsencode(src),dst_fd,os.fsencode(dst),1):
        err=ctypes.get_errno()
        if err in (errno.ENOSYS,errno.EINVAL,errno.EOPNOTSUPP):raise BackupError('restore_atomic')
        if err==errno.EXDEV:raise BackupError('restore_mount')
        if err==errno.EEXIST:raise BackupError('restore_stale')
        raise OSError(err,os.strerror(err))
    os.fsync(src_fd);os.fsync(dst_fd)


def processes(target,limit_seconds=1.5):
    """Advisory PIDs only. Never reads argv, environment, or signals another process."""
    found=set();complete=not (os.environ.get('PTM_CONTAINER')=='1' or Path('/.dockerenv').exists());deadline=time.monotonic()+limit_seconds
    try:paths=Path('/proc').iterdir()
    except OSError:return dict(pids=[],complete=False)
    for directory in paths:
        if time.monotonic()>deadline:complete=False;break
        if not directory.name.isdecimal() or int(directory.name)==os.getpid():continue
        try:
            candidates=(directory/'fd').iterdir()
            try:candidates=chain((directory/'cwd',),candidates)
            except FileNotFoundError:continue
            for path in candidates:
                if time.monotonic()>deadline:complete=False;break
                try:value=os.readlink(path)
                except FileNotFoundError:continue
                if value.startswith('/') and inside(Path(value.removesuffix(' (deleted)')),target):
                    found.add(int(directory.name));break
        except FileNotFoundError:continue
        except PermissionError:complete=False
    return dict(pids=sorted(found),complete=complete)


def remove_private_tree(path,expected_id):
    """Only a known owned workspace. Anchored unlink, no symlinks/mount traversal."""
    with open_directory(path) as root:
        if [os.fstat(root).st_dev,os.fstat(root).st_ino]!=expected_id:raise BackupError('restore_workspace')
        def walk(fd):
            for name in os.listdir(fd):
                st=os.stat(name,dir_fd=fd,follow_symlinks=False)
                if stat.S_ISDIR(st.st_mode):
                    if st.st_dev!=expected_id[0]:raise BackupError('restore_mount')
                    child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                    try:os.fchmod(child,0o700);walk(child)
                    finally:os.close(child)
                    os.rmdir(name,dir_fd=fd)
                elif stat.S_ISREG(st.st_mode):os.unlink(name,dir_fd=fd)
                else:raise BackupError('unsafe_path')
            os.fsync(fd)
        walk(root)
    with open_directory(path.parent) as parent:
        st=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        if [st.st_dev,st.st_ino]!=expected_id:raise BackupError('restore_workspace')
        os.rmdir(path.name,dir_fd=parent);os.fsync(parent)
