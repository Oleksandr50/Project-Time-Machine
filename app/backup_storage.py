"""Private atomic storage and streaming AES-256-GCM. Sources are never written."""
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
import hashlib
import os
import re
import shutil
import stat
import tempfile
from .filesystem import open_directory, inside
from . import projects

CHUNK = 1024 * 1024
MAGIC = b'PTMGCM1\0'


class BackupError(ValueError):
    """Only a fixed public error code may cross the HTTP/job boundary."""
    def __init__(self, code):
        self.code = code
        super().__init__('engine.' + code)


def relative_name(value):
    if not isinstance(value, str) or not value or len(value)>1024 or '\\' in value or ':' in value or '\0' in value:
        raise BackupError('unsafe_path')
    p=PurePosixPath(value)
    if p.is_absolute() or not p.parts or p.as_posix()!=value or any(x in ('.','..') or x.endswith((' ','.')) or
        re.fullmatch(r'(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?',x) or
        any(ord(c)<32 for c in x) for x in p.parts):
        raise BackupError('unsafe_path')
    return value


def private_dir(path):
    path=Path(path)
    # Create each component through its parent FD, never through a swapped symlink.
    if not path.is_absolute() or '..' in path.parts:raise BackupError('unsafe_path')
    fd=os.open(path.anchor,os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            try:os.mkdir(part,mode=0o700,dir_fd=fd)
            except FileExistsError:pass
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
    finally:os.close(fd)
    with open_directory(path) as fd:
        st=os.fstat(fd)
        if st.st_uid!=os.geteuid() or st.st_mode & 0o077:
            raise BackupError('storage_permissions')
    return path


def fsync_dir(path):
    with open_directory(path) as fd:os.fsync(fd)


@contextmanager
def read_private(path):
    p=Path(path)
    with open_directory(p.parent) as parent:
        fd=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_mode&0o077 or st.st_uid!=os.geteuid():raise BackupError('storage_permissions')
            with os.fdopen(fd,'rb',closefd=False) as stream:yield stream
        finally:os.close(fd)


def ensure_space(path, required):
    cfg=projects.base_settings
    if shutil.disk_usage(path).free < required + cfg.backup_reserve_bytes:
        raise BackupError('space')


def digest_stream(stream, tick=lambda:None):
    h=hashlib.sha256();size=0
    for chunk in iter(lambda:stream.read(CHUNK),b''):
        tick();h.update(chunk);size+=len(chunk)
    return h.hexdigest(),size


def digest_file(path,tick=lambda:None):
    with read_private(path) as stream:return digest_stream(stream,tick)[0]


@contextmanager
def project_lock(project_id,restore_id=None):
    """Shared protocol for backup, analysis, verify, retention and future restore."""
    if os.name!='posix':raise BackupError('platform')
    root=private_dir(projects.base_settings.data_dir/'operation-locks')
    path=root/f'project-{int(project_id)}.lock'
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    import fcntl
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise BackupError('busy')
        from .restore_state import ensure_clear
        ensure_clear(project_id,restore_id)
        yield
    finally:os.close(fd)


@contextmanager
def capacity():
    if os.name!='posix':raise BackupError('platform')
    root=private_dir(projects.base_settings.data_dir/'operation-locks')
    import fcntl
    chosen=None
    try:
        for n in range(projects.base_settings.max_parallel_jobs):
            fd=os.open(root/f'slot-{n}.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);chosen=fd;break
            except BlockingIOError:os.close(fd)
        if chosen is None:raise BackupError('busy')
        yield
    finally:
        if chosen is not None:os.close(chosen)


def load_key(key_id,cfg):
    if not key_id:return None
    value=projects.base_settings.encryption_keys.get(key_id)
    if not value:raise BackupError('key_missing')
    path=Path(value)
    # Config may hold only a path, and a key may never share archive/content/temp/source trees.
    if any(inside(path,Path(root).resolve()) for root in (cfg.agent_root,cfg.backups_dir,cfg.content_dir,cfg.temp_dir)):
        raise BackupError('key_location')
    try:
        with read_private(path) as stream:key=stream.read(33)
    except FileNotFoundError:raise BackupError('key_missing') from None
    if len(key)!=32:raise BackupError('key_invalid')
    return key


def encrypt(source,dest,key,aad,tick=lambda:None):
    from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
    nonce=os.urandom(12)
    ctx=Cipher(algorithms.AES(key),modes.GCM(nonce)).encryptor()
    ctx.authenticate_additional_data(aad)
    dest.write(MAGIC+nonce)
    for chunk in iter(lambda:source.read(CHUNK),b''):
        tick();dest.write(ctx.update(chunk))
    dest.write(ctx.finalize());dest.write(ctx.tag)


def consume(source,stored_size,key,aad,expected_digest,expected_size,tick=lambda:None,sink=None):
    """Validate before publication. Decrypted bytes only go to a private staging sink."""
    h=hashlib.sha256();size=0
    def output(chunk):
        nonlocal size
        size+=len(chunk)
        if size>expected_size:raise BackupError('corrupt')
        h.update(chunk)
        if sink is not None:sink.write(chunk)
    try:
        if key is None:
            if stored_size!=expected_size:raise BackupError('corrupt')
            remaining=stored_size
            while remaining:
                tick();chunk=source.read(min(CHUNK,remaining))
                if not chunk:raise BackupError('corrupt')
                remaining-=len(chunk);output(chunk)
        else:
            from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
            if stored_size!=expected_size+36 or source.read(8)!=MAGIC:raise BackupError('corrupt')
            nonce=source.read(12)
            if len(nonce)!=12:raise BackupError('corrupt')
            ctx=Cipher(algorithms.AES(key),modes.GCM(nonce)).decryptor();ctx.authenticate_additional_data(aad)
            remaining=stored_size-36
            while remaining:
                tick();chunk=source.read(min(CHUNK,remaining))
                if not chunk:raise BackupError('corrupt')
                remaining-=len(chunk);output(ctx.update(chunk))
            tag=source.read(16)
            if len(tag)!=16:raise BackupError('corrupt')
            output(ctx.finalize_with_tag(tag))
        if source.read(1) or size!=expected_size or h.hexdigest()!=expected_digest:raise BackupError('corrupt')
    except BackupError:raise
    except Exception as exc:
        from cryptography.exceptions import InvalidTag
        if isinstance(exc,(InvalidTag,ValueError)):raise BackupError('corrupt') from None
        raise


def object_aad(pid,key_id,digest):
    return f'PTM1:object:{pid}:{key_id}:{digest}'.encode('ascii')


class ObjectStore:
    def __init__(self,cfg,key_id='',tick=lambda:None):
        if key_id and (key_id=='plain' or not re.fullmatch('[A-Za-z0-9_-]{1,40}',key_id)):raise BackupError('policy')
        self.cfg=cfg;self.key_id=key_id;self.key=load_key(key_id,cfg);self.tick=tick
        self.root=private_dir(cfg.content_dir)
        self.namespace=f'projects/{cfg.project_id}/{key_id or "plain"}'

    def object_path(self,digest):
        if not re.fullmatch('[0-9a-f]{64}',digest):raise BackupError('corrupt')
        return self.root/self.namespace/digest[:2]/digest

    def verify(self,record):
        path=self.object_path(record['sha256'])
        with read_private(path) as stream:
            consume(stream,os.fstat(stream.fileno()).st_size,self.key,
                    object_aad(self.cfg.project_id,self.key_id,record['sha256']),
                    record['sha256'],record['size'],self.tick)

    def put(self,source,digest,size):
        path=self.object_path(digest)
        private_dir(path.parent)
        record={'sha256':digest,'size':size}
        if path.exists():
            self.verify(record)
        else:
            ensure_space(path.parent,size+36)
            fd,temp=tempfile.mkstemp(prefix='.pending-',dir=path.parent)
            try:
                with os.fdopen(fd,'wb') as out:
                    if self.key:encrypt(source,out,self.key,object_aad(self.cfg.project_id,self.key_id,digest),self.tick)
                    else:
                        for chunk in iter(lambda:source.read(CHUNK),b''):self.tick();out.write(chunk)
                    out.flush();os.fsync(out.fileno())
                # Atomic no-clobber publication. Project lock serializes this namespace.
                os.link(temp,path,follow_symlinks=False);fsync_dir(path.parent)
            finally:Path(temp).unlink(missing_ok=True)
            self.verify(record)
        return {'storage_key':path.relative_to(self.root).as_posix(),'stored_size':path.stat().st_size}
