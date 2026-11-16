"""Allowlisted read-only access. Reject symlinks at every opened component."""
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
import os
import stat

SYSTEM = ('/etc','/proc','/sys','/dev','/boot','/run','/var','/usr','/bin','/sbin','/lib','/lib64')
CREDENTIALS = {'.ssh','.aws','.gnupg','.codex'}
PRIVATE_FDS=ContextVar('private_workspace_fds',default={})


def private_origin(path):
    parts=Path(path).parts
    if parts[:4]!=('/','proc','self','fd') or len(parts)<5:return None
    item=PRIVATE_FDS.get().get(parts[4])
    return (item[1].joinpath(*parts[5:])) if item else None


@contextmanager
def private_fd(fd,canonical,expected):
    """Internal capability; HTTP paths can never manufacture an entry in this context."""
    owned=os.dup(fd);st=os.fstat(owned)
    if [st.st_dev,st.st_ino]!=expected or st.st_uid!=os.geteuid() or st.st_mode&0o077:
        os.close(owned);raise ValueError('engine.restore_workspace')
    token=PRIVATE_FDS.set({**PRIVATE_FDS.get(),str(owned):(owned,Path(canonical))})
    try:yield Path('/proc/self/fd')/str(owned)
    finally:PRIVATE_FDS.reset(token);os.close(owned)


def inside(path, parent):
    return path == parent or parent in path.parents


def absolute(value):
    value=str(value)
    p=Path(value)
    if not p.is_absolute() or '\x00' in value or '..' in p.parts or '\\' in value:
        raise ValueError('Укажите абсолютный путь без traversal')
    return p


def forbidden(path):
    return path in (Path('/'),Path('/home'),Path('/tmp')) or bool(set(path.parts)&CREDENTIALS) or any(inside(path,Path(x)) for x in SYSTEM)


@contextmanager
def open_directory(path):
    path=absolute(path)
    # POSIX dir_fd anchors every path component; no check-then-follow-symlink open.
    if os.name != 'nt':
        origin=private_origin(path)
        if origin is not None:
            fd=os.dup(PRIVATE_FDS.get()[path.parts[4]][0]);parts=path.parts[5:]
        else:
            fd=os.open(path.anchor,os.O_RDONLY|os.O_DIRECTORY);parts=path.parts[1:]
        try:
            for part in parts:
                new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd);fd=new
            yield fd
        finally: os.close(fd)
    else:
        # Windows fail closed: native reparse-safe handles are a later platform task.
        raise ValueError('Безопасный доступ Windows требует проверки reparse points; пока используйте Linux')


def validate_allowed_root(value,cfg):
    """Authorize a parent such as HOME, without authorizing protected children."""
    p=absolute(value);resolved=p.resolve(strict=True)
    if forbidden(resolved):raise ValueError('System or credential directory is not an allowed root')
    if any(inside(resolved,Path(root).resolve()) for root in cfg.storage_roots):
        raise ValueError('Allowed root is inside application storage')
    try:
        with open_directory(p):pass
    except OSError as exc:raise ValueError('Directory is inaccessible or contains a symlink') from exc
    if not os.access(p,os.R_OK|os.X_OK):raise ValueError('Directory is not readable')
    return resolved


def validate_project(value,cfg):
    p=absolute(value)
    origin=private_origin(p)
    if origin is not None:
        # Only an already pinned, private application staging inode is represented here.
        resolved=origin
    else:resolved=p.resolve(strict=True)
    if forbidden(resolved): raise ValueError('Системный каталог или каталог учётных данных запрещён')
    roots=[absolute(r) for r in cfg.allowed_roots]
    # Do not turn a swapped symlink root into a new authorization, and an offline
    # unrelated mount must not prevent access to an existing approved project.
    if not any(inside(origin or p,r) and inside(resolved,r) for r in roots): raise ValueError('Путь вне разрешённых корней')
    for root in cfg.storage_roots:
        protected=Path(root).resolve()
        if inside(resolved,protected) or inside(protected,resolved):
            raise ValueError('Проект пересекается с хранилищем или кодом приложения')
    try:
        with open_directory(p): pass
    except OSError as exc: raise ValueError('Каталог недоступен или содержит символическую ссылку') from exc
    return p if origin is not None else resolved


@contextmanager
def open_project_file(root, relative, cfg):
    root=validate_project(root,cfg)
    rel=Path(relative)
    if rel.is_absolute() or not rel.parts or '..' in rel.parts or '\\' in str(relative) or '\x00' in str(relative):
        raise ValueError('Недопустимый относительный путь')
    target=root/rel
    if forbidden(target) and private_origin(target) is None: raise ValueError('Недопустимый путь')
    if any(inside(target,Path(p).resolve()) for p in cfg.storage_roots):
        raise ValueError('Хранилище приложения недоступно как исходный код')
    with open_directory(root) as root_fd:
        fd=os.dup(root_fd)
        try:
            for part in rel.parts[:-1]:
                new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd);fd=new
            file_fd=os.open(rel.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            try:
                if not stat.S_ISREG(os.fstat(file_fd).st_mode): raise ValueError('Разрешены только обычные файлы')
                with os.fdopen(file_fd,'rb',closefd=False) as stream: yield stream
            finally: os.close(file_fd)
        finally: os.close(fd)
