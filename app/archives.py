"""Availability is not integrity or recoverability. Never changes legacy records."""
from contextlib import contextmanager
from pathlib import Path
import os
import stat
from .config import settings
from .filesystem import inside, open_directory, absolute


@contextmanager
def open_archive(path):
    p=absolute(path)
    if not any(inside(p,Path(root).resolve()) for root in (settings.backups_dir,*settings.archive_roots)):
        raise ValueError('Архив вне настроенных каталогов хранения')
    with open_directory(p.parent) as parent:
        fd=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode): raise ValueError('Архив не является обычным файлом')
            with os.fdopen(fd,'rb',closefd=False) as stream: yield stream
        finally: os.close(fd)


def availability(path):
    try:
        with open_archive(path): pass
        return 'Available'
    except FileNotFoundError: return 'Missing'
    except (ValueError,OSError):
        # Missing is reported even for an obsolete absolute legacy location.
        try:
            if not Path(path).exists(): return 'Missing'
        except OSError: pass
        return 'Unavailable'
