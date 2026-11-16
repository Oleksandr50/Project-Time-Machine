"""Owner-only one-time code for network administrator creation; never in URLs or logs."""
import hmac
import os
from pathlib import Path
import secrets
import stat
from .filesystem import open_directory

NAME='setup-code'

def directory(cfg):return Path(cfg.data_dir)/'.bootstrap'

def path(cfg):return directory(cfg)/NAME


def read(cfg):
    with open_directory(directory(cfg)) as parent:
        fd=os.open(NAME,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077 or info.st_nlink!=1:raise ValueError('Unsafe setup-code file permissions')
            value=os.read(fd,128).decode('ascii').strip()
            if len(value)!=64 or any(c not in '0123456789abcdef' for c in value):raise ValueError('Invalid setup-code file')
            return value
        finally:os.close(fd)


def ensure(cfg):
    from .maintenance import private_mkdir
    private_mkdir(directory(cfg),exist_ok=True)
    with open_directory(directory(cfg)) as parent:
        try:fd=os.open(NAME,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        except FileExistsError:read(cfg);return
        try:
            value=(secrets.token_hex(32)+'\n').encode()
            if os.write(fd,value)!=len(value):raise OSError('Setup-code write incomplete')
            os.fsync(fd);os.fsync(parent)
        finally:os.close(fd)


def valid(cfg,submitted):
    if not isinstance(submitted,str) or len(submitted.strip())!=64:return False
    try:return hmac.compare_digest(read(cfg),submitted.strip())
    except (OSError,ValueError,UnicodeError):return False


def consume(cfg):
    try:
        with open_directory(directory(cfg)) as parent:
            os.unlink(NAME,dir_fd=parent);os.fsync(parent)
    except FileNotFoundError:pass
