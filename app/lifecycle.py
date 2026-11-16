"""Application/maintenance exclusion, independent of project locks and credentials."""
from contextlib import contextmanager
from pathlib import Path
import os


@contextmanager
def guard(data_dir,exclusive=False):
    if os.name!='posix':raise ValueError('Linux or WSL2 is required for the file engine')
    import fcntl
    import json
    from .backup_storage import private_dir
    root=private_dir(Path(data_dir)/'.maintenance')
    fd=os.open(root/'maintenance.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        try:fcntl.flock(fd,(fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Application or maintenance is running; stop this instance first') from None
        prefix=Path(data_dir).parent
        if not exclusive and (prefix/'installation.json').exists() and (prefix/'update-journal.json').exists():
            if json.loads((prefix/'update-journal.json').read_text()).get('phase')!='complete':
                raise ValueError('Interrupted update: explicit recovery is required before startup')
        settings_journal=prefix/'configuration-journal.json'
        if not exclusive and settings_journal.exists() and json.loads(settings_journal.read_text()).get('phase')!='complete':
            raise ValueError('Interrupted settings change: run setup.sh --recover')
        deployment=Path(data_dir)/'deployment-journal.json'
        if not exclusive and deployment.exists() and json.loads(deployment.read_text()).get('phase')!='complete':
            raise ValueError('Interrupted deployment: explicit recovery is required before startup')
        yield
    finally:os.close(fd)
