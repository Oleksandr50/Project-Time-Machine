"""Single exclusion policy and anchored read access for scan/log/DB/backup preparation."""
from pathlib import Path
from fnmatch import fnmatchcase
import os
import stat
from .config import settings
from .filesystem import validate_project, open_project_file, open_directory, inside

ARCHIVE_NAMES={'backups','backup','archives','archive'}
DEPENDENCIES={'.venv','venv','node_modules','site-packages'}
GENERATED={'__pycache__','.pytest_cache','.mypy_cache','.ruff_cache','.cache','dist','build'}


def category(rel):
    parts=set(Path(rel).parts[:-1])
    if parts & ARCHIVE_NAMES: return 'archived'
    if parts & DEPENDENCIES: return 'dependencies'
    if parts & GENERATED: return 'generated'
    return 'active'


def excluded(rel,cfg=None):
    cfg=cfg or settings
    path=Path(cfg.agent_root)/rel
    if any(inside(path.resolve(),Path(root).resolve()) for root in cfg.storage_roots): return True
    parts=Path(rel).parts
    prefixes=['/'.join(parts[:n]) for n in range(1,len(parts)+1)]
    return any(any(fnmatchcase(prefix,rule) for prefix in prefixes) or any(fnmatchcase(part,rule) for part in parts)
               for rule in cfg.exclusion_rules)


def iter_files(root, strict=False, include_dirs=False):
    root=validate_project(root,settings)
    from .restore_state import workspaces
    owned=workspaces(settings.project_id)
    def walk(fd, prefix=''):
        with os.scandir(fd) as entries:
            for entry in (entries if strict else sorted(entries,key=lambda e:e.name)):
                rel=prefix+entry.name
                if str(root/rel) in owned:continue
                if excluded(rel): continue
                if entry.is_symlink():
                    if strict:
                        from .backup_storage import BackupError
                        raise BackupError('unsafe_path')
                    continue
                if entry.is_dir(follow_symlinks=False):
                    try: child=os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                    except OSError:
                        if strict:raise
                        continue
                    if include_dirs:yield root/rel,entry.stat(follow_symlinks=False)
                    try: yield from walk(child,rel+'/')
                    finally: os.close(child)
                elif entry.is_file(follow_symlinks=False):
                    try:
                        with open_project_file(root,rel,settings) as stream:
                            st=os.fstat(stream.fileno())
                        yield root/rel,st
                    except (OSError,ValueError):
                        if strict:raise
                        continue
                elif strict:
                    from .backup_storage import BackupError
                    raise BackupError('unsupported_file')
    with open_directory(root) as fd:
        yield from walk(fd)


def open_source(path):
    path=Path(path)
    return open_project_file(settings.agent_root,path.relative_to(settings.agent_root),settings)


def read_text(path):
    with open_source(path) as stream:
        return stream.read().decode('utf-8',errors='replace')


def eligible_analysis(rel):
    kind=category(rel)
    return kind=='active' or settings.scan_settings.get('analyze_'+kind,False)
