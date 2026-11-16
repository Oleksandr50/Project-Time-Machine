"""Explicit, isolated configuration. No production paths or implicit project registration."""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import json
import os

CODE_ROOT = Path(__file__).resolve().parents[1]
LOOPBACK_NETWORKS=('127.0.0.0/8','::1/128')
PRIVATE_NETWORKS=('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','100.64.0.0/10','169.254.0.0/16','fc00::/7','fe80::/10')
DEFAULT_EXCLUSIONS = ('.git', '.venv', 'venv', 'node_modules', '__pycache__',
                      '.pytest_cache', '.mypy_cache', '.ruff_cache', '.cache',
                      'site-packages', 'dist', 'build', 'backups', 'backup', 'archives')


@dataclass(frozen=True)
class Settings:
    app_root: Path = CODE_ROOT
    config_dir: Path = CODE_ROOT / 'runtime/config'
    data_dir: Path = CODE_ROOT / 'runtime/state'
    backups_dir: Path = CODE_ROOT / 'runtime/backups'
    reports_dir: Path = CODE_ROOT / 'runtime/reports'
    metadata_dir: Path = CODE_ROOT / 'runtime/snapshot-metadata'
    content_dir: Path = CODE_ROOT / 'runtime/content'
    logs_dir: Path = CODE_ROOT / 'runtime/logs'
    temp_dir: Path = CODE_ROOT / 'runtime/tmp'
    migrations_dir: Path = CODE_ROOT / 'runtime/migration-backups'
    db_path: Path = CODE_ROOT / 'runtime/state/unselected.sqlite'
    # Legacy Python attribute kept for service compatibility, never populated implicitly.
    agent_root: Path | None = None
    project_id: int | None = None
    allowed_roots: tuple[Path, ...] = ()
    protected_roots: tuple[Path, ...] = ()
    archive_roots: tuple[Path, ...] = ()  # explicit read-only locations for imported archives
    exclusion_rules: tuple[str, ...] = DEFAULT_EXCLUSIONS
    scan_settings: dict = field(default_factory=lambda: {'python_analysis': True})
    management_networks: tuple[str, ...] | None = None
    trusted_hosts: tuple[str, ...] = ('localhost','127.0.0.1','::1')
    trusted_proxies: tuple[str, ...] = ()
    session_idle_seconds: int = 1800
    session_absolute_seconds: int = 43200
    login_attempt_limit: int = 5
    login_window_seconds: int = 300
    require_https_remote: bool = True
    lan_access: bool = True  # Direct access through the server's assigned interface addresses.
    remote_setup: bool = True  # Initial network setup requires the owner's one-time code.
    secret_file_names: tuple[str, ...] = ('.env', '.env.local', '.env.dev', '.env.prod',
        '.env.production', 'credentials.json', 'token.json', 'client_secret.json', 'service_account.json')
    secret_path_substrings: tuple[str, ...] = ('secret', 'secrets', 'credential', 'credentials', 'token', 'private', 'key')
    max_hash_bytes_general: int = 30 * 1024 * 1024
    backup_reserve_bytes: int = 64 * 1024 * 1024
    max_parallel_jobs: int = 2
    job_poll_seconds: int = 2
    encryption_keys: dict = field(default_factory=dict)  # key ID -> external 0600 file, never key bytes

    def __post_init__(self):
        if self.management_networks is None:
            object.__setattr__(self,'management_networks',('0.0.0.0/0','::/0') if self.lan_access else LOOPBACK_NETWORKS)
        # Resources belong to the imported release, never to a persisted installation
        # prefix or the release that happened to be active when JSON was written.
        legacy=Path(self.app_root)
        if not legacy.is_absolute():raise ValueError('app_root: absolute path required')
        if legacy!=CODE_ROOT:
            object.__setattr__(self,'protected_roots',tuple(dict.fromkeys((*self.protected_roots,legacy))))
        object.__setattr__(self,'app_root',CODE_ROOT)

    @property
    def static_dir(self):return self.app_root/'app/static'

    @property
    def templates_dir(self):return self.app_root/'app/templates'

    @property
    def locales_dir(self):return self.app_root/'app/locales'

    @property
    def storage_roots(self):
        return (CODE_ROOT, self.app_root, self.config_dir, self.data_dir, self.backups_dir,
                self.reports_dir, self.metadata_dir, self.content_dir, self.logs_dir, self.temp_dir,
                self.migrations_dir, *self.protected_roots, *self.archive_roots,
                *(Path(p) for p in self.encryption_keys.values()))


def load_settings():
    filename = os.environ.get('PTM_CONFIG')
    if not filename:
        return Settings()
    value = json.loads(Path(filename).read_text(encoding='utf-8'))
    paths = {'app_root','config_dir','data_dir','backups_dir','reports_dir','content_dir',
             'logs_dir','temp_dir','migrations_dir','db_path','metadata_dir'}
    path_lists = {'allowed_roots','protected_roots','archive_roots'}
    for key in paths & value.keys():
        p = Path(value[key]).expanduser()
        if not p.is_absolute(): raise ValueError(f'{key}: absolute path required')
        value[key] = p
    for key in path_lists & value.keys():
        value[key] = tuple(Path(p) for p in value[key])
        if any(not p.is_absolute() for p in value[key]): raise ValueError(f'{key}: absolute paths required')
    for key in ('exclusion_rules','management_networks','trusted_hosts','trusted_proxies'):
        if key in value: value[key] = tuple(value[key])
    # Projects are selected only from the registry, never from configuration.
    if 'agent_root' in value or 'project_id' in value: raise ValueError('Configure projects through the registry')
    import ipaddress
    for proxy in value.get('trusted_proxies',()):
        ipaddress.ip_address(proxy)  # exact IPs only, never '*'
    for key in ('session_idle_seconds','session_absolute_seconds','login_attempt_limit','login_window_seconds'):
        if key in value and (type(value[key]) is not int or value[key]<=0):raise ValueError(key+': positive integer required')
    for key in ('require_https_remote','lan_access','remote_setup'):
        if key in value and type(value[key]) is not bool:raise ValueError(key+': boolean required')
    for key in ('backup_reserve_bytes','max_parallel_jobs','job_poll_seconds'):
        if key in value and (type(value[key]) is not int or value[key]<1):raise ValueError(key+': positive integer required')
    if value.get('max_parallel_jobs',2)>8:raise ValueError('max_parallel_jobs: maximum 8')
    if 'encryption_keys' in value:
        import re
        if not isinstance(value['encryption_keys'],dict) or any(k=='plain' or not re.fullmatch(r'[A-Za-z0-9_-]{1,40}',k) or not Path(p).is_absolute() for k,p in value['encryption_keys'].items()):raise ValueError('Invalid encryption_keys')
    return Settings(**value)


base_settings = load_settings()


class ProjectSettings:
    def __getattr__(self, name):
        from .projects import current_settings
        return getattr(current_settings.get(), name)


settings = ProjectSettings()
