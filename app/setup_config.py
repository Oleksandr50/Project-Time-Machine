"""Per-installation configuration; no migrations or implicit database creation."""
from contextlib import closing,contextmanager
from pathlib import Path
import copy
import fcntl
import http.client
import ipaddress
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import uuid
from . import installation as install
from .maintenance import atomic_json
from .filesystem import absolute,forbidden,inside,open_directory,validate_allowed_root


def user_path(value):
    value=str(value).strip()
    if value=='~':value=str(install.user_home())
    elif value.startswith('~/'):value=str(install.user_home()/value[2:])
    p=absolute(value)
    if any(c in str(p) for c in ('\n','\r')):raise ValueError('Control characters in path')
    return p


def settings_object(document):
    from .config import Settings
    value=copy.deepcopy(document)
    for key in ('app_root','config_dir','data_dir','backups_dir','reports_dir','metadata_dir','content_dir','logs_dir','temp_dir','migrations_dir','db_path'):
        if key in value:value[key]=Path(value[key])
    for key in ('allowed_roots','protected_roots','archive_roots'):
        if key in value:value[key]=tuple(Path(p) for p in value[key])
    return Settings(**value)


def load(prefix):
    prefix=install.prefix_path(prefix);info=install.layout(prefix)
    file=prefix/'config/settings.json'
    if file.is_symlink():raise ValueError('Settings file must not be a symlink')
    with open_directory(file.parent):pass
    document=json.loads(file.read_text(encoding='utf-8'))
    return info,document


def registry_rows(document,query,params=()):
    database=Path(document['data_dir'])/'projects.sqlite'
    if not database.exists():return []
    if database.is_symlink():raise ValueError('Unsafe registry path')
    with closing(sqlite3.connect(database.as_uri()+'?mode=ro',uri=True,timeout=5)) as c:
        c.execute('PRAGMA query_only=ON')
        return c.execute(query,params).fetchall()


def network_ready(document):
    try:return registry_rows(document,'SELECT setup_completed,network_enabled FROM auth_settings')==[(1,1)]
    except sqlite3.OperationalError:return False


def health_connection(info):
    host=ipaddress.ip_address(info.get('bind_address','127.0.0.1'))
    loopback='::1' if host.version==6 else '127.0.0.1'
    destination=loopback if host.is_unspecified else str(host)
    # Linux local route: bind the client to loopback even for a specific local LAN IP.
    # Health stays localhost-only; neither trusted hosts nor remote access are relaxed.
    connection=http.client.HTTPConnection(destination,info['port'],timeout=.3,source_address=(loopback,0))
    try:
        connection.request('GET','/healthz',headers={'Host':'[::1]' if host.version==6 else loopback})
        response=connection.getresponse()
        if response.status!=200:raise ValueError('Local health check rejected')
        return json.loads(response.read(4097))
    finally:connection.close()


def validate_storage(value,prefix,document,allow_missing=False):
    path=user_path(value)
    parent=path
    while not parent.exists():
        if parent==parent.parent:raise ValueError('Storage parent does not exist')
        parent=parent.parent
    with open_directory(parent):pass
    if not path.exists() and not allow_missing:raise ValueError('Backup directory does not exist; confirm creation first')
    if path.exists():
        with open_directory(path):pass
    if forbidden(path) or not os.access(parent,os.W_OK|os.X_OK):raise ValueError('Backup directory is forbidden or not writable')
    # A backup directory may be inside the installation, but never inside its code,
    # database/config/key stores, or another registered source project.
    protected=[Path(document[k]) for k in ('config_dir','data_dir','reports_dir','metadata_dir','content_dir','logs_dir','temp_dir','migrations_dir') if k in document]
    protected += [Path(prefix)/name for name in ('releases','bin','updates','keys')]
    protected += [Path(p) for p in document.get('encryption_keys',{}).values()]
    for root in protected:
        if inside(path,root) or inside(root,path):raise ValueError('Backup directory overlaps application storage')
    for _,project,_ in registry_rows(document,'SELECT id,path,backup_path FROM projects'):
        root=Path(project)
        if inside(path,root) or inside(root,path):raise ValueError('Backup directory overlaps a registered project')
    if shutil.disk_usage(parent).free<int(document.get('backup_reserve_bytes',64*1024*1024)):
        raise ValueError('Not enough free space for the configured backup reserve')
    return path


def validate(prefix,old_info,old_document,info,document,allow_create=False,check_port=True):
    info=copy.deepcopy(info);document=copy.deepcopy(document)
    # Only explicit setup controls are editable, never IDs, owner, state or key paths.
    for key in set(info)|set(old_info):
        if key not in ('port','bind_address','autostart_after_install','autostart_on_boot') and info.get(key)!=old_info.get(key):raise ValueError('Installation identity cannot be changed')
    for key in set(document)|set(old_document):
        if key not in ('allowed_roots','backups_dir','archive_roots') and document.get(key)!=old_document.get(key):raise ValueError('Unsupported settings change')
    host=ipaddress.ip_address(info.get('bind_address','127.0.0.1'))
    if '%' in str(host):raise ValueError('Scoped IPv6 addresses are not supported')
    info['bind_address']=str(host)
    port=info.get('port')
    if type(port) is not int or not 1024<=port<=65535:raise ValueError('Port must be between 1024 and 65535')
    for key in ('autostart_after_install','autostart_on_boot'):
        if type(info.get(key,False if key.endswith('boot') else True)) is not bool:raise ValueError('Invalid autostart setting')
    document['backups_dir']=str(validate_storage(document['backups_dir'],prefix,old_document,allow_create))
    cfg=settings_object(document)
    if not isinstance(document.get('allowed_roots'),list) or not document['allowed_roots']:raise ValueError('Keep at least one project root (normally HOME)')
    document['allowed_roots']=list(dict.fromkeys(str(validate_allowed_root(user_path(p),cfg)) for p in document['allowed_roots']))
    if document['backups_dir']!=old_document['backups_dir']:
        # Existing archive paths remain authorized, immutable historical records.
        roots=[*old_document.get('archive_roots',[]),old_document['backups_dir']]
        roots += [r[2] for r in registry_rows(old_document,'SELECT id,path,backup_path FROM projects') if r[2]]
        document['archive_roots']=list(dict.fromkeys(roots))
    else:document['archive_roots']=old_document.get('archive_roots',[])
    if check_port and (port!=old_info['port'] or str(host)!=old_info.get('bind_address','127.0.0.1')):
        try:
            with socket.socket(socket.AF_INET6 if host.version==6 else socket.AF_INET,socket.SOCK_STREAM) as sock:sock.bind((str(host),port))
        except OSError as exc:raise ValueError('Bind address unavailable or port occupied; no process was stopped') from exc
    return info,document


@contextmanager
def configuration_lock(prefix):
    fd=os.open(Path(prefix)/'.configuration.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Another settings operation is running') from None
        yield
    finally:os.close(fd)


def binding_plan(old_document,new_document):
    if old_document['backups_dir']==new_document['backups_dir']:return []
    return [dict(id=row[0],old=row[2],new=str(Path(new_document['backups_dir'])/'projects'/str(row[0])))
            for row in registry_rows(old_document,'SELECT id,path,backup_path FROM projects')]


def write_bindings(document,bindings,reverse=False):
    if not bindings:return
    database=Path(document['data_dir'])/'projects.sqlite'
    if not database.exists() or database.is_symlink():raise ValueError('Registry disappeared or changed')
    with closing(sqlite3.connect(database.as_uri()+'?mode=rw',uri=True,timeout=5)) as c:
        c.execute('PRAGMA foreign_keys=ON');c.execute('BEGIN IMMEDIATE')
        try:
            for row in bindings:
                source,target=(row['new'],row['old']) if reverse else (row['old'],row['new'])
                current=c.execute('SELECT backup_path FROM projects WHERE id=?',(row['id'],)).fetchone()
                if current is None or current[0] not in (source,target):raise ValueError('Project backup binding changed; refusing overwrite')
                c.execute('UPDATE projects SET backup_path=? WHERE id=?',(target,row['id']))
            if c.execute('PRAGMA foreign_key_check').fetchall():raise ValueError('Registry foreign-key violation')
            c.commit()
        except Exception:c.rollback();raise


def capture_registry(document,destination):
    database=Path(document['data_dir'])/'projects.sqlite'
    if not database.exists():return
    destination.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    with closing(sqlite3.connect(database.as_uri()+'?mode=ro',uri=True,timeout=5)) as source,closing(sqlite3.connect(destination)) as copy_db:
        source.backup(copy_db,pages=128)
        if copy_db.execute('PRAGMA integrity_check').fetchall()!=[('ok',)] or copy_db.execute('PRAGMA foreign_key_check').fetchall():raise ValueError('Registry checkpoint failed')
    destination.chmod(0o600)
    with destination.open('rb') as stream:os.fsync(stream.fileno())


def set_boot(prefix,enabled,enable_linger=False):
    if enabled:
        linger=subprocess.run(['loginctl','show-user',str(os.geteuid()),'-p','Linger','--value'],capture_output=True,text=True,check=True).stdout.strip()
        if linger!='yes':
            if not enable_linger:raise ValueError('Boot autostart requires explicit permission to enable user linger')
            subprocess.run(['loginctl','enable-linger',str(os.geteuid())],check=True)
        install.install_service(prefix)  # Unique owned user unit; never a system/global unit.
    elif install.service_owned(prefix):
        subprocess.run(['systemctl','--user','disable',install.unit_path(prefix).name],check=True)
    # Do not disable linger: other applications may need this user's manager.


def apply(prefix,expected_info,expected_document,info,document,allow_create=False,enable_linger=False):
    prefix=install.prefix_path(prefix)
    if not (prefix/'current/app/setup_config.py').is_file():raise ValueError('Update this installation to 0.7.1 before changing settings')
    with configuration_lock(prefix):
        old_info,old_document=load(prefix)
        if (old_info,old_document)!=(expected_info,expected_document):raise ValueError('Settings changed concurrently; reopen setup')
        if install.pending(prefix):raise ValueError('Recover the pending update/settings operation first')
        if (info,document)==(old_info,old_document):return
        info,document=validate(prefix,old_info,old_document,info,document,allow_create)
        if (info,document)==(old_info,old_document):return
        was_running=bool(install.process(prefix) or install.service_active(prefix))
        install.stop(prefix)
        from .lifecycle import guard
        journal_file=prefix/'configuration-journal.json'
        try:
            with guard(Path(old_document['data_dir']),exclusive=True):
                pending=registry_rows(old_document,"SELECT id FROM restore_operations WHERE state IN ('queued','preparing','applying','interrupted','undoing') LIMIT 1")
                if pending:raise ValueError('Finish or recover the pending restore before changing settings')
                path=Path(document['backups_dir'])
                if not path.exists():
                    from .maintenance import private_mkdir
                    private_mkdir(path)
                # Recheck paths after stopping the instance, without changing project permissions.
                info,document=validate(prefix,old_info,old_document,info,document,False)
                bindings=binding_plan(old_document,document)
                point=prefix/'updates'/('settings-'+uuid.uuid4().hex);point.mkdir(mode=0o700)
                if bindings:capture_registry(old_document,point/'registry.sqlite')
                boot_requested=info.get('autostart_on_boot',False)
                info['autostart_on_boot']=old_info.get('autostart_on_boot',False)
                journal=dict(phase='prepared',old_info=old_info,old_document=old_document,new_info=info,new_document=document,bindings=bindings,checkpoint=str(point))
                atomic_json(point/'configuration.json',journal);atomic_json(journal_file,journal)
                write_bindings(old_document,bindings)
                atomic_json(prefix/'config/settings.json',document);atomic_json(prefix/'installation.json',info)
                journal['phase']='complete';atomic_json(journal_file,journal)
            if boot_requested!=old_info.get('autostart_on_boot',False):
                set_boot(prefix,boot_requested,enable_linger)
                info['autostart_on_boot']=boot_requested;atomic_json(prefix/'installation.json',info)
        finally:
            # Pending journal prevents a partial state from starting. Boot failures leave
            # the saved configuration and old boot flag, with a visible error for retry.
            if was_running and not install.pending(prefix):install.start(prefix)


def recover(prefix):
    prefix=install.prefix_path(prefix)
    with configuration_lock(prefix):
        file=prefix/'configuration-journal.json';journal=json.loads(file.read_text())
        if journal['phase']=='complete':raise ValueError('There is no interrupted settings operation')
        current_info,current_document=load(prefix)
        if current_info not in (journal['old_info'],journal['new_info']) or current_document not in (journal['old_document'],journal['new_document']):raise ValueError('Settings changed outside setup; refusing overwrite')
        install.stop(prefix)
        from .lifecycle import guard
        with guard(Path(journal['old_document']['data_dir']),exclusive=True):
            write_bindings(journal['old_document'],journal['bindings'],reverse=True)
            atomic_json(prefix/'config/settings.json',journal['old_document']);atomic_json(prefix/'installation.json',journal['old_info'])
            journal.update(phase='complete',recovered=True);atomic_json(file,journal)
