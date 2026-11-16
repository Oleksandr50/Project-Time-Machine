"""Per-user Linux/WSL installation. Only this marked prefix and its own process are managed."""
from pathlib import Path
import hashlib
import json
import os
import shlex
import signal
import subprocess
import sys
import time
import uuid
from .maintenance import atomic_json


def user_home():
    import pwd
    return Path(pwd.getpwuid(os.geteuid()).pw_dir).resolve(strict=True)


def default_prefix():
    return user_home()/'ProjectTimeMachine'


def base_interpreter():
    return os.path.realpath(getattr(sys,'_base_executable',sys.executable))


def fresh_configuration(prefix,projects_root=None):
    prefix=Path(prefix).resolve()
    value={k:str(prefix/v) for k,v in dict(config_dir='config',data_dir='state',backups_dir='backups',metadata_dir='metadata',reports_dir='reports',content_dir='content',logs_dir='logs',temp_dir='tmp',migrations_dir='migration-backups').items()}
    value.update(db_path=str(prefix/'state/unselected.sqlite'),
                 allowed_roots=[str(Path(projects_root).expanduser().resolve(strict=True) if projects_root else user_home())],
                 protected_roots=[str(prefix),*[str(prefix/name) for name in ('releases','bin','updates','keys')]])
    return value


DEFAULT_BIND='0.0.0.0'


def fresh_installation_info(prefix,port):
    return dict(format_version=1,id=uuid.uuid4().hex,prefix=str(Path(prefix).resolve()),port=port,
                owner_uid=os.geteuid(),bind_address=DEFAULT_BIND,autostart_after_install=True,autostart_on_boot=False)


def choose_port(requested=None):
    import socket
    candidates=[requested] if requested is not None else list(range(13011,13032))
    for port in candidates:
        if not 1024<=port<=65535:raise ValueError('Choose a port between 1024 and 65535')
        try:
            with socket.socket() as sock:sock.bind(('127.0.0.1',port))
            return port
        except OSError:
            if requested is not None:raise ValueError('Port is occupied; choose another --port. No process was stopped') from None
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]


def _pidfd_syscall(number,*args):
    # Some standalone Python builds omit the wrappers even on a supported kernel.
    # Linux x86_64/aarch64 use these asm-generic syscall numbers; other ABIs require
    # the standard-library wrappers rather than guessing their syscall table.
    import ctypes,platform
    if sys.platform!='linux' or platform.machine() not in ('x86_64','aarch64'):
        raise ValueError('Use a distribution Python with pidfd support on this architecture')
    libc=ctypes.CDLL(None,use_errno=True);libc.syscall.restype=ctypes.c_long
    result=libc.syscall(ctypes.c_long(number),*args)
    if result<0:
        error=ctypes.get_errno();raise OSError(error,os.strerror(error))
    return result


def pidfd_open(pid):
    native=getattr(os,'pidfd_open',None)
    return native(pid,0) if callable(native) else _pidfd_syscall(434,ctypes_int(pid),ctypes_int(0))


def ctypes_int(value):
    import ctypes
    return ctypes.c_int(value)


def pidfd_send_signal(fd,sig):
    native=getattr(signal,'pidfd_send_signal',None)
    if callable(native):return native(fd,sig)
    import ctypes
    return _pidfd_syscall(424,ctypes.c_int(fd),ctypes.c_int(sig),ctypes.c_void_p(),ctypes.c_uint(0))


def check_process_handles():
    try:fd=pidfd_open(os.getpid())
    except OSError:raise ValueError('Linux pidfd is unavailable; native process management cannot run safely') from None
    os.close(fd)


def prefix_path(value):
    p=Path(value).expanduser()
    if not p.is_absolute() or any(c in str(p) for c in ('\n','\r','\0')):raise ValueError('An absolute installation path is required')
    p=p.resolve()
    if p in (Path('/'),Path.home(),Path('/tmp'),Path('/home')):raise ValueError('Choose a dedicated installation directory')
    return p


def layout(prefix):
    prefix=prefix_path(prefix);data=json.loads((prefix/'installation.json').read_text())
    if data.get('format_version')!=1 or data.get('prefix')!=str(prefix) or data.get('owner_uid')!=os.geteuid():raise ValueError('Not an installation owned by this user')
    return data


def environment(prefix,release=None):
    info=layout(prefix);env=dict(os.environ)
    env.update(PTM_CONFIG=str(Path(prefix)/'config/settings.json'),PTM_PORT=str(info['port']),PTM_HOST=info.get('bind_address','127.0.0.1'),PTM_MANAGED_ID=info['id'],PYTHONDONTWRITEBYTECODE='1')
    env.pop('PYTHONHOME',None);env.pop('PYTHONPATH',None)
    return env


def process(prefix):
    info=layout(prefix);file=Path(prefix)/'process.json'
    if not file.exists():return None
    data=json.loads(file.read_text());pid=int(data['pid']);proc=Path('/proc')/str(pid)
    try:
        stat=(proc/'stat').read_text().split(') ',1)[1].split()
        if str(stat[19])!=str(data['start_time']):raise ValueError('PID identity mismatch; no signal sent')
        if stat[0] in ('Z','X','x'):return None
        env=(proc/'environ').read_bytes().split(b'\0')
        if ('PTM_MANAGED_ID='+info['id']).encode() not in env or ('PTM_CONFIG='+str(Path(prefix)/'config/settings.json')).encode() not in env:
            raise ValueError('PID identity mismatch; no signal sent')
        return pid
    except FileNotFoundError:return None
    except PermissionError:
        # A process can become a zombie between stat and environ. Never relax identity
        # checks for a live, unreadable process and never signal a recycled PID.
        try:fresh=(proc/'stat').read_text().split(') ',1)[1].split()
        except FileNotFoundError:return None
        if fresh[0] in ('Z','X','x') and str(fresh[19])==str(data['start_time']):return None
        raise ValueError('Cannot verify live process identity; no signal sent') from None


def unit_path(prefix):
    return Path.home()/'.config/systemd/user'/('ptm-'+layout(prefix)['id'][:12]+'.service')


def service_owned(prefix):
    p=unit_path(prefix)
    if not p.exists():return False
    if p.is_symlink() or '# PTM '+layout(prefix)['id'] not in p.read_text():raise ValueError('Service ownership mismatch')
    return True


def service_active(prefix):
    return service_owned(prefix) and subprocess.run(['systemctl','--user','is-active','--quiet',unit_path(prefix).name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0


def pending(prefix):
    p=Path(prefix)/'update-journal.json'
    if p.exists() and json.loads(p.read_text()).get('phase')!='complete':return True
    p=Path(prefix)/'configuration-journal.json'
    return p.exists() and json.loads(p.read_text()).get('phase')!='complete'


def run(prefix):
    if pending(prefix):raise ValueError('Interrupted update: run ptm recover-update first')
    target=(Path(prefix)/'current').resolve(strict=True)
    if not target.is_relative_to(Path(prefix)/'releases'):raise ValueError('Unsafe current release')
    os.chdir(target);os.execve(target/'venv/bin/python',[str(target/'venv/bin/python'),'-B','-m','app'],environment(prefix))


def startup_failure(prefix,reason,offset=0,service=False,since=None):
    """Bounded diagnostics from this attempt, with the existing secret masking."""
    from .redaction import redact
    log=Path(prefix)/'logs/server.log';detail=''
    if service:
        try:
            command=['journalctl','--user','-u',unit_path(prefix).name,'-n','60','--no-pager','--output=cat']
            if since:command+=['--since',since]
            result=subprocess.run(command,capture_output=True,text=True,timeout=5)
            detail=result.stdout[-16384:]
        except (OSError,subprocess.SubprocessError):pass
        location='user journal for '+unit_path(prefix).name
    else:
        location=str(log)
        try:
            with log.open('rb') as stream:
                stream.seek(0,os.SEEK_END);size=stream.tell()
                # Do not report stale failures from a previous invocation.
                stream.seek(max(offset if size>=offset else 0,size-16384))
                detail=stream.read(16384).decode('utf-8',errors='replace')
        except OSError:pass
    return str(reason)+'\nDiagnostics: '+location+('\n'+redact(detail).strip() if detail.strip() else '\nNo startup log output was captured.')


def start(prefix):
    from .setup_config import health_connection
    from datetime import datetime,timezone
    import http.client
    if pending(prefix):raise ValueError('Interrupted update: run ptm recover-update first')
    check_process_handles()
    if process(prefix):return
    info=layout(prefix);child=None;offset=0;service=service_owned(prefix)
    since=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    if service:
        try:subprocess.run(['systemctl','--user','start',unit_path(prefix).name],check=True)
        except subprocess.CalledProcessError as exc:
            raise ValueError(startup_failure(prefix,'User service failed to start (exit '+str(exc.returncode)+')',service=True,since=since)) from None
    else:
        target=(Path(prefix)/'current').resolve(strict=True)
        with (Path(prefix)/'logs/server.log').open('ab') as log:
            offset=log.tell()
            child=subprocess.Popen([str(target/'venv/bin/python'),'-B','-m','app'],cwd=target,env=environment(prefix),stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
        try:stat=(Path('/proc')/str(child.pid)/'stat').read_text().split(') ',1)[1].split()
        except FileNotFoundError:
            child.wait(timeout=3)
            raise ValueError(startup_failure(prefix,'Application exited with code '+str(child.returncode),offset)) from None
        atomic_json(Path(prefix)/'process.json',dict(pid=child.pid,start_time=stat[19]))
    last_error='No successful health response'
    for _ in range(100):
        if child and child.poll() is not None:
            raise ValueError(startup_failure(prefix,'Application exited with code '+str(child.returncode),offset))
        try:
            result=health_connection(info)
            if result.get('status')=='ok' and result.get('instance')==info['id']:return
            last_error='Health response did not match this installation'
        except (OSError,ValueError,http.client.HTTPException) as exc:last_error=str(exc)
        time.sleep(.1)
    raise ValueError(startup_failure(prefix,'Startup health check failed: '+last_error,offset,service,since))


def stop(prefix):
    if service_active(prefix):
        subprocess.run(['systemctl','--user','stop',unit_path(prefix).name],check=True)
        return True
    pid=process(prefix)
    if not pid:return False
    check_process_handles()
    try:fd=pidfd_open(pid)
    except ProcessLookupError:return True
    try:
        # Bind the signal to a kernel process handle, then recheck the stored identity.
        # After SIGTERM wait on that handle; never read a dying process's environment.
        current=process(prefix)
        if current is None:return True
        if current!=pid:raise ValueError('Process identity changed; no signal sent')
        try:pidfd_send_signal(fd,signal.SIGTERM)
        except ProcessLookupError:return True
        import select
        if select.select([fd],[],[],15)[0]:return True
        raise ValueError('This instance is still shutting down; no SIGKILL was sent')
    finally:os.close(fd)


def activate(prefix,target):
    prefix=Path(prefix);target=Path(target).resolve()
    if not target.is_relative_to(prefix/'releases') or not (target/'app/main.py').is_file():raise ValueError('Unsafe release')
    temporary=prefix/('.current-'+uuid.uuid4().hex)
    temporary.symlink_to(target.relative_to(prefix),target_is_directory=True)
    os.replace(temporary,prefix/'current')
    fd=os.open(prefix,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def sync_release(target):
    from .maintenance import sync_directory
    for path in target.rglob('*'):
        if path.is_file() and not path.is_symlink():
            with path.open('rb') as stream:os.fsync(stream.fileno())
    directories=[p for p in target.rglob('*') if p.is_dir() and not p.is_symlink()]
    for path in sorted(directories,key=lambda p:len(p.parts),reverse=True):sync_directory(path)
    sync_directory(target);sync_directory(target.parent)


def install(source,prefix,port=None,projects_root=None,wheelhouse=None,no_start=False,service=False):
    import shutil
    from .version import VERSION
    source=Path(source).resolve();prefix=prefix_path(prefix)
    if os.name!='posix' or not (3,11)<=sys.version_info[:2]<(3,14):raise ValueError('Python 3.11–3.13 on Linux/WSL2 is required')
    if os.geteuid()==0:raise ValueError('Run as your normal user; sudo is not required')
    check_process_handles()
    os.umask(0o077)
    existed=(prefix/'installation.json').exists()
    if prefix.exists() and not existed and any(prefix.iterdir()):raise ValueError('Install destination must be empty or a marked installation')
    if (source/'release-manifest.json').exists():
        expected=json.loads((source/'release-manifest.json').read_text())['files']
        for name,digest in expected.items():
            p=Path(name)
            if p.is_absolute() or '..' in p.parts or (source/p).is_symlink() or hashlib.sha256((source/p).read_bytes()).hexdigest()!=digest:raise ValueError('Release manifest does not match')
    prefix.mkdir(parents=True,exist_ok=True,mode=0o700)
    if prefix.stat().st_uid!=os.geteuid() or prefix.stat().st_mode&0o077:raise ValueError('Installation directory must be owned by you with mode 0700')
    if existed:
        info=layout(prefix)
        if pending(prefix):raise ValueError('Recover the interrupted update before installing another release')
        if port is not None and port!=info['port'] or projects_root is not None:raise ValueError('Update keeps existing settings; configure roots separately')
    else:
        port=choose_port(port)
        info=fresh_installation_info(prefix,port)
        for name in ('config','state','backups','metadata','reports','content','logs','tmp','migration-backups','keys','projects','updates','releases','bin'):(prefix/name).mkdir(mode=0o700)
        config=fresh_configuration(prefix,projects_root)
        atomic_json(prefix/'config/settings.json',config);atomic_json(prefix/'installation.json',info)
    target=prefix/'releases'/(VERSION+'-'+uuid.uuid4().hex[:12]);target.mkdir(mode=0o700)
    # Copy only runtime code, never the source checkout state, local config, or evidence.
    for p in (source/'app').rglob('*'):
        if p.is_file() and '__pycache__' not in p.parts and (p.suffix in ('.py','.html','.css','.js') or p.suffix=='.json' and p.parent.name=='locales'):
            if p.is_symlink() or p.name.endswith('.local.json'):raise ValueError('Unsafe runtime source')
            dest=target/p.relative_to(source);dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700);shutil.copyfile(p,dest);dest.chmod(0o600)
            if hashlib.sha256(p.read_bytes()).digest()!=hashlib.sha256(dest.read_bytes()).digest():raise ValueError('Runtime copy verification failed')
    for name in ('requirements.lock','scripts/manage.py','scripts/install.py','scripts/setup.py','scripts/generate_backup_key.py'):
        dest=target/name;dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700);shutil.copyfile(source/name,dest)
        if hashlib.sha256((source/name).read_bytes()).digest()!=hashlib.sha256(dest.read_bytes()).digest():raise ValueError('Launcher copy verification failed')
    interpreter=base_interpreter()
    try:subprocess.run([interpreter,'-m','venv','--symlinks',str(target/'venv')],check=True)
    except subprocess.CalledProcessError:raise ValueError('Python venv is unavailable. On Ubuntu/Debian install python3-venv, then retry') from None
    cmd=[str(target/'venv/bin/python'),'-m','pip','install','--disable-pip-version-check']
    if wheelhouse:cmd+=['--no-index','--find-links',str(Path(wheelhouse).resolve())]
    subprocess.run([*cmd,'-r',str(target/'requirements.lock')],check=True)
    subprocess.run([str(target/'venv/bin/python'),'-B','-m','app.selftest'],cwd=target,check=True,env={**os.environ,'PYTHONPATH':str(target)})
    sync_release(target)
    wrapper=prefix/'bin/ptm';temporary=prefix/'bin'/('.ptm-'+uuid.uuid4().hex)
    # The new management code is available even if migration/activation is interrupted.
    temporary.write_text('#!/bin/sh\nexec '+shlex.quote(str(target/'venv/bin/python'))+' -B '+shlex.quote(str(target/'scripts/manage.py'))+' --prefix '+shlex.quote(str(prefix))+' "$@"\n');temporary.chmod(0o700)
    with temporary.open('rb') as f:os.fsync(f.fileno())
    os.replace(temporary,wrapper)
    setup=prefix/'bin/setup';temporary=prefix/'bin'/('.setup-'+uuid.uuid4().hex)
    temporary.write_text('#!/bin/sh\nexec '+shlex.quote(str(target/'venv/bin/python'))+' -B '+shlex.quote(str(target/'scripts/setup.py'))+' --prefix '+shlex.quote(str(prefix))+' "$@"\n');temporary.chmod(0o700)
    with temporary.open('rb') as f:os.fsync(f.fileno())
    os.replace(temporary,setup)
    from .maintenance import sync_directory
    sync_directory(wrapper.parent)
    if existed:stop(prefix)
    old=(prefix/'current').resolve() if (prefix/'current').exists() else None
    os.environ.update(environment(prefix))
    # Import the new release for migration, not the installer source checkout.
    code='from app.installation import update_state; update_state('+repr(str(prefix))+','+repr(str(target))+','+repr(str(old) if old else None)+')'
    result=subprocess.run([str(target/'venv/bin/python'),'-B','-c',code],cwd=target,env=environment(prefix))
    if result.returncode:raise ValueError('Update paused; old release retained. Use ptm recover-update before restarting')
    if service:install_service(prefix)
    should_start=not no_start and info.get('autostart_after_install',True)
    if should_start:start(prefix)
    from .interfaces import urls
    return dict(status='installed',prefix=str(prefix),url='http://127.0.0.1:'+str(info['port']),bind_address=info.get('bind_address','127.0.0.1'),network_urls=urls(info['port'],info.get('bind_address','127.0.0.1')),setup_code_command=shlex.quote(str(prefix/'bin/ptm'))+' setup-code',previous_release_retained=old is not None,started=should_start)


def update_state(prefix,target,old):
    from . import projects
    from .lifecycle import guard
    from .maintenance import checkpoint,rehearse,migrate_checked
    cfg=projects.base_settings;prefix=Path(prefix)
    if old is None:
        from .filesystem import validate_allowed_root
        for root in cfg.allowed_roots:validate_allowed_root(root,cfg)
    with guard(cfg.data_dir,exclusive=True):
        point=prefix/'updates'/uuid.uuid4().hex
        journal=dict(phase='preparing',old_release=old,new_release=target,checkpoint=str(point))
        atomic_json(prefix/'update-journal.json',journal)
        checkpoint(cfg,point);rehearse(point)
        journal['phase']='migrating';atomic_json(prefix/'update-journal.json',journal)
        migrate_checked(cfg,point)
        journal['phase']='activating';atomic_json(prefix/'update-journal.json',journal)
        activate(prefix,target)
        journal['phase']='complete';atomic_json(prefix/'update-journal.json',journal)


def recover_update(prefix):
    from . import projects
    from .lifecycle import guard
    from .maintenance import recover
    stop(prefix);prefix=Path(prefix);journal=json.loads((prefix/'update-journal.json').read_text())
    if journal['phase']=='complete':raise ValueError('There is no interrupted update')
    point=Path(journal['checkpoint']).resolve()
    if not point.is_relative_to(prefix/'updates'):raise ValueError('Unsafe checkpoint')
    with guard(projects.base_settings.data_dir,exclusive=True):
        if journal['phase'] in ('migrating','activating'):recover(projects.base_settings,point)
        if journal['old_release']:activate(prefix,journal['old_release'])
        journal['phase']='complete';journal['recovered']=True;atomic_json(prefix/'update-journal.json',journal)


def install_service(prefix):
    subprocess.run(['systemctl','--user','show-environment'],check=True,stdout=subprocess.DEVNULL)
    stop(prefix);p=unit_path(prefix)
    if p.exists() and not service_owned(prefix):raise ValueError('Service name is occupied')
    p.parent.mkdir(parents=True,exist_ok=True)
    value=str(Path(prefix)/'bin/ptm').replace('\\','\\\\').replace('"','\\"').replace('%','%%')
    p.write_text('# PTM '+layout(prefix)['id']+'\n[Unit]\nDescription=Project Time Machine\nAfter=network.target\n[Service]\nExecStart="'+value+'" run\nRestart=on-failure\nRestartSec=5\nUMask=0077\nNoNewPrivileges=true\n[Install]\nWantedBy=default.target\n');p.chmod(0o600)
    subprocess.run(['systemctl','--user','daemon-reload'],check=True)
    subprocess.run(['systemctl','--user','enable',p.name],check=True)
