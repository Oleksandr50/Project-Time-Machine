"""Manage only the named, marked installation; never stop processes by name or port."""
from pathlib import Path
import argparse,json,os,subprocess,sys,uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
p=argparse.ArgumentParser();p.add_argument('--prefix',required=True)
p.add_argument('command',choices=('start','stop','restart','run','status','doctor','self-test','update','recover-update','recover-settings','setup','setup-code','network-on','network-off','allow-root','backup-state','service-install','uninstall'))
p.add_argument('value',nargs='?');a=p.parse_args()
from app import installation as i
try:
    prefix=i.prefix_path(a.prefix);info=i.layout(prefix);os.environ.update(i.environment(prefix))
    if a.command=='run':i.run(prefix)
    elif a.command=='start':i.start(prefix)
    elif a.command=='stop':i.stop(prefix)
    elif a.command=='restart':i.stop(prefix);i.start(prefix)
    elif a.command in ('doctor','status'):
        print(json.dumps(dict(running=bool(i.process(prefix) or i.service_active(prefix)),pending_update=i.pending(prefix),prefix=str(prefix),port=info['port']),indent=2))
    elif a.command=='setup':
        subprocess.run([sys.executable,'-B',str(Path(__file__).resolve().with_name('setup.py')),'--prefix',str(prefix)],check=True)
    elif a.command=='recover-settings':
        from app.setup_config import recover
        recover(prefix)
    elif a.command=='setup-code':
        from app import auth,projects,setup_codes
        if auth.state()['setup_completed']:raise ValueError('Administrator already exists; sign in using your current credentials')
        setup_codes.ensure(projects.base_settings)
        print(setup_codes.read(projects.base_settings))
    elif a.command in ('network-on','network-off'):
        from app import auth,projects
        import time
        enabled=a.command=='network-on'
        with projects.registry() as connection:
            connection.execute('BEGIN IMMEDIATE')
            connection.execute('UPDATE auth_settings SET network_enabled=? WHERE id=1',(int(enabled),))
            if not enabled:
                for session in connection.execute('SELECT id,peer FROM sessions WHERE revoked_at IS NULL').fetchall():
                    if not auth.loopback(session['peer']):connection.execute('UPDATE sessions SET revoked_at=? WHERE id=?',(time.time(),session['id']))
            auth.event(connection,None,'network_enabled' if enabled else 'network_disabled','local-cli')
        print('Network access enabled' if enabled else 'Network access disabled')
    elif a.command=='self-test':
        subprocess.run([sys.executable,'-B','-m','app.selftest'],cwd=Path(__file__).resolve().parents[1],env=i.environment(prefix),check=True)
    elif a.command=='update':
        if not a.value:raise ValueError('Specify the extracted new release directory')
        subprocess.run([sys.executable,'-B',str(Path(a.value).resolve()/'scripts/install.py'),'--prefix',str(prefix)],check=True,env=i.environment(prefix))
    elif a.command=='recover-update':i.recover_update(prefix)
    elif a.command=='service-install':i.install_service(prefix);i.start(prefix)
    elif a.command=='backup-state':
        from app import projects
        from app.lifecycle import guard
        from app.maintenance import checkpoint
        with guard(projects.base_settings.data_dir,exclusive=True):
            dest=prefix/'updates'/('manual-'+uuid.uuid4().hex);checkpoint(projects.base_settings,dest)
        print('Verified metadata checkpoint: '+str(dest))
    elif a.command=='allow-root':
        from dataclasses import replace
        from app import projects
        from app.filesystem import validate_allowed_root
        from app.lifecycle import guard
        from app.maintenance import atomic_json
        if not a.value:raise ValueError('Specify an existing absolute project directory')
        path=Path(a.value).expanduser().resolve(strict=True);cfg=projects.base_settings
        validate_allowed_root(path,cfg)
        active=i.stop(prefix)
        with guard(cfg.data_dir,exclusive=True):
            file=prefix/'config/settings.json';value=json.loads(file.read_text());roots=value.setdefault('allowed_roots',[])
            if str(path) not in roots:roots.append(str(path))
            atomic_json(prefix/'updates'/('settings-'+uuid.uuid4().hex+'.json'),json.loads(file.read_text()))
            atomic_json(file,value)
        if active:i.start(prefix)
    elif a.command=='uninstall':
        # Preserve data, all archives, keys, project directories and rollback releases.
        from app import projects
        from app.lifecycle import guard
        i.stop(prefix)
        with guard(projects.base_settings.data_dir,exclusive=True):
            if i.service_owned(prefix):
                unit=i.unit_path(prefix);subprocess.run(['systemctl','--user','disable',unit.name],check=True);unit.unlink();subprocess.run(['systemctl','--user','daemon-reload'],check=True)
            current=prefix/'current'
            if current.is_symlink():current.unlink()
            (prefix/'bin/ptm').unlink(missing_ok=True)
            (prefix/'bin/setup').unlink(missing_ok=True)
        print('Application disconnected. Data, backups, keys, projects and rollback code retained in '+str(prefix))
except (OSError,ValueError,subprocess.CalledProcessError) as e:p.exit(1,str(e)+'\n')
