"""Interactive settings for one explicitly selected installation."""
from pathlib import Path
import argparse,copy,ipaddress,os,sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app import installation as install

MENU='''========================================
          PROJECT TIME MACHINE
             CONFIGURATION
========================================

Installation: {prefix}

1. Project directories (allowed_roots)
2. Backup storage (backups_dir)
3. Network interface / Bind address
4. Server port
5. Start application
6. Stop application
7. Restart application
8. Autostart after installation ({after})
9. Autostart on system boot ({boot})
10. Show current settings and status
11. Save settings and apply changes
0. Exit
'''


def main(argv=None,input_fn=input,out=print):
    parser=argparse.ArgumentParser(description='Configure one Project Time Machine installation')
    parser.add_argument('--prefix',default=str(install.default_prefix()))
    parser.add_argument('--recover',action='store_true',help='Explicit recovery of an interrupted settings save')
    args=parser.parse_args(argv);prefix=install.prefix_path(args.prefix)
    os.environ.update(install.environment(prefix))
    from app import setup_config as config
    if args.recover:
        if input_fn('Restore settings from the interrupted change? [y/N]: ').lower()=='y':config.recover(prefix);out('Previous settings restored. Start the application explicitly.')
        return 0
    if install.pending(prefix):raise ValueError('Pending update/settings operation: use recover-update or setup.sh --recover first')
    saved_info,saved_document=config.load(prefix)
    info=copy.deepcopy(saved_info);document=copy.deepcopy(saved_document)
    allow_create=False;enable_linger=False
    while True:
        out(MENU.format(prefix=prefix,after='ON' if info.get('autostart_after_install',True) else 'OFF',boot='ON' if info.get('autostart_on_boot',False) else 'OFF'))
        choice=input_fn('Select option: ').strip()
        try:
            if choice=='0':
                if (info,document)!=(saved_info,saved_document) and input_fn('Discard unsaved settings? [y/N]: ').lower()!='y':continue
                return 0
            if choice=='1':
                while True:
                    for n,path in enumerate(document['allowed_roots'],1):out(str(n)+'. '+path)
                    action=input_fn('a: add, d: delete, h: add HOME, 0: back: ').strip().lower()
                    if action=='0':break
                    if action in ('a','h'):
                        value=str(install.user_home()) if action=='h' else input_fn('Absolute project parent directory (or ~/): ')
                        root=config.validate_allowed_root(config.user_path(value),config.settings_object(document))
                        if str(root) not in document['allowed_roots']:document['allowed_roots'].append(str(root))
                    elif action=='d':
                        index=int(input_fn('Directory number: '))-1
                        if not 0<=index<len(document['allowed_roots']):raise ValueError('Invalid directory number')
                        if len(document['allowed_roots'])==1:raise ValueError('Keep at least one root; add a replacement first')
                        document['allowed_roots'].pop(index)
            elif choice=='2':
                out('Current: '+document['backups_dir']);out('Default: '+str(prefix/'backups'))
                value=input_fn('New backup directory (empty = default): ').strip() or str(prefix/'backups')
                path=config.user_path(value);create=False
                if not path.exists():
                    create=input_fn('Create this directory when saving? [y/N]: ').lower()=='y'
                    if not create:continue
                path=config.validate_storage(path,prefix,saved_document,create)
                if str(path)!=saved_document['backups_dir']:
                    out('Existing archives will NOT move or be deleted. Old paths remain authorized; offline/missing disks remain unavailable.')
                    if input_fn('Use this directory for future backups? [y/N]: ').lower()!='y':continue
                document['backups_dir']=str(path);allow_create=create
            elif choice=='3':
                out('0.0.0.0 listens on all IPv4 interfaces; browse using the server private IP. Bind can be changed before setup. Direct interface/VPN login is enabled by default; network first-admin setup requires the one-time setup-code.')
                value=input_fn('Bind IP address ['+info.get('bind_address','127.0.0.1')+']: ').strip()
                if value:info['bind_address']=str(ipaddress.ip_address(value))
            elif choice=='4':
                value=input_fn('Server port ['+str(info['port'])+'] (1024-65535): ').strip()
                if value:info['port']=int(value)
            elif choice in ('5','6','7'):
                out('Using SAVED settings; unsaved edits are not applied.')
                if choice in ('6','7'):install.stop(prefix)
                if choice in ('5','7'):install.start(prefix)
                out('Done.')
            elif choice=='8':info['autostart_after_install']=not info.get('autostart_after_install',True)
            elif choice=='9':
                if not info.get('autostart_on_boot',False):
                    out('ON creates/enables only this installation user-service. Boot startup requires loginctl enable-linger for your user; policy may require authentication. No global system service is created.')
                    if input_fn('Explicitly allow user-service and linger on Save? [y/N]: ').lower()!='y':continue
                    info['autostart_on_boot']=True;enable_linger=True
                else:info['autostart_on_boot']=False
            elif choice=='10':
                out('Saved bind/port: '+saved_info.get('bind_address','127.0.0.1')+':'+str(saved_info['port']))
                out('Pending bind/port: '+info.get('bind_address','127.0.0.1')+':'+str(info['port']))
                out('Project roots: '+', '.join(document['allowed_roots']));out('Backup storage: '+document['backups_dir'])
                out('Running: '+str(bool(install.process(prefix) or install.service_active(prefix))))
            elif choice=='11':
                out('Save applies only to this installation. If running, it will stop and resume. Removing roots can make existing projects unavailable; history is retained.')
                if input_fn('Save and apply? [y/N]: ').lower()!='y':continue
                config.apply(prefix,saved_info,saved_document,info,document,allow_create,enable_linger)
                saved_info,saved_document=config.load(prefix);info=copy.deepcopy(saved_info);document=copy.deepcopy(saved_document)
                allow_create=False;enable_linger=False;out('Settings saved.')
            else:out('Unknown option.')
        except (ValueError,OSError,RuntimeError) as exc:
            out('Error: '+str(exc))
            if install.pending(prefix):out('Interrupted settings change: run setup.sh --recover before starting.');return 1
            # Boot activation can fail after a successful configuration save. Reload to
            # avoid pretending that those persisted changes were discarded.
            current_info,current_document=config.load(prefix)
            if (current_info,current_document)!=(saved_info,saved_document):
                saved_info,saved_document=current_info,current_document
                info=copy.deepcopy(saved_info);document=copy.deepcopy(saved_document)
        except Exception as exc:
            import subprocess
            if not isinstance(exc,subprocess.CalledProcessError):raise
            out('Service action failed. Check user-systemd/loginctl availability and permissions.')
            saved_info,saved_document=config.load(prefix);info=copy.deepcopy(saved_info);document=copy.deepcopy(saved_document)


if __name__=='__main__':
    try:sys.exit(main())
    except (ValueError,OSError) as exc:print('Setup: '+str(exc),file=sys.stderr);sys.exit(1)
    except (EOFError,KeyboardInterrupt):print('\nNo further changes applied.');sys.exit(1)
