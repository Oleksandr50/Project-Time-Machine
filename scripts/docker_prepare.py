"""Create empty owned bind directories/config, never overwrite existing configuration."""
import argparse,json,os,sys,re,uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.installation import choose_port
p=argparse.ArgumentParser();p.add_argument('--directory',default='.');p.add_argument('--projects');p.add_argument('--port',type=int);a=p.parse_args()
root=Path(a.directory).resolve();root.mkdir(parents=True,exist_ok=True)
if os.name!='posix' or os.geteuid()==0:p.exit(1,'Run as your normal Linux/WSL user\n')
env=root/'.env'
if env.exists():
    match=re.search(r"(?m)^PTM_PORT=['\"]?(\d+)",env.read_text())
    if not match:p.exit(1,'Existing .env needs a PTM_PORT; it was not overwritten\n')
    port=int(match[1])
    if a.port is not None and a.port!=port:p.exit(1,'Existing .env keeps its port; it was not overwritten\n')
else:port=choose_port(a.port)
os.umask(0o077)
paths={k:root/('docker-'+k) for k in ('state','config','keys','projects')}
if a.projects:paths['projects']=Path(a.projects).expanduser().resolve(strict=True)
project=paths['projects'].resolve()
if project in (Path('/'),Path('/home'),Path('/tmp'),Path('/etc'),Path('/var'),Path('/usr')):p.exit(1,'Mount a dedicated project directory, not a system root\n')
for name in ('state','config','keys'):
    storage=paths[name].resolve()
    if project==storage or project in storage.parents or storage in project.parents:p.exit(1,'Projects and application storage must not overlap\n')
for name,path in paths.items():
    if name=='projects' and a.projects:continue
    path.mkdir(exist_ok=True,mode=0o700)
    if path.is_symlink() or path.stat().st_uid!=os.geteuid() or path.stat().st_mode&0o077:p.exit(1,'Storage must be owned by you with mode 0700: '+str(path)+'\n')
cfg=paths['config']/'settings.json'
if not cfg.exists():
    value={k:'/state/'+v for k,v in dict(config_dir='configuration',data_dir='state',backups_dir='backups',metadata_dir='metadata',reports_dir='reports',content_dir='content',logs_dir='logs',temp_dir='tmp',migrations_dir='migration-backups').items()}
    value.update(db_path='/state/state/unselected.sqlite',allowed_roots=['/projects'],protected_roots=['/state','/config','/keys'],encryption_keys={})
    with cfg.open('x') as f:json.dump(value,f,indent=2);f.write('\n')
if not env.exists():
    values=dict(COMPOSE_PROJECT_NAME='ptm-'+uuid.uuid4().hex[:12],PTM_UID=os.geteuid(),PTM_GID=os.getegid(),PTM_PORT=port,**{'PTM_'+k.upper()+'_DIR':str(v) for k,v in paths.items()})
    if any('\n' in str(v) or '\r' in str(v) or "'" in str(v) for v in values.values()):p.exit(1,'Choose paths without quotes or newlines\n')
    with env.open('x') as f:
        for k,v in values.items():f.write(k+"='"+str(v)+"'\n")
print('Ready. Start with: docker compose up -d --build')
print('Local URL: http://127.0.0.1:'+str(port))
