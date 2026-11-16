"""Build first, then stop and upgrade only the selected, labelled PTM service."""
from pathlib import Path
import argparse,json,subprocess,sys,uuid
p=argparse.ArgumentParser();p.add_argument('--install-dir',required=True);p.add_argument('--project-name');a=p.parse_args()
new=Path(__file__).resolve().parents[1];old=Path(a.install_dir).resolve()
if not (old/'.env').is_file():p.exit(1,'Run docker_prepare.py in the installation directory first\n')
def compose(root):return ['docker','compose',*(['--project-name',a.project_name] if a.project_name else []),'--project-directory',str(root),'--env-file',str(old/'.env'),'-f',str(root/'compose.yaml')]
def execute(args,**kwargs):return subprocess.run(args,check=True,**kwargs)
try:
    project_name=json.loads(execute([*compose(old),'config','--format','json'],capture_output=True,text=True).stdout)['name']
    ids=execute([*compose(old),'ps','-aq','app'],capture_output=True,text=True).stdout.split()
    rollback=[]
    for ident in ids:
        container=json.loads(execute(['docker','inspect',ident],capture_output=True,text=True).stdout)[0]
        labels=container['Config']['Labels']
        if labels.get('org.opencontainers.image.title')!='Project Time Machine' or labels.get('com.docker.compose.project')!=project_name or labels.get('com.docker.compose.service')!='app':raise ValueError('Refusing to stop an unrelated container')
        tag='project-time-machine:rollback-'+uuid.uuid4().hex[:12]
        execute(['docker','image','tag',container['Image'],tag]);rollback.append(tag)
    execute([*compose(new),'build','app'])
    execute([*compose(new),'run','--rm','--no-deps','app','python','-B','-m','app.selftest'])
    execute([*compose(old),'stop','app'])
    execute([*compose(new),'run','--rm','--no-deps','app','python','-B','-m','app.maintenance_cli','prepare-upgrade'])
    execute([*compose(new),'up','-d','--no-deps','--wait','--wait-timeout','90','app'])
    receipt=old/'docker-config'/'last-update.json'
    receipt.write_text(json.dumps(dict(status='updated',rollback_images=rollback,new_source=str(new)),indent=2)+'\n');receipt.chmod(0o600)
    print('Updated. Data and previous images retained; no other compose project was stopped.')
except (ValueError,subprocess.CalledProcessError) as e:
    p.exit(1,str(e)+'\nNo automatic database rollback. Inspect logs and deployment checkpoint before restarting.\n')
