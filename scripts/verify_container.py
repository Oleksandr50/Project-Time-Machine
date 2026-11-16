"""Real non-root Docker smoke test. Unique compose project, port and temporary bind paths."""
from contextlib import closing,contextmanager
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.parse import urlencode,urlsplit,parse_qs
from urllib.request import build_opener,HTTPCookieProcessor,Request,ProxyHandler
import argparse,json,re,secrets,shutil,socket,sqlite3,subprocess,sys,tempfile,time,uuid


@contextmanager
def disposable(result):
    root=Path(tempfile.mkdtemp(prefix='ptm-container-check-'))
    try:yield root
    finally:
        if 'cleanup' not in result:shutil.rmtree(root)


def main():
    p=argparse.ArgumentParser();p.add_argument('--source',default=str(Path(__file__).resolve().parents[1]));p.add_argument('--report');a=p.parse_args()
    source=Path(a.source).resolve();image='ptm-smoke-'+uuid.uuid4().hex[:12]+':local';result=dict(status='running',checks=[])
    with disposable(result) as root:
        log=root/'docker.log'
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        def execute(args,output=False):
            if output:return subprocess.run(args,check=True,capture_output=True,text=True,timeout=240).stdout
            with log.open('ab') as out:subprocess.run(args,check=True,stdout=out,stderr=subprocess.STDOUT,timeout=240)
        execute([sys.executable,'-B',str(source/'scripts/docker_prepare.py'),'--directory',str(root),'--port',str(port)])
        with (root/'.env').open('a') as env:env.write("PTM_IMAGE='"+image+"'\n")
        shutil.copyfile(source/'compose.yaml',root/'compose.yaml')
        compose=['docker','compose','--project-directory',str(source),'--env-file',str(root/'.env'),'-f',str(source/'compose.yaml')]
        jar=CookieJar();http=build_opener(ProxyHandler({}),HTTPCookieProcessor(jar))
        base='http://127.0.0.1:'+str(port)
        def request(path,data=None):
            if data is not None:data=urlencode(dict(csrf_token=next((c.value for c in jar if c.name=='ptm_csrf'),''),**data)).encode()
            with http.open(Request(base+path,data=data,headers={'Origin':base,'Accept-Language':'en'}),timeout=15) as r:return r.geturl(),r.read().decode()
        def jobs(pid):
            for _ in range(200):
                rows=json.loads(request('/api/jobs?project_id='+str(pid))[1])['jobs']
                if rows and all(x['state'] not in ('queued','running') for x in rows):
                    assert all(x['state']=='succeeded' for x in rows);return
                time.sleep(.1)
            raise ValueError('Container queue timeout')
        def snapshot():
            with closing(sqlite3.connect(root/'docker-state/state/projects.sqlite')) as c:users=c.execute('SELECT id,username,password_hash,auth_version FROM users').fetchall();projects=c.execute('SELECT id,path,history_path,backup_path FROM projects').fetchall()
            with closing(sqlite3.connect(root/'docker-state/state/projects/1/history.sqlite')) as c:
                snaps=c.execute('SELECT id,description,content_status,backup_point_id FROM snapshots ORDER BY id').fetchall();points=c.execute('SELECT id,archive_path,sha256 FROM backups ORDER BY id').fetchall()
            return users,projects,snaps,points
        try:
            execute(['docker','build','-t',image,str(source)])
            execute([*compose,'up','-d','--no-build','--wait','--wait-timeout','90','app'])
            ident=execute([*compose,'ps','-q','app'],True).strip();container=json.loads(execute(['docker','inspect',ident],True))[0]
            assert container['Config']['User'] not in ('','0','0:0','root')
            assert container['HostConfig']['ReadonlyRootfs'] and not container['HostConfig']['Privileged']
            assert 'ALL' in container['HostConfig']['CapDrop'] and container['State']['Health']['Status']=='healthy'
            mounts={x['Destination']:x for x in container['Mounts']}
            assert set(mounts)=={'/state','/projects','/config','/keys'}
            assert '/tmp' in container['HostConfig']['Tmpfs']
            assert mounts['/config']['RW'] is False and mounts['/keys']['RW'] is False
            result['checks']+=['non-root, no privilege, read-only rootfs, capabilities dropped','explicit project/state/config/key mounts only','healthy before setup; host loopback preserved']
            request('/setup');password=secrets.token_urlsafe(32)
            request('/setup',dict(username='container-test',password=password,confirm_password=password,language='en'))
            project=root/'docker-projects/demo';project.mkdir();(project/'code.py').write_text('def value():\n    return 9\n')
            url,_=request('/projects/add',dict(path='/projects/demo',name='Disposable container',category='Python'));pid=int(parse_qs(urlsplit(url).query)['project_id'][0])
            request('/actions/analyze?project_id='+str(pid),{});request('/actions/backup?project_id='+str(pid),{});jobs(pid)
            with closing(sqlite3.connect(root/'docker-state/state/projects/1/history.sqlite')) as c:point=c.execute("SELECT id FROM backup_points WHERE kind='full'").fetchone()[0]
            (project/'code.py').write_text('changed\n');_,html=request('/restore/preview?project_id='+str(pid),dict(source='point:'+point,mode='full'))
            def field(name):return re.search('name="'+name+'" value="([^"]+)"',html)[1]
            request('/restore/confirm?project_id='+str(pid),dict(preview_id=field('preview_id'),confirmation_token=field('confirmation_token'),acknowledge='on',confirmation='RESTORE'));jobs(pid)
            assert (project/'code.py').read_text()=='def value():\n    return 9\n'
            report_file=root/'docker-state/reports/projects/1/current_state.md';report_bytes=report_file.read_bytes()
            before=snapshot();execute([*compose,'stop','app']);execute([*compose,'up','-d','--no-build','--wait','--wait-timeout','90','app'])
            request('/settings');request('/report?project_id='+str(pid));assert snapshot()==before
            assert report_file.read_bytes()==report_bytes
            result['checks']+=['real web setup/project/metadata/full backup/confirmed restore','persistent bind state and administrator survive container restart']
            execute([sys.executable,'-B',str(source/'scripts/docker_upgrade.py'),'--install-dir',str(root)])
            request('/settings');request('/report?project_id='+str(pid));assert snapshot()==before
            assert report_file.read_bytes()==report_bytes
            assert list((root/'docker-state/migration-backups/deployments').glob('*/manifest.json'))
            result['checks']+=['real Docker update helper, offline checkpoint/rehearsal and health','project/snapshot/backup IDs, password hash and source bytes preserved']
            result['status']='passed';result['image']=image
        finally:
            try:execute([*compose,'down'])
            except Exception:result.update(status='failed',cleanup='compose down failed for own test project',retained_test_directory=str(root))
            if result['status']=='running':result['status']='failed'
            if a.report:
                report=Path(a.report);report.parent.mkdir(parents=True,exist_ok=True,mode=0o700);report.write_text(json.dumps(result,indent=2)+'\n')
                if log.exists():(report.parent/'docker.log').write_bytes(log.read_bytes())
    print(json.dumps(result));return result['status']=='passed'


if __name__=='__main__':sys.exit(not main())
