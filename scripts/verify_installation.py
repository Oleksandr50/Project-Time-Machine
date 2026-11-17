"""Real install/update/restart/uninstall smoke test, exclusively in TemporaryDirectory."""
from contextlib import closing,contextmanager
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.parse import urlencode,urlsplit,parse_qs
from urllib.request import build_opener,HTTPCookieProcessor,Request,ProxyHandler
import argparse,json,re,secrets,socket,sqlite3,subprocess,sys,tempfile,time,shutil


@contextmanager
def disposable(result):
    root=Path(tempfile.mkdtemp(prefix='ptm-installation-check-'))
    try:yield root
    finally:
        if 'cleanup' not in result:shutil.rmtree(root)


def main():
    p=argparse.ArgumentParser();p.add_argument('--source',default=str(Path(__file__).resolve().parents[1]));p.add_argument('--wheelhouse');p.add_argument('--report');a=p.parse_args()
    source=Path(a.source).resolve();result=dict(status='running',checks=[])
    with disposable(result) as root:
        prefix=root/'installation with spaces';log=root/'installation.log'
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        base='http://127.0.0.1:'+str(port);jar=CookieJar();http=build_opener(ProxyHandler({}),HTTPCookieProcessor(jar))
        def request(path,data=None):
            headers={'Accept-Language':'en','Origin':base}
            if data is not None:
                token=next((c.value for c in jar if c.name=='ptm_csrf'),'');data=urlencode(dict(csrf_token=token,**data)).encode()
            with http.open(Request(base+path,data=data,headers=headers),timeout=15) as r:return r.geturl(),r.read().decode()
        def command(args):
            with log.open('ab') as out:subprocess.run(args,stdout=out,stderr=subprocess.STDOUT,check=True,timeout=180)
        def manage(*args):command([sys.executable,'-B',str(source/'scripts/manage.py'),'--prefix',str(prefix),*args])
        def wait_jobs(pid):
            for _ in range(160):
                rows=json.loads(request('/api/jobs?project_id='+str(pid))[1])['jobs']
                if rows and all(r['state'] not in ('queued','running') for r in rows):
                    if not all(r['state']=='succeeded' for r in rows):raise ValueError('Smoke job failed')
                    return
                time.sleep(.1)
            raise ValueError('Smoke queue timeout')
        def state():
            with closing(sqlite3.connect(prefix/'state/projects.sqlite')) as c:
                users=c.execute('SELECT id,username,password_hash,auth_version FROM users').fetchall()
                bindings=c.execute('SELECT id,path,history_path,backup_path FROM projects').fetchall()
            history=Path(bindings[0][2])
            with closing(sqlite3.connect(history)) as c:
                snapshots=c.execute('SELECT id,description,content_status,backup_point_id FROM snapshots ORDER BY id').fetchall()
                archives=c.execute('SELECT id,archive_path,sha256 FROM backups ORDER BY id').fetchall()
            return users,bindings,snapshots,archives
        try:
            install=[sys.executable,'-B',str(source/'scripts/install.py'),'--prefix',str(prefix),'--port',str(port)]
            if a.wheelhouse:install+=['--wheelhouse',str(Path(a.wheelhouse).resolve())]
            command(install)
            with closing(sqlite3.connect(prefix/'state/projects.sqlite')) as c:
                assert c.execute('SELECT count(*) FROM users').fetchone()[0]==0
                assert c.execute('SELECT setup_completed,network_enabled FROM auth_settings').fetchone()==(0,0)
            denied=subprocess.run([sys.executable,'-B',str(source/'scripts/manage.py'),'--prefix',str(prefix),'allow-root',str(prefix/'updates')],capture_output=True)
            assert denied.returncode!=0
            request('/setup');password=secrets.token_urlsafe(32)
            request('/setup',dict(username='installation-test',password=password,confirm_password=password,language='en'))
            project=root/'projects/demo';project.mkdir(parents=True);(project/'code.py').write_text('def value():\n    return 7\n')
            manage('allow-root',str(project.parent))
            url,_=request('/projects/add',dict(name='Disposable',path=str(project),category='Python'));pid=int(parse_qs(urlsplit(url).query)['project_id'][0])
            request('/actions/analyze?project_id='+str(pid),dict(description='installation snapshot'))
            request('/actions/backup?project_id='+str(pid),{});wait_jobs(pid)
            history=prefix/'state/projects'/str(pid)/'history.sqlite'
            with closing(sqlite3.connect(history)) as c:point=c.execute("SELECT id FROM backup_points WHERE kind='full'").fetchone()[0]
            (project/'code.py').write_text('changed\n')
            _,html=request('/restore/preview?project_id='+str(pid),dict(source='point:'+point,mode='full'))
            def field(name):return re.search('name="'+name+'" value="([^"]+)"',html)[1]
            request('/restore/confirm?project_id='+str(pid),dict(preview_id=field('preview_id'),confirmation_token=field('confirmation_token'),acknowledge='on',confirmation='RESTORE'));wait_jobs(pid)
            assert (project/'code.py').read_text()=='def value():\n    return 7\n'
            result['checks']+=['fresh users=0 and network disabled; own updates/keys/releases are protected','browser setup without default password','real HTTP project/snapshot/full backup/preview/confirmed restore']
            report_file=prefix/'reports/projects'/str(pid)/'current_state.md';report_bytes=report_file.read_bytes()
            before=state();command(install)  # same-version rehearsal also exercises the real update path
            assert before==state();assert report_file.read_bytes()==report_bytes
            request('/report?project_id='+str(pid))
            assert len(list((prefix/'releases').iterdir()))==2
            assert list((prefix/'updates').glob('*/manifest.json'))
            request('/settings');manage('restart');request('/settings');assert before==state()
            result['checks']+=['checked metadata checkpoint and rehearsal','project/snapshot/backup IDs and password hash survive update','old release retained','restart retains authentication and history']
            request('/logout',{});jar.clear();request('/login');request('/login',dict(username='installation-test',password=password,language='en'))
            manage('uninstall')
            assert (prefix/'state/projects.sqlite').exists() and (project/'code.py').exists()
            assert not (prefix/'bin/ptm').exists() and not (prefix/'current').exists()
            for _,path,_ in before[3]:assert Path(path).exists()
            result['checks']+=['same administrator can sign in after update','uninstall retains state, archives, keys directory and source']
            result['status']='passed'
        finally:
            if (prefix/'installation.json').exists():
                try:manage('stop')
                except Exception:result.update(status='failed',cleanup='stop failed; inspect process identity before retry',retained_test_directory=str(root))
            if result['status']=='running':result['status']='failed'
            if a.report:
                report=Path(a.report);report.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                report.write_text(json.dumps(result,indent=2)+'\n')
                if log.exists():(report.parent/'installation.log').write_bytes(log.read_bytes())
    print(json.dumps(result));return result['status']=='passed'


if __name__=='__main__':sys.exit(not main())
