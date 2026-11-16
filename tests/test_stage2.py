import hashlib
import json
import sqlite3
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
import unittest
from fastapi.testclient import TestClient
from app import auth,access,projects,migrations
from app.config import Settings
from app.main import app

PASSWORD='Owner-password-unique-2026'
USER_PASSWORD='User-password-unique-2026'


class AuthFixture(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.before=projects.base_settings
        self.cfg=replace(Settings(),app_root=self.root/'application',config_dir=self.root/'config',
            data_dir=self.root/'state',db_path=self.root/'state/unselected.sqlite',
            backups_dir=self.root/'backups',metadata_dir=self.root/'metadata',reports_dir=self.root/'reports',
            content_dir=self.root/'content',logs_dir=self.root/'logs',temp_dir=self.root/'tmp',
            migrations_dir=self.root/'migration-backups',allowed_roots=(self.root/'sources',),
            management_networks=('127.0.0.0/8','::1/128','192.168.1.0/24'),lan_access=False,login_attempt_limit=1000)
        (self.root/'sources').mkdir()
        projects.base_settings=self.cfg;self.token=projects.current_settings.set(self.cfg)
        self.clients=[];self.admin=self.client()

    def tearDown(self):
        for c in self.clients:c.close()
        projects.current_settings.reset(self.token);projects.base_settings=self.before
        self.temp.cleanup()

    def client(self,host='http://127.0.0.1:13011',peer='127.0.0.1'):
        c=TestClient(app,base_url=host,client=(peer,123));self.clients.append(c);return c

    def post(self,c,path,data=None,**kwargs):
        form={'csrf_token':c.cookies.get('ptm_csrf'),**(data or {})}
        return c.post(path,data=form,headers={'origin':str(c.base_url).rstrip('/')},follow_redirects=False,**kwargs)

    def setup(self):
        r=self.admin.get('/setup');self.assertEqual(r.status_code,200,r.text)
        r=self.post(self.admin,'/setup',{'username':'owner','password':PASSWORD,'confirm_password':PASSWORD})
        self.assertEqual(r.status_code,303,r.text)

    def signin(self,c,name='owner',password=PASSWORD,language='ru'):
        self.assertEqual(c.get('/login').status_code,200)
        r=self.post(c,'/login',{'username':name,'password':password,'language':language})
        self.assertEqual(r.status_code,303,r.text)

    def create_user(self,name='reader',role='viewer'):
        r=self.post(self.admin,'/admin/users/create',{'username':name,'password':USER_PASSWORD,'role':role,'current_password':PASSWORD})
        self.assertEqual(r.status_code,303,r.text)
        with projects.registry() as c:return c.execute('SELECT id FROM users WHERE username=?',(name,)).fetchone()[0]

    def project(self,name):
        path=self.root/'sources'/name;path.mkdir();(path/'code.py').write_text('def sample():\n    return 1\n')
        r=self.post(self.admin,'/projects/add',{'path':str(path),'name':name,'description':'PRIVATE_'+name})
        self.assertEqual(r.status_code,303,r.text);pid=int(r.headers['location'].split('=')[1])
        self.assertEqual(self.post(self.admin,f'/actions/analyze?project_id={pid}').status_code,303)
        return pid,path

    def grant(self,uid,pid,restore=False):
        r=self.post(self.admin,'/admin/access',{'user_id':uid,'project_id':pid,'allowed':'on','can_restore':'on' if restore else 'off','current_password':PASSWORD})
        self.assertEqual(r.status_code,303,r.text)

    def user_row(self,uid):
        with projects.registry() as c:return dict(c.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone())


class BootstrapTests(AuthFixture):
    def test_no_default_credentials_and_no_operations_before_setup(self):
        with patch.object(projects,'list_projects',side_effect=AssertionError('Must not enumerate projects')):
            for path in ['/','/api/status','/backups/download?id=1']:
                self.assertEqual(self.admin.get(path,follow_redirects=False).status_code,303)
            self.assertEqual(self.admin.post('/actions/backup').status_code,403)
        self.admin.get('/setup')
        self.assertEqual(self.post(self.admin,'/setup',{'username':'admin','password':'admin','confirm_password':'admin'}).status_code,400)
        self.setup()
        self.assertEqual(self.admin.get('/setup').status_code,410)
        self.assertEqual(self.post(self.admin,'/setup',{'username':'intruder','password':PASSWORD,'confirm_password':PASSWORD}).status_code,410)
        self.assertEqual(self.post(self.admin,'/login',{'username':'admin','password':'admin'}).status_code,401)
        with projects.registry() as c:
            row=c.execute('SELECT username,password_hash FROM users').fetchone()
            self.assertEqual(row['username'],'owner');self.assertTrue(row['password_hash'].startswith('$argon2id$v=19$m=65536,t=3,p=4$'))
            self.assertNotIn(PASSWORD,row['password_hash'])

    def test_setup_rejects_remote_proxy_headers_and_forged_localhost(self):
        remote=self.client(peer='192.168.1.7')
        for path in ['/setup','/login','/','/static/css/app.css']:
            self.assertEqual(remote.get(path).status_code,403)
        self.assertEqual(remote.get('/setup',headers={'x-forwarded-for':'127.0.0.1'}).status_code,403)
        self.assertEqual(self.admin.get('/setup',headers={'x-forwarded-for':'192.168.1.7'}).status_code,403)
        disguised=self.client(host='http://192.168.1.10:13011')
        self.assertEqual(disguised.get('/setup').status_code,403)
        self.assertEqual(self.admin.post('/setup',data={'username':'owner','password':PASSWORD}).status_code,403)

    def test_setup_is_single_use_even_for_two_prepared_browsers(self):
        other=self.client();other.get('/setup');self.admin.get('/setup')
        self.setup()
        self.assertEqual(self.post(other,'/setup',{'username':'second','password':PASSWORD,'confirm_password':PASSWORD}).status_code,410)
        with projects.registry() as c:self.assertEqual(c.execute('SELECT count(*) FROM users').fetchone()[0],1)

    def test_parallel_setup_cannot_create_two_administrators(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        second=self.client();self.admin.get('/setup');second.get('/setup')
        barrier=Barrier(2)
        def submit(client):
            barrier.wait()
            return self.post(client,'/setup',{'username':'owner' if client is self.admin else 'second','password':PASSWORD,'confirm_password':PASSWORD}).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            codes=list(pool.map(submit,[self.admin,second]))
        self.assertEqual(codes.count(303),1,codes)
        self.assertTrue(all(code in (303,403,409,410) for code in codes),codes)
        with projects.registry() as c:
            self.assertEqual(c.execute("SELECT count(*) FROM users WHERE role='administrator'").fetchone()[0],1)



class AuthorizationTests(AuthFixture):
    def setUp(self):super().setUp();self.setup()

    def test_all_project_routes_are_guarded_before_history_access(self):
        anonymous=self.client()
        with patch.object(projects,'list_projects',side_effect=AssertionError('Unauthorized enumeration')):
            for path in access.PROJECT_READ:
                r=anonymous.get(path,follow_redirects=False)
                self.assertEqual(r.status_code,401 if path.startswith('/api/') else 303,path)
            for path in access.PROJECT_ADMIN|access.PROJECT_WRITE|access.GLOBAL_WRITE|access.PROJECT_RESTORE:
                self.assertEqual(anonymous.post(path).status_code,401,path)
        self.assertEqual(anonymous.get('/docs',follow_redirects=False).status_code,404)
        self.assertEqual(anonymous.get('/openapi.json').status_code,404)
        for route in app.routes:
            if hasattr(route,'methods'):
                for method in route.methods:self.assertTrue(access.known(route.path,method),(route.path,method))

    def test_viewer_isolation_every_read_and_write_and_forged_ids(self):
        first,p=self.project('visible');second,q=self.project('hidden')
        uid=self.create_user();self.grant(uid,first)
        reader=self.client();self.signin(reader,'reader',USER_PASSWORD)
        for path in access.PROJECT_READ:
            if path=='/file':params={'snapshot_id':1,'path':'code.py'}
            elif path=='/logs/view':continue
            elif path=='/backups/download':params={'id':1}
            else:params={}
            r=reader.get(path,params={'project_id':second,**params},follow_redirects=False)
            self.assertEqual(r.status_code,404,path)
        page=reader.get('/?project_id='+str(first)).text
        self.assertNotIn(str(q),page);self.assertNotIn('PRIVATE_hidden',page)
        self.assertNotIn('/projects/add',page);self.assertNotIn('/actions/analyze',page)
        for path in access.PROJECT_WRITE|access.PROJECT_ADMIN|access.GLOBAL_WRITE|access.PROJECT_RESTORE:
            if path in {'/logout','/account/update','/account/revoke','/account/preferences'}:continue
            r=self.post(reader,path,{'project_id':first,'user_id':1,'role':'administrator'})
            self.assertEqual(r.status_code,403,path)
        r=reader.get('/api/status',params={'project_id':first,'user_id':1,'role':'administrator'},headers={'x-user-id':'1','x-role':'administrator'})
        self.assertEqual(r.status_code,200)
        self.assertEqual(self.user_row(uid)['role'],'viewer')

    def test_operator_backup_analysis_assigned_only_and_restore_permission(self):
        first,p=self.project('visible');second,q=self.project('hidden')
        uid=self.create_user('operator','operator');self.grant(uid,first)
        operator=self.client();self.signin(operator,'operator',USER_PASSWORD)
        for path in ('/actions/analyze','/actions/backup'):
            self.assertEqual(self.post(operator,path+'?project_id='+str(first)).status_code,303)
            self.assertEqual(self.post(operator,path+'?project_id='+str(second)).status_code,404)
        from app import jobs
        # New backup control queues durable work; execute it deterministically in this test.
        for row in reversed(jobs.job_rows(first)):
            if row['state']=='queued':jobs.execute(row['id'])
        self.assertEqual(operator.get(f'/backups/download?project_id={first}&id=1').status_code,200)
        principal=auth.session(operator.cookies.get(auth.COOKIE))
        self.assertFalse(auth.can_restore(principal,first))
        self.grant(uid,first,restore=True)
        self.assertFalse(auth.can_restore(principal,first))
        self.assertEqual(operator.get('/api/status?project_id='+str(first)).status_code,401)
        self.signin(operator,'operator',USER_PASSWORD)
        self.assertTrue(auth.can_restore(auth.session(operator.cookies.get(auth.COOKIE)),first))
        self.assertEqual(self.post(operator,'/restore',{'project_id':first}).status_code,404)

    def test_csrf_origin_and_session_binding_cover_every_write(self):
        pid,p=self.project('visible')
        for path in access.GLOBAL_WRITE|access.PROJECT_ADMIN|access.PROJECT_WRITE|access.PROJECT_RESTORE|{'/login'}:
            self.assertEqual(self.admin.post(path,data={'project_id':pid},follow_redirects=False).status_code,403,path)
        other=self.client();self.signin(other)
        foreign=self.admin.cookies.get('ptm_csrf')
        other.cookies.set('ptm_csrf',foreign,domain='127.0.0.1',path='/')
        self.assertEqual(other.post('/logout',data={'csrf_token':foreign}).status_code,403)
        self.assertEqual(self.admin.post('/logout',data={'csrf_token':self.admin.cookies.get('ptm_csrf')},headers={'origin':'http://evil.invalid'}).status_code,403)
        self.assertEqual(self.admin.post('/logout',data={'csrf_token':'я'*64}).status_code,403)
        self.assertEqual(self.post(self.admin,'/logout').status_code,303)

    def test_session_rotation_digest_storage_logout_and_expiry(self):
        user=self.client();user.get('/login');old=user.cookies.get(auth.COOKIE)
        self.signin(user)
        raw=user.cookies.get(auth.COOKIE);self.assertNotEqual(old,raw)
        with projects.registry() as c:
            self.assertIsNone(c.execute('SELECT 1 FROM sessions WHERE digest=?',(raw,)).fetchone())
            self.assertTrue(c.execute('SELECT 1 FROM sessions WHERE digest=?',(hashlib.sha256(raw.encode()).hexdigest(),)).fetchone())
            c.execute('UPDATE sessions SET last_seen=? WHERE digest=?',(time.time()-self.cfg.session_idle_seconds-1,auth.digest(raw)))
        self.assertEqual(user.get('/api/status').status_code,401)
        self.signin(user)
        with projects.registry() as c:c.execute('UPDATE sessions SET expires_at=? WHERE digest=?',(time.time()-1,auth.digest(user.cookies.get(auth.COOKIE))))
        self.assertEqual(user.get('/api/status').status_code,401)
        self.signin(user);raw=user.cookies.get(auth.COOKIE)
        self.assertEqual(self.post(user,'/logout').status_code,303)
        self.assertIsNone(auth.session(raw));self.assertIsNone(user.cookies.get(auth.COOKIE))

    def test_admin_disable_reset_role_and_acl_revoke_sessions(self):
        pid,p=self.project('visible');uid=self.create_user();self.grant(uid,pid)
        user=self.client();self.signin(user,'reader',USER_PASSWORD)
        self.assertEqual(user.get('/api/status?project_id='+str(pid)).status_code,200)
        row=self.user_row(uid)
        r=self.post(self.admin,'/admin/users/update',{'user_id':uid,'username':'reader','role':'operator','enabled':'off','version':row['auth_version'],'current_password':PASSWORD})
        self.assertEqual(r.status_code,303,r.text)
        with projects.registry() as c:
            details=json.loads(c.execute("SELECT details FROM user_audit WHERE event='user_updated' ORDER BY id DESC LIMIT 1").fetchone()[0])
            self.assertEqual(details['old_role'],'viewer');self.assertEqual(details['new_role'],'operator')
            self.assertFalse(details['new_enabled'])
        self.assertEqual(user.get('/api/status?project_id='+str(pid)).status_code,401)
        user.get('/login');self.assertEqual(self.post(user,'/login',{'username':'reader','password':USER_PASSWORD}).status_code,401)
        row=self.user_row(uid)
        self.assertEqual(self.post(self.admin,'/admin/users/update',{'user_id':uid,'username':'reader','role':'operator','enabled':'on','version':row['auth_version'],'current_password':PASSWORD}).status_code,303)
        self.signin(user,'reader',USER_PASSWORD)
        self.assertEqual(self.post(self.admin,'/admin/users/reset',{'user_id':uid,'new_password':'New-user-password-2026','current_password':PASSWORD}).status_code,303)
        self.assertEqual(user.get('/api/status').status_code,401)
        self.signin(user,'reader','New-user-password-2026')
        self.assertEqual(self.post(self.admin,'/admin/access',{'user_id':uid,'project_id':pid,'current_password':PASSWORD}).status_code,303)
        self.assertEqual(user.get('/api/status?project_id='+str(pid)).status_code,401)
        self.signin(user,'reader','New-user-password-2026')
        self.assertEqual(user.get('/api/status?project_id='+str(pid)).status_code,404)

    def test_last_admin_optimistic_version_and_reauthentication(self):
        row=self.user_row(1)
        payload={'user_id':1,'username':'owner','role':'viewer','enabled':'on','version':row['auth_version'],'current_password':PASSWORD}
        self.assertEqual(self.post(self.admin,'/admin/users/update',payload).status_code,409)
        self.assertEqual(self.post(self.admin,'/admin/users/update',{**payload,'role':'administrator','version':999}).status_code,409)
        self.assertEqual(self.post(self.admin,'/admin/network',{'enabled':'on','current_password':'wrong-password'}).status_code,403)
        self.assertEqual(auth.state()['network_enabled'],0)
        self.assertEqual(self.user_row(1)['role'],'administrator')

    def test_profile_uses_session_identity_changes_login_password_and_language(self):
        uid=self.create_user();user=self.client();self.signin(user,'reader',USER_PASSWORD,'pl')
        self.assertEqual(self.user_row(uid)['language'],'pl')
        r=self.post(user,'/account/update',{'user_id':1,'role':'administrator','username':'newreader','current_password':USER_PASSWORD,'new_password':'New-reader-password-2026','language':'uk'})
        self.assertEqual(r.status_code,303,r.text)
        self.assertEqual(user.get('/account',follow_redirects=False).status_code,303)
        self.assertEqual(self.user_row(1)['username'],'owner')
        self.assertEqual(self.user_row(uid)['role'],'viewer')
        self.assertEqual(self.user_row(uid)['language'],'uk')
        self.signin(user,'newreader','New-reader-password-2026','uk')
        self.assertEqual(user.get('/account').status_code,200)

    def test_login_limit_persists_across_clients_and_window(self):
        limited=replace(self.cfg,login_attempt_limit=3)
        with patch.object(projects,'base_settings',limited):
            user=self.client();user.get('/login')
            for _ in range(3):self.assertEqual(self.post(user,'/login',{'username':'owner','password':'bad-password'}).status_code,401)
            other=self.client();other.get('/login')
            self.assertEqual(self.post(other,'/login',{'username':'owner','password':PASSWORD}).status_code,429)
            future=time.time()+limited.login_window_seconds+1
            with patch('app.auth.time.time',return_value=future):
                self.assertEqual(self.post(other,'/login',{'username':'owner','password':PASSWORD}).status_code,303)
        self.assertEqual(self.post(self.admin,'/login',{'username':'юзер','password':'anything'}).status_code,401)

    def test_network_enable_is_explicit_https_cookies_and_proxy_header_safety(self):
        remote=self.client('https://192.168.1.10:13011','192.168.1.7')
        self.assertEqual(remote.get('/login').status_code,403)
        self.assertEqual(self.post(self.admin,'/admin/network',{'enabled':'on','current_password':PASSWORD}).status_code,303)
        plain=self.client('http://192.168.1.10:13011','192.168.1.7')
        self.assertEqual(plain.get('/login').status_code,403)
        response=remote.get('/login')
        self.assertIn('Secure',response.headers['set-cookie']);self.assertIn('HttpOnly',response.headers['set-cookie']);self.assertIn('SameSite=strict',response.headers['set-cookie'])
        self.signin(remote)
        self.assertEqual(remote.get('/account').status_code,200)
        raw=remote.cookies.get(auth.COOKIE)
        self.assertEqual(self.post(self.admin,'/admin/network',{'current_password':PASSWORD}).status_code,303)
        self.assertEqual(remote.get('/account').status_code,403)
        self.assertIsNone(auth.session(raw))
        self.assertEqual(self.admin.get('/login',headers={'x-forwarded-for':'192.168.1.7'}).status_code,403)

    def test_self_revoke_cannot_target_another_user_and_admin_can_revoke(self):
        uid=self.create_user();user=self.client();self.signin(user,'reader',USER_PASSWORD)
        own=auth.session(user.cookies.get(auth.COOKIE));owner=auth.session(self.admin.cookies.get(auth.COOKIE))
        self.assertEqual(self.post(user,'/account/revoke',{'session_id':owner['session_id']}).status_code,404)
        self.assertIsNotNone(auth.session(self.admin.cookies.get(auth.COOKIE)))
        self.assertEqual(self.post(self.admin,'/admin/sessions/revoke',{'session_id':own['session_id'],'current_password':PASSWORD}).status_code,303)
        self.assertEqual(user.get('/api/status').status_code,401)

    def test_no_password_or_session_token_in_audit_or_admin_html(self):
        raw=self.admin.cookies.get(auth.COOKIE)
        uid=self.create_user();user=self.client();self.signin(user,'reader',USER_PASSWORD)
        data=self.admin.get('/admin/users');self.assertEqual(data.status_code,200,data.text)
        with projects.registry() as c:
            text=json.dumps([tuple(r) for r in c.execute('SELECT * FROM user_audit')])
        for secret in [PASSWORD,USER_PASSWORD,raw,user.cookies.get(auth.COOKIE),'$argon2id$']:
            self.assertNotIn(secret,data.text);self.assertNotIn(secret,text)
        with projects.registry() as c:
            actions=[r[0] for r in c.execute('SELECT event FROM user_audit')]
        self.assertIn('login_success',actions);self.assertIn('user_created',actions)
        # Validation responses must not echo arbitrary input fields or URLs.
        response=self.post(self.admin,'/admin/users/update?password='+PASSWORD,{'user_id':USER_PASSWORD})
        self.assertEqual(response.status_code,422)
        self.assertNotIn(PASSWORD,response.text);self.assertNotIn(USER_PASSWORD,response.text)

    def test_state_survives_reconnect_and_migration_preserves_projects(self):
        pid,p=self.project('visible');uid=self.create_user();self.grant(uid,pid)
        before=projects.get_project(pid)
        path=self.cfg.data_dir/'projects.sqlite'
        with sqlite3.connect(path) as c:
            self.assertEqual(c.execute('PRAGMA user_version').fetchone()[0],migrations.MIGRATIONS['registry'][-1][0])
        migrations.migrate(path,'registry',self.cfg.migrations_dir)
        self.assertEqual(projects.get_project(pid),before)
        fresh=self.client();self.signin(fresh,'reader',USER_PASSWORD)
        self.assertEqual(fresh.get('/api/status?project_id='+str(pid)).status_code,200)

    def test_revoked_principal_cannot_execute_an_admin_mutation_after_reauth(self):
        self.create_user('secondadmin','administrator')
        principal=auth.session(self.admin.cookies.get(auth.COOKIE))
        with projects.registry() as c:
            c.execute("UPDATE users SET role='operator',auth_version=auth_version+1 WHERE id=1")
        with patch.object(auth,'_reauth',return_value=principal):
            with self.assertRaises(auth.AuthError) as error:
                auth.network(principal['digest'],PASSWORD,'127.0.0.1',True)
            self.assertEqual(error.exception.status,401)
        self.assertEqual(auth.state()['network_enabled'],0)
        self.assertFalse(auth.can_restore(principal,1))

    def test_large_request_is_rejected_before_form_or_operation(self):
        result=self.admin.post('/account/update',data={'csrf_token':self.admin.cookies.get('ptm_csrf'),'payload':'x'*70000})
        self.assertEqual(result.status_code,413)
        self.assertEqual(self.user_row(1)['username'],'owner')

    def test_launcher_allows_bind_without_bypassing_http_network_policy(self):
        import runpy
        import uvicorn
        with patch.dict('os.environ',{'PTM_HOST':'0.0.0.0'}),patch.object(uvicorn,'run') as serve:
            runpy.run_module('app',run_name='__main__')
            self.assertEqual(serve.call_args.kwargs['host'],'0.0.0.0')
        self.assertEqual(auth.state()['network_enabled'],0)
        self.assertEqual(self.client(host='https://192.168.1.2:13011',peer='192.168.1.4').get('/login').status_code,403)
        self.assertEqual(self.post(self.admin,'/admin/network',{'enabled':'on','current_password':PASSWORD}).status_code,303)
        with patch.dict('os.environ',{'PTM_HOST':'127.0.0.1','PTM_PORT':'13011'}),patch.object(uvicorn,'run') as serve:
            runpy.run_module('app',run_name='__main__')
            self.assertEqual(serve.call_args.kwargs['host'],'127.0.0.1')
            self.assertFalse(serve.call_args.kwargs['proxy_headers'])
            self.assertFalse(serve.call_args.kwargs['access_log'])

    def test_stage1_registry_upgrade_preserves_all_project_columns(self):
        self.skipTest("Private historical database fixtures are not distributed")

    def test_internal_error_and_failed_operations_do_not_disclose_credentials(self):
        pid,p=self.project('visible')
        with patch('app.services.run_analysis',side_effect=RuntimeError(PASSWORD)):
            with self.assertLogs('ptm',level='ERROR') as logs:
                response=self.post(self.admin,'/actions/analyze?project_id='+str(pid))
            self.assertEqual(response.status_code,500)
            self.assertIn('PTM_INTERNAL_ERROR',response.text)
            self.assertNotIn(PASSWORD,response.text)
            self.assertNotIn(PASSWORD,' '.join(logs.output))
        with projects.registry() as c:
            actions=[r[0] for r in c.execute('SELECT event FROM user_audit')]
        self.assertIn('actions_analyze_started',actions)
        self.assertIn('actions_analyze_failed',actions)
