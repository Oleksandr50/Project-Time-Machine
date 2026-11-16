import hashlib
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import os
from pathlib import Path
from html.parser import HTMLParser
from unittest.mock import patch
import unittest
import test_stage2 as stage2
from app import i18n,projects,auth,db,migrations
from app.ui import safe_return


class TextOnly(HTMLParser):
    def __init__(self):super().__init__();self.text=[]
    def handle_data(self,text):self.text.append(text)


def visible(html):
    parser=TextOnly();parser.feed(html);return ''.join(parser.text)


class InterfaceTests(stage2.AuthFixture):
    def setUp(self):super().setUp();self.setup()

    def pref(self,locale='en',theme='dark',scale=100,return_to='/settings'):
        result=self.post(self.admin,'/account/preferences',dict(locale=locale,theme=theme,scale=scale,return_to=return_to))
        self.assertEqual(result.status_code,303,result.text);return result

    def test_all_catalog_keys_and_placeholders_have_four_translations(self):
        self.assertEqual(set(i18n.CATALOGS),{'ru','en','pl','uk'})
        for code,catalog in i18n.CATALOGS.items():
            self.assertEqual(set(catalog),set(i18n.CATALOGS['en']))
            for key,value in catalog.items():
                self.assertTrue(value.strip(),(code,key))
                self.assertEqual(i18n.placeholders(value),i18n.placeholders(i18n.CATALOGS['en'][key]),(code,key))

    def test_all_screens_render_in_each_language_without_missing_keys(self):
        pid,path=self.project('sample')
        pages=['/','/projects','/snapshots','/timeline','/compare','/files','/functions','/audit','/backups','/restore','/logs','/sqlite','/settings','/account','/admin/users','/admin/users?section=sessions','/admin/users?section=history','/admin/users?section=network']
        for locale in i18n.LANGUAGES:
            self.pref(locale)
            for page in pages:
                with self.subTest(locale=locale,page=page):
                    response=self.admin.get(page)
                    self.assertEqual(response.status_code,200,response.text[:300])
                    self.assertIn(f'<html lang="{locale}"',response.text)
                    self.assertEqual(response.headers['content-language'],locale)
                    self.assertNotRegex(visible(response.text),r'\b(?:nav|common|settings|error|message)\.[a-z_]+')
                    if locale!='ru':self.assertNotRegex(visible(response.text),r'[ЫыЭэЪъ]')

    def test_profile_preferences_are_persistent_scoped_and_csrf_guarded(self):
        raw=self.admin.cookies.get(auth.COOKIE)
        result=self.pref('uk','light',140,'/snapshots?project_id=1&page=2')
        self.assertEqual(result.headers['location'],'/snapshots?project_id=1&page=2')
        current=auth.session(raw)
        self.assertEqual((current['language'],current['theme'],current['scale']),('uk','light',140))
        self.assertEqual(self.user_row(1)['language'],'uk')
        self.assertEqual(self.admin.post('/account/preferences',data={'locale':'en','theme':'dark','scale':100}).status_code,403)
        self.assertEqual(self.post(self.admin,'/account/preferences',{'locale':'evil','theme':'dark','scale':100}).status_code,400)
        self.assertEqual(self.post(self.admin,'/account/preferences',{'locale':'en','theme':'evil','scale':100}).status_code,400)
        self.assertEqual(self.post(self.admin,'/account/preferences',{'locale':'en','theme':'light','scale':9000}).status_code,400)
        self.assertEqual(auth.session(raw)['scale'],140)
        uid=self.create_user('viewer','viewer');reader=self.client();self.signin(reader,'viewer',stage2.USER_PASSWORD)
        r=self.post(reader,'/account/preferences',{'user_id':1,'role':'administrator','locale':'pl','theme':'dark','scale':110})
        self.assertEqual(r.status_code,303)
        self.assertEqual(auth.session(raw)['language'],'uk')
        self.assertEqual(self.user_row(uid)['role'],'viewer')

    def test_login_browser_language_and_error_language(self):
        guest=self.client()
        response=guest.get('/login',headers={'accept-language':'de;q=1,pl-PL;q=0.9,en;q=0.7'})
        self.assertIn('<html lang="pl"',response.text)
        self.assertEqual(response.headers['referrer-policy'],'same-origin')
        response=self.post(guest,'/login',{'username':'nobody','password':'wrong-password','language':'en'})
        self.assertEqual(response.status_code,401)
        self.assertIn('Incorrect username or password',visible(response.text))
        response=guest.get('/api/status',headers={'accept':'application/json','accept-language':'en'})
        self.assertEqual(response.status_code,401)
        self.assertEqual(response.json()['error']['message'],'Sign in required')

    def test_full_sql_pagination_sort_search_and_unsafe_identifiers(self):
        pid,path=self.project('sample');cfg=projects.project_settings(projects.get_project(pid))
        with sqlite3.connect(cfg.db_path) as c:
            for n in range(300):
                c.execute('INSERT INTO snapshots(created_at,description,agent_root,total_files,python_files,total_bytes,functions_count,classes_count,sqlite_files,log_files,project_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                    ('2026-11-10T12:00:00',f'checkpoint-{n:03d}',str(path),1,1,12,1,0,0,0,pid))
        self.pref()
        r=self.admin.get(f'/snapshots?project_id={pid}&per_page=10&page=21&sort=id&order=asc')
        self.assertEqual(r.status_code,200,r.text[:200]);self.assertIn('Page 21 of 31',visible(r.text))
        self.assertEqual(len(re.findall(r'<tr>',r.text.split('<tbody>')[1].split('</tbody>')[0])),10)
        r=self.admin.get(f'/snapshots?project_id={pid}&q=checkpoint-299')
        self.assertIn('checkpoint-299',r.text);self.assertIn('Total: 1',visible(r.text))
        r=self.admin.get(f'/snapshots?project_id={pid}&sort=id DESC; DROP TABLE snapshots')
        self.assertEqual(r.status_code,400);self.assertIn('Invalid table parameters',visible(r.text))
        self.assertEqual(self.admin.get(f'/snapshots?project_id={pid}&columns=evil').status_code,400)
        self.assertEqual(self.admin.get(f'/snapshots?project_id={pid}&per_page=999').status_code,400)
        with sqlite3.connect(cfg.db_path) as c:self.assertEqual(c.execute('SELECT count(*) FROM snapshots').fetchone()[0],301)

    def test_file_rows_long_paths_short_hashes_and_older_snapshot_picker(self):
        pid,path=self.project('sample')
        long_name='component_'+'long_'*30+'.py';(path/long_name).write_text('def sample():\n    return 123\n')
        self.assertEqual(self.post(self.admin,f'/actions/analyze?project_id={pid}').status_code,303)
        self.pref()
        response=self.admin.get(f'/files?project_id={pid}&q=component_')
        self.assertEqual(response.status_code,200,response.text[:200])
        digest=hashlib.sha256((path/long_name).read_bytes()).hexdigest()
        self.assertIn('data-copy="'+digest+'"',response.text)
        self.assertNotIn(digest,visible(response.text));self.assertNotIn(long_name,visible(response.text))
        self.assertIn('project_id='+str(pid),response.text)
        self.assertEqual(self.admin.get(f'/file?project_id={pid}&snapshot_id=1&path=code.py').status_code,200)

    def test_dashboard_aggregates_only_assigned_projects_and_keeps_history_read_only(self):
        first,p=self.project('visible');second,q=self.project('hidden')
        uid=self.create_user();self.grant(uid,first)
        reader=self.client();self.signin(reader,'reader',stage2.USER_PASSWORD,'en')
        before={cfg.db_path:cfg.db_path.read_bytes() for cfg in [projects.project_settings(projects.get_project(first)),projects.project_settings(projects.get_project(second))]}
        response=reader.get('/')
        self.assertEqual(response.status_code,200)
        self.assertNotIn(str(q),response.text);self.assertNotIn('PRIVATE_hidden',response.text)
        self.assertNotIn('project_id='+str(second)+'"',response.text)
        for path,digest in before.items():self.assertEqual(path.read_bytes(),digest)
        for route in ['/projects','/restore','/compare/text']:
            self.assertEqual(reader.get(route,params={'project_id':second}).status_code,404)
        self.assertEqual(reader.get('/settings').status_code,200)

    def test_restore_requires_preview_and_has_no_direct_write_route(self):
        pid,path=self.project('sample');self.pref()
        response=self.admin.get(f'/restore?project_id={pid}')
        self.assertEqual(response.status_code,200)
        self.assertIn('Restore starts with point verification',visible(response.text))
        self.assertIn('action="/restore/preview?project_id=',response.text)
        self.assertRegex(response.text,r'<button[^>]*disabled')
        self.assertEqual(self.post(self.admin,'/restore',{'project_id':pid}).status_code,404)

    def test_saved_content_diff_integrity_redaction_and_legacy_absence(self):
        pid,path=self.project('sample');self.pref()
        original=(path/'code.py').read_bytes()
        (path/'code.py').write_text('def sample():\n    password="test-inline-secret"\n    return "<script>unsafe</script>"\n')
        self.post(self.admin,f'/actions/analyze?project_id={pid}')
        endpoint=f'/compare/text?project_id={pid}&a=1&b=2&path=code.py'
        response=self.admin.get(endpoint)
        self.assertIn('No saved content',visible(response.text))
        self.assertNotIn('test-inline-secret',response.text)
        cfg=projects.project_settings(projects.get_project(pid));cfg.content_dir.mkdir()
        with sqlite3.connect(cfg.db_path) as c:
            for sid,data in [(1,original),(2,(path/'code.py').read_bytes())]:
                digest=hashlib.sha256(data).hexdigest();(cfg.content_dir/digest).write_bytes(data)
                c.execute('INSERT INTO content_objects VALUES(?,?,?,?)',(digest,len(data),digest,'2026-11-10T00:00:00Z'))
                c.execute('INSERT INTO snapshot_content VALUES(?,?,?)',(sid,'code.py',digest))
        response=self.admin.get(endpoint)
        self.assertEqual(response.status_code,200)
        self.assertIn('diff-line add',response.text);self.assertIn('diff-line del',response.text)
        self.assertNotIn('test-inline-secret',response.text);self.assertIn('[REDACTED]',response.text)
        self.assertNotIn('<script>unsafe</script>',response.text);self.assertIn('&lt;script&gt;unsafe&lt;/script&gt;',response.text)
        (cfg.content_dir/hashlib.sha256(original).hexdigest()).write_bytes(b'damaged')
        response=self.admin.get(endpoint)
        self.assertIn('failed integrity verification',visible(response.text))
        self.assertNotIn('diff-line add',response.text)
        self.assertEqual(self.admin.get(f'/compare/text?project_id={pid}&a=1&b=2&path=../private').status_code,400)

    def test_preferences_return_url_cannot_redirect_to_another_origin(self):
        for bad in ['https://evil.invalid','//evil.invalid','/\\evil.invalid','javascript:alert(1)']:
            self.assertEqual(safe_return(bad),'/')
            self.assertEqual(self.pref(return_to=bad).headers['location'],'/')
        self.assertEqual(safe_return('/files?password=secret&project_id=1'),'/files?project_id=1')

    def test_additional_catalog_does_not_require_app_logic_or_schema_changes(self):
        target=self.root/'clone';shutil.copytree(Path(__file__).resolve().parents[1]/'app',target/'app',ignore=shutil.ignore_patterns('__pycache__'))
        catalog=json.loads((target/'app/locales/en.json').read_text());catalog['language_name']='Test language'
        (target/'app/locales/zz.json').write_text(json.dumps(catalog))
        cfg=self.root/'locale-test.json';cfg.write_text(json.dumps({'data_dir':str(self.root/'fifth-state'),'migrations_dir':str(self.root/'fifth-backups')}))
        code='''import os,sys,json
sys.path[1:1]=os.environ['PTM_TEST_DEPS'].split(os.pathsep)
from app import auth,i18n
assert 'zz' in i18n.CATALOGS
raw=auth.anonymous('127.0.0.1')
raw=auth.bootstrap(auth.digest(raw),'testuser','temporary-language-password','127.0.0.1','zz')
assert auth.session(raw)['language']=='zz'
print('fifth-locale-ok')'''
        env={**os.environ,'PTM_CONFIG':str(cfg)}
        result=subprocess.run([sys.executable,'-B','-c',code],cwd=target,env=env,capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('fifth-locale-ok',result.stdout)

    def test_registry_v3_preserves_existing_users_sessions_acl_and_data(self):
        target=self.root/'previous/projects.sqlite';target.parent.mkdir()
        old_steps=migrations.MIGRATIONS['registry'][:2]
        with patch.dict(migrations.MIGRATIONS,{'registry':old_steps}):migrations.migrate(target,'registry',self.root/'previous-backups')
        raw='A'*43;now=__import__('time').time()
        hashed=auth.password_hash('synthetic-migration-password')
        with sqlite3.connect(target) as c:
            c.execute("INSERT INTO projects(id,path,enabled) VALUES(42,'/synthetic-not-a-real-project',1)")
            c.execute('INSERT INTO users VALUES(7,?,?,?,?,?,?,?,?)',('previous',hashed,'viewer',1,5,'pl','2026-11-10','2026-11-10'))
            c.execute('INSERT INTO sessions(digest,user_id,user_version,created_at,last_seen,expires_at,peer) VALUES(?,?,?,?,?,?,?)',(auth.digest(raw),7,5,now,now,now+3600,'127.0.0.1'))
            c.execute('INSERT INTO project_access VALUES(7,42,0)')
            c.execute('UPDATE auth_settings SET setup_completed=1')
            tables=[r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('schema_info','schema_migrations')")]
            before={t:c.execute('SELECT * FROM "'+t+'" ORDER BY rowid').fetchall() for t in tables}
        migrations.migrate(target,'registry',self.root/'previous-backups')
        with sqlite3.connect(target) as c:
            self.assertEqual(c.execute('PRAGMA user_version').fetchone()[0],migrations.MIGRATIONS['registry'][-1][0])
            self.assertEqual(c.execute('SELECT * FROM user_preferences').fetchall(),[(7,'pl','system',100)])
            for table,rows in before.items():self.assertEqual(c.execute('SELECT * FROM "'+table+'" ORDER BY rowid').fetchall(),rows,table)
        with patch.object(projects,'base_settings',__import__('dataclasses').replace(self.cfg,data_dir=target.parent)):
            principal=auth.session(raw)
            self.assertEqual((principal['user_id'],principal['language'],principal['role']),(7,'pl','viewer'))
        backups=list((self.root/'previous-backups').glob('*.sqlite'))
        migrations.migrate(target,'registry',self.root/'previous-backups')
        self.assertEqual(list((self.root/'previous-backups').glob('*.sqlite')),backups)
