"""Analysis/audit/data inspection integration only against disposable projects."""
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch
import test_stage2 as stage2
from app import analyzer,projects,db,services,audit_service,analysis_plugins,data_views,migrations,auth,backups
from app.audit_rules import inspect_tree,deduplicate
from app.redaction import redact


class StageSixTests(stage2.AuthFixture):
    def setUp(self):
        super().setUp();self.setup();self.pid,self.source=self.project('sample')
        self.cfg=projects.project_settings(projects.get_project(self.pid));self.selected=projects.current_settings.set(self.cfg)
    def tearDown(self):
        projects.current_settings.reset(self.selected);super().tearDown()
    def analyze(self,source):
        (self.source/'code.py').write_text(source)
        return services.run_analysis()['snapshot_id']
    def findings(self,sid):
        with db.db_conn() as c:
            audit_service.view(c)
            return [dict(r) for r in c.execute('SELECT * FROM audit_view WHERE snapshot_id=?',(sid,))]
    def url(self,endpoint,**params):
        from urllib.parse import urlencode
        return endpoint+'?'+urlencode(dict(project_id=self.pid,**params))
    def source_hashes(self):return {p.relative_to(self.source).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in self.source.rglob('*') if p.is_file()}

    def test_python_qualified_names_and_risk_do_not_leak_between_siblings(self):
        sid=self.analyze('import os\nclass A:\n def dangerous(self):\n  os.system("echo x")\nclass B:\n def safe(self):\n  return 1\ndef top():\n def nested():\n  return 2\n return nested()\n')
        with db.db_conn() as c:rows={r['qualname']:r['risk_level'] for r in c.execute('SELECT * FROM python_entities WHERE snapshot_id=?',(sid,))}
        self.assertEqual(set(rows),{'A','A.dangerous','B','B.safe','top','top.nested'})
        self.assertEqual(rows['A.dangerous'],'red');self.assertEqual(rows['B.safe'],'green');self.assertEqual(rows['top'],'green')

    def test_ast_timeout_is_per_call_ignores_comments_and_resolves_basic_import_aliases(self):
        sid=self.analyze('import requests as rq\nfrom subprocess import run\n# os.system("comment")\nx="shell=True"\nrq.get("a",timeout=2)\nrq.get("b")\nrun(["echo"],shell=False)\nrun("echo",shell=True)\n')
        rows=self.findings(sid)
        self.assertEqual({(r['rule_id'],r['lineno']) for r in rows},{('python.timeout',6),('python.shell',8)})
        self.assertTrue(all(r['why'] and r['fix'] for r in rows))

    def test_dedup_and_fingerprint_survive_line_shift(self):
        text='import os\nos.system("echo x")\nos.system("echo x")\n'
        first=self.analyze(text);second=self.analyze('\n\n'+text)
        a=self.findings(first);b=self.findings(second)
        self.assertEqual(len(a),1);self.assertEqual(a[0]['review_key'],b[0]['review_key'])
        with db.db_conn() as c:
            occ=json.loads(c.execute('SELECT occurrences FROM audit_findings WHERE snapshot_id=?',(first,)).fetchone()[0])
        self.assertEqual(occ,[2,3])
        self.assertEqual(self.admin.get(self.url('/audit/export',snapshot_id=second,baseline=first,new_only=1)).json()['findings'],[])

    def test_grouped_occurrences_keep_risk_on_each_actual_function(self):
        sid=self.analyze('import os\ndef first():\n os.system("echo")\ndef second():\n os.system("echo")\ndef safe():\n return 1\n')
        with db.db_conn() as c:risks={r[0]:r[1] for r in c.execute('SELECT name,risk_level FROM python_entities WHERE snapshot_id=?',(sid,))}
        self.assertEqual(risks,dict(first='red',second='red',safe='green'))
        self.assertEqual(len(self.findings(sid)),1)

    def test_new_only_categories_severity_and_false_positive_persist(self):
        first=self.analyze('import os\nos.system("echo")\n');key=self.findings(first)[0]['review_key']
        result=self.post(self.admin,self.url('/audit/review'),dict(snapshot_id=first,fingerprint=key,status='false_positive'))
        self.assertEqual(result.status_code,303,result.text)
        second=self.analyze('import os\nos.system("echo")\neval(value)\n')
        self.assertEqual(next(r for r in self.findings(second) if r['rule_id']=='python.shell')['review_status'],'false_positive')
        response=self.admin.get(self.url('/audit/export',snapshot_id=second,baseline=first,new_only=1,category='execution',kind='high'))
        self.assertEqual([r['rule_id'] for r in response.json()['findings']],['python.dynamic'])
        self.assertEqual(self.admin.get(self.url('/audit',snapshot_id=second,new_only=1)).status_code,400)
        self.assertEqual(self.post(self.admin,self.url('/audit/review'),dict(snapshot_id=first,fingerprint=key,status='open')).status_code,303)
        self.assertTrue(all(r['review_status']=='open' for r in self.findings(second)))

    def test_legacy_null_line_duplicates_dedup_without_changing_history(self):
        with db.db_conn() as c:
            for level in ('info','high'):c.execute('INSERT INTO audit_findings(snapshot_id,severity,category,path,lineno,message,evidence) VALUES(1,?,?,?,?,?,?)',(level,'http','old.py',None,'password="legacy-test-secret"','legacy raw retained'))
        self.assertEqual(len(self.findings(1)),1)
        self.assertEqual(self.findings(1)[0]['severity'],'high')
        response=self.admin.get(self.url('/audit/export',snapshot_id=1))
        self.assertEqual(response.status_code,200,response.text);self.assertNotIn('legacy-test-secret',response.text)
        self.assertIn('Историческая эвристика',self.admin.get(self.url('/audit',snapshot_id=1)).text)
        with db.db_conn() as c:self.assertEqual(c.execute('SELECT count(*) FROM audit_findings WHERE snapshot_id=1').fetchone()[0],2)

    def test_source_secrets_not_in_new_findings_entities_report_or_export(self):
        marker='synthetic-credential-88770011'
        sid=self.analyze('password="'+marker+'"\ndef f(password="'+marker+'"):\n return 1\n')
        with db.db_conn() as c:
            data=json.dumps([tuple(r) for r in c.execute('SELECT * FROM audit_findings WHERE snapshot_id=?',(sid,))])+json.dumps([tuple(r) for r in c.execute('SELECT * FROM python_entities WHERE snapshot_id=?',(sid,))])
        self.assertNotIn(marker,data)
        for route in ('/audit','/audit/export','/functions','/report'):
            response=self.admin.get(self.url(route,snapshot_id=sid));self.assertEqual(response.status_code,200,response.text);self.assertNotIn(marker,response.text)
        self.assertNotIn(marker,(self.cfg.reports_dir/'current_state.md').read_text())

    def test_archived_generated_dependencies_metrics_separate_and_history_preserved(self):
        for name in ('backups','build','node_modules'):
            (self.source/name).mkdir();(self.source/name/'copy.py').write_text('def duplicated():\n return 2\n')
        first=self.analyze('def active():\n return 1\n')
        with db.db_conn() as c:self.assertEqual(c.execute('SELECT functions_count FROM snapshots WHERE id=?',(first,)).fetchone()[0],1)
        projects.update_project(self.pid,'sample','','other',[],{'python_analysis':True,'analyze_archived':True,'analyze_generated':True,'analyze_dependencies':True})
        cfg=projects.project_settings(projects.get_project(self.pid));token=projects.current_settings.set(cfg)
        try:second=services.run_analysis()['snapshot_id']
        finally:projects.current_settings.reset(token)
        with db.db_conn() as c:
            m=json.loads(c.execute('SELECT category_metrics FROM snapshots WHERE id=?',(second,)).fetchone()[0]);self.assertEqual(set(m),{'active','archived','generated','dependencies'})
            self.assertTrue(all(x['functions']==1 for x in m.values()))
            self.assertEqual(c.execute('SELECT functions_count FROM snapshots WHERE id=?',(first,)).fetchone()[0],1)
        self.assertEqual(self.admin.get(self.url('/functions',snapshot_id=second,scope='archived')).status_code,200)

    def test_trusted_adapter_and_unsupported_language_keep_core_history(self):
        (self.source/'script.js').write_text('function hello() {}');(self.source/'other.php').write_text('<?php echo 1;')
        def adapter(path,rel):
            ent=analyzer.Entity(rel,'function','hello','hello',1,1,'()',None,[],[],[],'green',[])
            return [ent],[]
        with patch.dict(analysis_plugins._adapters):
            analysis_plugins.register(analysis_plugins.Adapter('test-js',('.js',),adapter))
            sid=services.run_analysis()['snapshot_id']
            with db.db_conn() as c:
                self.assertEqual(c.execute('SELECT analyzer_id FROM python_entities WHERE snapshot_id=? AND path=?',(sid,'script.js')).fetchone()[0],'test-js')
                info=json.loads(c.execute('SELECT analysis_info FROM snapshots WHERE id=?',(sid,)).fetchone()[0]);self.assertEqual(info['unsupported']['.php'],1)
            with self.assertRaises(ValueError):analysis_plugins.register(analysis_plugins.Adapter('other',('.js',),adapter))
        point=backups.create('full',actor_id=1);self.assertIn('other.php',[e['path'] for e in point['manifest']['files']])

    def test_failed_adapter_is_visible_without_exception_secret(self):
        (self.source/'input.zz').write_text('never executed')
        def broken(*_):raise RuntimeError('password="plugin-sensitive-value"')
        with patch.dict(analysis_plugins._adapters):
            analysis_plugins.register(analysis_plugins.Adapter('broken',('.zz',),broken));sid=services.run_analysis()['snapshot_id']
        response=self.admin.get(self.url('/audit/export',snapshot_id=sid))
        self.assertNotIn('plugin-sensitive-value',response.text);self.assertIn('python.plugin',response.text)

    def test_large_and_invalid_python_report_incomplete_analysis_without_affecting_backup(self):
        (self.source/'huge.py').write_bytes(b'#'+b'x'*(2*1024*1024))
        sid=self.analyze('def broken(:\n')
        self.assertEqual({x['rule_id'] for x in self.findings(sid)},{'python.limit','python.syntax'})
        self.assertEqual((self.source/'huge.py').stat().st_size,2*1024*1024+1)

    def test_log_search_levels_masking_copy_and_bounded_reads(self):
        path=self.source/'service.log';path.write_text('INFO old\n'+'x'*data_views.LOG_BYTES+'\nERROR password="log-sensitive-value"\nINFO ready\nWARNING retry\n')
        result=data_views.log_window(path,10,level='ERROR')
        self.assertTrue(result['truncated']);self.assertIn('[REDACTED]',result['content']);self.assertNotIn('log-sensitive-value',result['content'])
        self.assertEqual(data_views.log_window(path,10,query='log-sensitive-value')['matches'],0)
        response=self.admin.get(self.url('/logs/view',path=str(path),n=10,level='WARNING',log_q='retry'))
        self.assertEqual(response.status_code,200,response.text);self.assertIn('WARNING retry',response.text);self.assertIn('data-copy=',response.text)
        self.assertNotIn('log-sensitive-value',response.text)
        self.assertEqual(self.admin.get(self.url('/logs/view',path=str(path),n=2001)).status_code,400)

    def test_log_and_sqlite_direct_exclusion_symlink_traversal_cross_project(self):
        (self.source/'backups').mkdir();hidden=self.source/'backups/hidden.log';hidden.write_text('hidden value')
        outside=self.root/'outside.log';outside.write_text('outside value');(self.source/'link.log').symlink_to(outside)
        for value in (str(hidden),str(self.source/'link.log'),str(self.source/'../outside.log'),str(outside)):
            r=self.admin.get(self.url('/logs/view',path=value));self.assertIn(r.status_code,(400,404));self.assertNotIn('outside value',r.text)
        second,other=self.project('other');(other/'data.log').write_text('other private')
        self.assertEqual(self.admin.get(self.url('/logs/view',path=str(other/'data.log'))).status_code,400)

    def test_sqlite_readonly_wal_paginated_masked_and_no_source_writes(self):
        path=self.source/'records.sqlite';live=sqlite3.connect(path)
        try:
            live.execute('PRAGMA journal_mode=WAL');live.execute('PRAGMA wal_autocheckpoint=0')
            live.execute('CREATE TABLE records(id INTEGER, password TEXT, email TEXT, note TEXT, payload BLOB)')
            live.executemany('INSERT INTO records VALUES(?,?,?,?,?)',[(n,'db-sensitive-value','person@example.invalid','record-'+str(n),b'privateblob') for n in range(35)]);live.commit()
            before=self.source_hashes();result=data_views.sqlite_inspect(path,'records',2,10)
            self.assertEqual(len(result['rows']),10);self.assertEqual(result['rows'][0],['10','[REDACTED]','[REDACTED]','record-10','[BLOB]'])
            self.assertEqual((result['page'],result['pages'],result['total']),(2,4,35));self.assertEqual(before,self.source_hashes())
            response=self.admin.get(self.url('/sqlite',path=str(path),table='records',records_page=2,records_per_page=10))
            self.assertEqual(response.status_code,200,response.text);self.assertNotIn('db-sensitive-value',response.text);self.assertNotIn('person@example.invalid',response.text);self.assertNotIn('privateblob',response.text)
            self.assertEqual(before,self.source_hashes())
        finally:live.close()

    def test_sqlite_injection_views_virtual_and_generated_not_evaluated(self):
        path=self.source/'records.sqlite'
        with sqlite3.connect(path) as c:
            c.execute('CREATE TABLE "odd\""table" (id INTEGER, result TEXT GENERATED ALWAYS AS (id+1))')
            c.execute('INSERT INTO "odd\""table"(id) VALUES(1)')
            c.execute('CREATE VIEW danger AS SELECT load_extension("bad")')
            c.execute('CREATE VIRTUAL TABLE search USING fts5(content)')
        result=data_views.sqlite_inspect(path,'odd"table');self.assertEqual(result['columns'],['id'])
        names={x['name'] for x in result['tables']};self.assertNotIn('danger',names);self.assertNotIn('search',names)
        for table in ('danger','search','x; DROP TABLE records; --'):
            with self.assertRaisesRegex(ValueError,'inspection.table'):data_views.sqlite_inspect(path,table)
        self.assertEqual(self.admin.post(self.url('/sqlite'),data={'sql':'DELETE FROM records'}).status_code,404)

    def test_sqlite_size_result_and_time_limits(self):
        path=self.source/'records.sqlite'
        with sqlite3.connect(path) as c:
            c.execute('CREATE TABLE data(value TEXT)');c.executemany('INSERT INTO data VALUES(?)',[('a'*10000,)]*100)
        result=data_views.sqlite_inspect(path,'data',1,100);self.assertTrue(result['truncated']);self.assertLessEqual(sum(len(x.encode()) for row in result['rows'] for x in row),data_views.RESULT_BYTES)
        with patch.object(data_views,'SQLITE_BYTES',100):
            with self.assertRaisesRegex(ValueError,'inspection.size'):data_views.sqlite_inspect(path)
        with patch.object(data_views.time,'monotonic',side_effect=[0,10]):
            with self.assertRaisesRegex(ValueError,'inspection.timeout'):data_views.sqlite_inspect(path)

    def test_sqlite_key_value_records_and_sensitive_tables_are_masked(self):
        path=self.source/'records.sqlite'
        with sqlite3.connect(path) as c:
            c.execute('CREATE TABLE settings(name TEXT,value TEXT)');c.execute("INSERT INTO settings VALUES('access_token','opaque-sensitive-value')")
            c.execute('CREATE TABLE credentials(id INTEGER,value TEXT)');c.execute("INSERT INTO credentials VALUES(1,'opaque-private-value')")
        self.assertEqual(data_views.sqlite_inspect(path,'settings')['rows'],[['[REDACTED]','[REDACTED]']])
        self.assertEqual(data_views.sqlite_inspect(path,'credentials')['rows'],[['[REDACTED]','[REDACTED]']])

    def test_roles_csrf_project_isolation_and_review_actor_cannot_be_forged(self):
        sid=self.analyze('eval(value)\n');key=self.findings(sid)[0]['review_key']
        uid=self.create_user('reader','viewer');self.grant(uid,self.pid);viewer=self.client();self.signin(viewer,'reader',stage2.USER_PASSWORD)
        self.assertEqual(viewer.get(self.url('/audit/export',snapshot_id=sid)).status_code,200)
        self.assertEqual(self.post(viewer,self.url('/audit/review'),dict(snapshot_id=sid,fingerprint=key,status='false_positive')).status_code,403)
        self.assertEqual(self.admin.post(self.url('/audit/review'),data=dict(snapshot_id=sid,fingerprint=key,status='false_positive')).status_code,403)
        op=self.create_user('operator','operator');self.grant(op,self.pid);operator=self.client();self.signin(operator,'operator',stage2.USER_PASSWORD)
        self.assertEqual(self.post(operator,self.url('/audit/review'),dict(snapshot_id=sid,fingerprint=key,status='false_positive',user_id=1)).status_code,303)
        with db.db_conn() as c:self.assertEqual(c.execute('SELECT actor_id FROM audit_reviews').fetchone()[0],op)
        second,_=self.project('other')
        for route in ('/audit','/audit/export','/sqlite','/logs'):
            self.assertEqual(viewer.get(route,params={'project_id':second}).status_code,404)
        self.assertEqual(self.post(self.admin,self.url('/audit/review'),dict(snapshot_id=sid,fingerprint='0'*64,status='false_positive')).status_code,400)

    def test_four_languages_on_new_audit_analysis_log_sqlite_screens(self):
        sid=self.analyze('import requests\nrequests.get("url")\n')
        log=self.source/'service.log';log.write_text('ERROR password="masked-local-value"\n')
        path=self.source/'records.sqlite'
        with sqlite3.connect(path) as c:c.execute('CREATE TABLE data(password TEXT)');c.execute("INSERT INTO data VALUES('masked-db-value')")
        for locale in ('ru','en','pl','uk'):
            r=self.post(self.admin,'/account/preferences',dict(locale=locale,theme='dark',scale=100));self.assertEqual(r.status_code,303)
            for url in (self.url('/audit',snapshot_id=sid),self.url('/functions',snapshot_id=sid),self.url('/logs/view',path=str(log)),self.url('/sqlite',path=str(path),table='data')):
                r=self.admin.get(url);self.assertEqual(r.status_code,200,r.text);self.assertIn('<html lang="'+locale+'"',r.text);self.assertNotIn('rules.timeout.message',r.text);self.assertNotIn('masked-local-value',r.text);self.assertNotIn('masked-db-value',r.text)

    def test_authorization_headers_urls_and_partial_private_keys_masked(self):
        text='Authorization: Bearer synthetic-bearer-value\nurl=https://user:pass@example.invalid/\npassword="secret-value"\n-----BEGIN PRIVATE KEY-----\nabcdef'
        safe=redact(text)
        for marker in ('synthetic-bearer-value','user:pass','secret-value','abcdef'):self.assertNotIn(marker,safe)
        self.assertNotIn('unfinished-sensitive-value',redact('password="unfinished-sensitive-value'))

    def test_audit_resolved_and_persistent_filters_and_review_history(self):
        first=self.analyze('import os\nos.system("echo")\neval(data)\n')
        key=next(r['review_key'] for r in self.findings(first) if r['rule_id']=='python.shell')
        for status in ('false_positive','open'):
            self.assertEqual(self.post(self.admin,self.url('/audit/review'),dict(snapshot_id=first,fingerprint=key,status=status)).status_code,303)
        second=self.analyze('import os\nos.system("echo")\n')
        resolved=self.admin.get(self.url('/audit/export',snapshot_id=second,baseline=first,audit_change='resolved')).json()['findings']
        persistent=self.admin.get(self.url('/audit/export',snapshot_id=second,baseline=first,audit_change='persistent')).json()['findings']
        self.assertEqual([x['rule_id'] for x in resolved],['python.dynamic']);self.assertEqual(resolved[0]['snapshot_id'],first)
        self.assertEqual([x['rule_id'] for x in persistent],['python.shell'])
        with db.db_conn() as c:self.assertEqual([r[0] for r in c.execute('SELECT status FROM audit_review_events ORDER BY id')],['false_positive','open'])

    def test_all_five_severities_have_explicit_rationale_and_no_secret_evidence(self):
        findings=inspect_tree(ast.parse('import sys\nimport requests\nsys.exit(0)\nrequests.get("url",verify=False)\nkey="-----BEGIN PRIVATE KEY----- synthetic"\n'),'file.py')
        self.assertEqual({x['severity'] for x in findings},{'critical','high','medium','low'})
        self.assertTrue(all(x['explanation'] and x['remediation'] and x['evidence'] is None for x in findings))
        self.assertNotIn('synthetic',json.dumps(findings))
        sid=self.analyze('broken syntax!\n');self.assertEqual(self.findings(sid)[0]['severity'],'info')

    def test_inspection_honors_pending_restore_lease_without_source_writes(self):
        from app import restores
        (self.source/'service.log').write_text('INFO ready\n')
        point=backups.create('full',actor_id=1);raw=self.admin.cookies.get(auth.COOKIE);user=auth.session(raw)
        preview=restores.preview(user,raw,'point',point['point_id'])
        restores.confirm(user,raw,preview['id'],preview['token'],'on','RESTORE')
        before=self.source_hashes()
        for route in ('/logs','/sqlite'):
            response=self.admin.get(self.url(route));self.assertEqual(response.status_code,400,response.text)
        self.assertEqual(before,self.source_hashes())


class StageSixMigrationTests(unittest.TestCase):
    def test_stage5_real_database_copies_preserve_all_old_columns_and_ids(self):
        self.skipTest("Private historical database fixtures are not distributed")
