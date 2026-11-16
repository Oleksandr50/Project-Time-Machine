"""Backup integration tests use only disposable projects and private temporary state."""
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
import hashlib
import io
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import unittest
import zipfile
import test_stage2 as stage2
from app import projects,db,backups,jobs,auth,migrations
from app.backup_storage import BackupError,ObjectStore,project_lock,capacity,relative_name
from app.backup_format import package,canonical
from app.ui_routes import stored_text


class BackupFixture(stage2.AuthFixture):
    def setUp(self):
        super().setUp();self.setup();self.pid,self.source=self.project('sample')
        self.cfg=projects.project_settings(projects.get_project(self.pid))
        self.selected=projects.current_settings.set(self.cfg)
    def tearDown(self):
        projects.current_settings.reset(self.selected);super().tearDown()
    def create(self,kind='full',**kw):return backups.create(kind,actor_id=1,**kw)
    def content(self,pid,path):
        out=io.BytesIO();backups.read_verified_file(pid,path,out);return out.getvalue()
    def hashes(self):return {p.relative_to(self.source).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in self.source.rglob('*') if p.is_file()}
    def key(self):
        p=self.root/'external-key';p.write_bytes(os.urandom(32));p.chmod(0o600)
        projects.base_settings=replace(projects.base_settings,encryption_keys={'test-key':str(p)})
        self.cfg=projects.project_settings(projects.get_project(self.pid));projects.current_settings.set(self.cfg)
        return p
    def job(self,kind='full',**kwargs):
        jid=jobs.enqueue(self.pid,1,kind=kind,**kwargs);self.assertTrue(jobs.execute(jid))
        return next(j for j in jobs.job_rows(self.pid) if j['id']==jid)


class BackupEngineTests(BackupFixture):
    def test_full_checkpoint_dedup_and_verified_roundtrip_without_source_writes(self):
        (self.source/'empty').mkdir();(self.source/'same.py').write_bytes((self.source/'code.py').read_bytes())
        data=os.urandom(1024*1024+23);(self.source/'payload.bin').write_bytes(data)
        before=self.hashes();full=self.create();checkpoint=self.create('checkpoint',description='before editing')
        self.assertEqual(self.hashes(),before)
        self.assertEqual(self.content(full['point_id'],'payload.bin'),data)
        self.assertEqual(checkpoint['manifest']['parent'],None)
        self.assertEqual(len(list(self.cfg.content_dir.rglob('[0-9a-f]'*64))),2)
        with zipfile.ZipFile(full['archive_path']) as z:self.assertEqual(len([n for n in z.namelist() if n.startswith('objects/')]),2)
        self.assertTrue(any(e['path']=='empty' and e['type']=='dir' for e in full['manifest']['files']))
        with db.db_conn() as c:
            self.assertEqual(c.execute('SELECT content_status FROM snapshots WHERE id=1').fetchone()[0],'metadata_only')
            self.assertEqual(c.execute('SELECT count(*) FROM snapshots WHERE content_status=\'recoverable\'').fetchone()[0],2)
            self.assertEqual(stored_text(c,full['snapshot_id'],'code.py')[0],(self.source/'code.py').read_text())
        # Archives can reconstruct all bytes with CAS completely offline.
        self.cfg.content_dir.rename(self.root/'cas-offline')
        self.assertEqual(self.content(checkpoint['point_id'],'code.py'),(self.source/'code.py').read_bytes())

    def test_incremental_full_chain_add_modify_delete_return_and_single_file(self):
        (self.source/'gone.txt').write_text('deleted later');(self.source/'return.txt').write_text('returns')
        full=self.create();(self.source/'code.py').write_text('changed\n');(self.source/'gone.txt').unlink();(self.source/'return.txt').unlink()
        first=self.create('incremental');(self.source/'new.txt').write_text('new');(self.source/'return.txt').write_text('returns')
        second=self.create('incremental')
        self.assertEqual(len(backups.verified_chain(second['point_id'])[0]),3)
        self.assertEqual(first['manifest']['deleted'],['gone.txt','return.txt'])
        self.assertEqual(self.content(second['point_id'],'return.txt'),b'returns')
        self.assertEqual(self.content(second['point_id'],'new.txt'),b'new')
        self.assertEqual(self.content(second['point_id'],'code.py'),b'changed\n')
        self.assertEqual(self.content(full['point_id'],'gone.txt'),b'deleted later')
        with self.assertRaises(BackupError):self.content(second['point_id'],'gone.txt')
        # Reconstruct a separate disposable directory using only the verified read primitive.
        export=self.root/'roundtrip';export.mkdir()
        for e in second['manifest']['files']:
            path=export/e['path']
            if e['type']=='dir':path.mkdir(parents=True,exist_ok=True)
            else:path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(self.content(second['point_id'],e['path']))
        self.assertEqual({p.relative_to(export).as_posix():p.read_bytes() for p in export.rglob('*') if p.is_file()},
                         {p.relative_to(self.source).as_posix():p.read_bytes() for p in self.source.rglob('*') if p.is_file()})

    def test_missing_parent_corruption_and_policy_changes_block_incremental(self):
        with self.assertRaisesRegex(BackupError,'parent_required'):self.create('incremental')
        full=self.create();child=self.create('incremental');path=Path(full['archive_path']);raw=path.read_bytes()
        path.write_bytes(raw[:-5]+b'bad!!')
        with self.assertRaises(BackupError):backups.verify(child['point_id'])
        path.write_bytes(raw);path.rename(path.with_suffix('.offline'))
        with self.assertRaises(BackupError):backups.verify(child['point_id'])
        path.with_suffix('.offline').rename(path)
        backups.save_policy(self.pid,'exclude','',False,20,30)
        with self.assertRaisesRegex(BackupError,'parent_policy'):self.create('incremental')
        self.assertEqual(len(backups.points()),2)

    def test_sqlite_wal_backup_api_preserves_source_and_reads_committed_rows(self):
        database=self.source/'records.sqlite';c=sqlite3.connect(database)
        try:
            c.execute('PRAGMA journal_mode=WAL');c.execute('PRAGMA wal_autocheckpoint=0');c.execute('CREATE TABLE records(value TEXT)')
            c.execute('INSERT INTO records VALUES(?)',('committed in WAL',));c.commit()
            before=self.hashes();point=self.create()
            self.assertEqual(self.hashes(),before)
            manifest=point['manifest'];names={e['path'] for e in manifest['files']}
            self.assertIn('records.sqlite',names);self.assertNotIn('records.sqlite-wal',names);self.assertNotIn('records.sqlite-shm',names)
            restored=self.root/'checked.sqlite';restored.write_bytes(self.content(point['point_id'],'records.sqlite'))
            with sqlite3.connect(restored) as check:
                self.assertEqual(check.execute('PRAGMA integrity_check').fetchone()[0],'ok')
                self.assertEqual(check.execute('SELECT value FROM records').fetchall(),[('committed in WAL',)])
            self.assertTrue(next(e for e in manifest['files'] if e['path']=='records.sqlite')['sqlite'])
        finally:c.close()

    def test_encrypted_manifest_and_cas_wrong_key_missing_key_and_tamper(self):
        key=self.key();original=key.read_bytes();(self.source/'.env').write_text('API_TOKEN=synthetic-secret-marker-99123')
        backups.save_policy(self.pid,'local','test-key',False,20,30)
        first=self.create();second=self.create('incremental');self.assertEqual(second['manifest']['objects'],[])
        self.assertEqual(self.content(second['point_id'],'.env'),b'API_TOKEN=synthetic-secret-marker-99123')
        all_data=Path(first['archive_path']).read_bytes()+b''.join(p.read_bytes() for p in self.cfg.content_dir.rglob('*') if p.is_file())
        self.assertNotIn(b'synthetic-secret-marker',all_data);self.assertNotIn(b'code.py',all_data)
        key.write_bytes(os.urandom(32))
        with self.assertRaisesRegex(BackupError,'corrupt'):backups.verify(first['point_id'])
        key.write_bytes(original);key.rename(key.with_suffix('.unplugged'))
        with self.assertRaises((BackupError,FileNotFoundError)):backups.verify(first['point_id'])
        key.with_suffix('.unplugged').rename(key);key.chmod(0o644)
        with self.assertRaisesRegex(BackupError,'storage_permissions'):backups.verify(first['point_id'])

    def test_live_sqlite_sidecars_may_appear_after_coherent_capture(self):
        path=self.source/'live.sqlite'
        with sqlite3.connect(path) as c:c.execute('CREATE TABLE records(value)');c.execute('INSERT INTO records VALUES(1)')
        real=backups.capture;writer=None
        def captured(source,*args,**kwargs):
            nonlocal writer
            result=real(source,*args,**kwargs)
            if source==path:
                writer=sqlite3.connect(path);writer.execute('PRAGMA journal_mode=WAL')
                writer.execute('INSERT INTO records VALUES(2)');writer.commit()
            return result
        try:
            with patch.object(backups,'capture',side_effect=captured):point=self.create()
            self.assertTrue(Path(str(path)+'-wal').exists())
            self.assertFalse(any(e['path'].endswith(('-wal','-shm','-journal')) for e in point['manifest']['files']))
            restored=self.root/'verified.sqlite';restored.write_bytes(self.content(point['point_id'],'live.sqlite'))
            with sqlite3.connect(restored) as c:
                self.assertEqual(c.execute('PRAGMA integrity_check').fetchall(),[('ok',)])
                self.assertEqual(c.execute('SELECT value FROM records').fetchall(),[(1,)])
        finally:
            if writer is not None:writer.close()

    def test_live_sqlite_sidecars_may_disappear_after_coherent_capture(self):
        path=self.source/'live.sqlite';writer=sqlite3.connect(path)
        writer.execute('PRAGMA journal_mode=WAL');writer.execute('CREATE TABLE records(value)')
        writer.execute('INSERT INTO records VALUES(1)');writer.commit()
        real=backups.capture
        def captured(source,*args,**kwargs):
            result=real(source,*args,**kwargs)
            if source==path:writer.close()
            return result
        try:
            with patch.object(backups,'capture',side_effect=captured):point=self.create()
            self.assertFalse(Path(str(path)+'-wal').exists())
            restored=self.root/'verified.sqlite';restored.write_bytes(self.content(point['point_id'],'live.sqlite'))
            with sqlite3.connect(restored) as c:self.assertEqual(c.execute('SELECT value FROM records').fetchall(),[(1,)])
        finally:writer.close()

    def test_journal_looking_ordinary_files_remain_subject_to_race_checks(self):
        real=backups.capture
        def captured(*args,**kwargs):
            result=real(*args,**kwargs);(self.source/'code.py-wal').write_text('ordinary project file');return result
        with patch.object(backups,'capture',side_effect=captured):
            with self.assertRaisesRegex(BackupError,'source_changed'):self.create()
        self.assertEqual(backups.points(),[])

    def test_disappearing_scan_entry_is_a_retryable_source_change(self):
        with patch('app.backup_capture.scanner.iter_files',side_effect=FileNotFoundError):
            with self.assertRaisesRegex(BackupError,'source_changed'):self.create()

    def test_directory_named_like_a_sqlite_sidecar_is_not_silently_omitted(self):
        path=self.source/'live.sqlite'
        with sqlite3.connect(path) as c:c.execute('CREATE TABLE records(value)')
        (self.source/'live.sqlite-wal').mkdir()
        with self.assertRaisesRegex(BackupError,'unsupported_file'):self.create()
        self.assertEqual(backups.points(),[])

    def test_secret_exclusion_and_encryption_key_location_are_explicit(self):
        (self.source/'.env').write_text('PASSWORD=synthetic-value');(self.source/'user-data.db').write_text('user database bytes')
        backups.save_policy(self.pid,'exclude','',False,20,30);p=self.create()
        self.assertNotIn('.env',{e['path'] for e in p['manifest']['files']});self.assertIn('.env',p['manifest']['omitted_secrets'])
        self.assertEqual(self.content(p['point_id'],'user-data.db'),b'user database bytes')
        key=self.key();bad=self.cfg.backups_dir/'invalid.key';bad.write_bytes(key.read_bytes());bad.chmod(0o600)
        projects.base_settings=replace(projects.base_settings,encryption_keys={'bad':str(bad)})
        backups.save_policy(self.pid,'warn','bad',False,20,30)
        with self.assertRaisesRegex(BackupError,'key_location'):self.create()

    def test_disk_exhaustion_cancel_and_racing_source_never_publish_partial_point(self):
        before=self.hashes()
        usage=shutil.disk_usage(self.root)
        with patch('app.backup_storage.shutil.disk_usage',return_value=type(usage)(usage.total,usage.used,0)):
            with self.assertRaisesRegex(BackupError,'space'):self.create()
        n=0
        def cancel():
            nonlocal n
            n+=1
            if n>5:raise BackupError('cancelled')
        with self.assertRaises(BackupError):self.create(tick=cancel)
        from app import backup_capture
        real=backups.capture
        def race(*args,**kw):
            result=real(*args,**kw);(self.source/'code.py').write_text('racing update');return result
        with patch.object(backups,'capture',side_effect=race):
            with self.assertRaisesRegex(BackupError,'source_changed'):self.create()
        self.assertEqual(backups.points(),[])
        with db.db_conn() as c:self.assertEqual(c.execute('SELECT count(*) FROM snapshots').fetchone()[0],1)
        self.assertFalse(list(self.cfg.backups_dir.rglob('*.ptm')))

    def test_shared_exclusions_symlinks_special_files_and_recursive_storage(self):
        for d in ('backups','node_modules','.git','__pycache__'):
            (self.source/d).mkdir();(self.source/d/'ignore').write_text('excluded')
        p=self.create();self.assertEqual([e['path'] for e in p['manifest']['files']],['code.py'])
        (self.source/'link').symlink_to(self.cfg.content_dir,target_is_directory=True)
        # Own storage link is excluded by the mandatory storage policy, never traversed.
        p=self.create();self.assertNotIn('link',{e['path'] for e in p['manifest']['files']})
        (self.source/'outside').symlink_to(self.root/'outside.txt')
        with self.assertRaises(ValueError):self.create()
        (self.source/'outside').unlink();os.mkfifo(self.source/'pipe')
        with self.assertRaises(ValueError):self.create()
        for name in ('../a','/root','C:/a','a\\b','a/../b','CON','x/aux.txt','x.','x//y'):
            with self.assertRaises(BackupError,msg=name):relative_name(name)
        with patch.object(projects,'base_settings',replace(projects.base_settings,allowed_roots=())):
            bad=replace(self.cfg,allowed_roots=())
            token=projects.current_settings.set(bad)
            try:
                with self.assertRaises(ValueError):self.create()
            finally:projects.current_settings.reset(token)

    def test_archive_parser_rejects_extra_members_links_duplicates_and_manifest_traversal(self):
        item=self.create();path=Path(item['archive_path'])
        with zipfile.ZipFile(path) as z:parts={n:z.read(n) for n in z.namelist()}
        tests=[('../escaped',b'bad'),('/absolute',b'bad'),('objects/not-a-digest',b'bad')]
        for n,(name,data) in enumerate(tests):
            bad=self.cfg.backups_dir/f'bad-{n}.ptm'
            with zipfile.ZipFile(bad,'w') as z:
                for member,content in parts.items():z.writestr(member,content)
                z.writestr(name,data)
            bad.chmod(0o600);expected={**backups.point(item['point_id']),'sha256':hashlib.sha256(bad.read_bytes()).hexdigest()}
            with self.assertRaises(BackupError):
                with package(bad,expected,self.cfg,lambda:None):pass
        # Even with a matching outer DB digest, semantic checks reject unsafe manifest names.
        manifest=json.loads(parts['manifest.bin']);manifest['files'][0]['path']='../../escaped'
        data=canonical(manifest);header=json.loads(parts['format.json']);header['manifest_size']=len(data);header['manifest_sha256']=hashlib.sha256(data).hexdigest()
        bad=self.cfg.backups_dir/'bad-manifest.ptm'
        with zipfile.ZipFile(bad,'w') as z:
            for name,content in parts.items():z.writestr(name,data if name=='manifest.bin' else (canonical(header) if name=='format.json' else content))
        bad.chmod(0o600);expected={**backups.point(item['point_id']),'sha256':hashlib.sha256(bad.read_bytes()).hexdigest(),'manifest_sha256':header['manifest_sha256']}
        with self.assertRaises(BackupError):
            with package(bad,expected,self.cfg,lambda:None):pass
        self.assertFalse((self.root/'escaped').exists())

    def test_project_locks_global_capacity_and_other_project_independence(self):
        with project_lock(self.pid):
            with self.assertRaisesRegex(BackupError,'busy'):self.create()
            with self.assertRaisesRegex(BackupError,'busy'):backups.verify('0'*32)
            with self.assertRaisesRegex(BackupError,'busy'):
                from app import services
                services.run_analysis()
        with capacity(),capacity():
            with self.assertRaisesRegex(BackupError,'busy'):self.create()
        pid,source=self.project('other');token=projects.current_settings.set(projects.project_settings(projects.get_project(pid)))
        try:
            with project_lock(self.pid):other=self.create()
            self.assertEqual(other['manifest']['project_id'],pid)
            with self.assertRaises(BackupError):backups.point('f'*32)
        finally:projects.current_settings.reset(token)
        self.assertEqual(backups.points(),[])

    def test_protected_retention_dependency_graph_and_cas_collection(self):
        old=self.create();(self.source/'only-old.txt').write_text('old only');protected=self.create('checkpoint')
        (self.source/'only-old.txt').unlink();base=self.create();child=self.create('incremental');latest=self.create('incremental')
        with self.assertRaisesRegex(BackupError,'retention_disabled'):backups.retention()
        backups.protect(protected['point_id'],True);backups.save_policy(self.pid,'warn','',True,1,0)
        self.assertEqual([p['id'] for p in backups.retention_candidates()],[old['point_id']])
        self.assertEqual(backups.retention(),1)
        self.assertFalse(Path(old['archive_path']).exists())
        self.assertEqual(self.content(latest['point_id'],'code.py'),(self.source/'code.py').read_bytes())
        self.assertTrue(Path(protected['archive_path']).exists())
        standalone=self.create('checkpoint');backups.protect(protected['point_id'],False)
        self.assertEqual(backups.retention(),4)
        with db.db_conn() as c:
            self.assertEqual(c.execute('SELECT count(*) FROM backups').fetchone()[0],6)
            self.assertEqual(c.execute("SELECT count(*) FROM snapshots WHERE content_status='unavailable'").fetchone()[0],5)
        self.assertEqual(len(list(self.cfg.content_dir.rglob('[0-9a-f]'*64))),1)
        self.assertEqual(self.content(standalone['point_id'],'code.py'),(self.source/'code.py').read_bytes())

    def test_journaled_deletion_finishes_after_restart_without_touching_legacy(self):
        from app import services
        legacy=services.create_and_store_backup();old=self.create();new=self.create()
        backups.save_policy(self.pid,'warn','',True,1,0)
        real=backups.finish_deletion
        with patch.object(backups,'finish_deletion',side_effect=OSError('simulated power loss')):
            with self.assertRaises(OSError):backups.retention()
        self.assertEqual(next(p for p in backups.points() if p['id']==old['point_id'])['state'],'deleting')
        jobs.recover_interrupted()
        self.assertEqual(next(p for p in backups.points() if p['id']==old['point_id'])['state'],'deleted')
        self.assertTrue(Path(legacy['archive_path']).is_file());self.assertTrue(Path(new['archive_path']).is_file())

    def test_encrypted_retention_keeps_plain_snapshot_references_with_same_digest(self):
        plain=self.create();backups.protect(plain['point_id'],True)
        self.key();backups.save_policy(self.pid,'warn','test-key',True,1,0)
        old=self.create();(self.source/'code.py').write_text('new encrypted value');latest=self.create()
        self.assertEqual(backups.retention(),1)
        self.assertFalse(Path(old['archive_path']).exists())
        self.assertEqual(self.content(plain['point_id'],'code.py'),b'def sample():\n    return 1\n')
        with db.db_conn() as c:self.assertEqual(stored_text(c,plain['snapshot_id'],'code.py')[1],'ok')
        self.assertEqual(self.content(latest['point_id'],'code.py'),b'new encrypted value')

    def test_tampered_cas_is_never_reused_and_archive_remains_independently_verifiable(self):
        first=self.create();record=next(e for e in first['manifest']['files'] if e['type']=='file')
        path=self.cfg.content_dir/record['storage_key'];path.write_bytes(b'corrupt')
        with self.assertRaisesRegex(BackupError,'corrupt'):self.create()
        self.assertEqual(len(backups.points()),1)
        self.assertEqual(self.content(first['point_id'],'code.py'),(self.source/'code.py').read_bytes())

    def test_zip_links_and_duplicate_members_are_rejected_with_matching_archive_digest(self):
        good=self.create()
        with zipfile.ZipFile(good['archive_path']) as z:parts={n:z.read(n) for n in z.namelist()}
        for mode in ('duplicate','symlink'):
            path=self.cfg.backups_dir/(mode+'.ptm')
            with zipfile.ZipFile(path,'w') as z:
                for name,data in parts.items():z.writestr(name,data)
                if mode=='duplicate':
                    import warnings
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore',UserWarning);z.writestr('format.json',parts['format.json'])
                else:
                    member=zipfile.ZipInfo('objects/'+'f'*64);member.create_system=3;member.external_attr=(stat.S_IFLNK|0o777)<<16
                    z.writestr(member,'../../external')
            path.chmod(0o600)
            expected={**backups.point(good['point_id']),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
            with self.assertRaisesRegex(BackupError,'unsafe_path'):
                with package(path,expected,self.cfg,lambda:None):pass

    def test_encrypted_object_authentication_rejects_tamper_even_with_new_outer_hash(self):
        self.key();backups.save_policy(self.pid,'warn','test-key',False,20,30);p=self.create()
        with zipfile.ZipFile(p['archive_path']) as source:parts={n:source.read(n) for n in source.namelist()}
        member=next(n for n in parts if n.startswith('objects/'))
        raw=bytearray(parts[member]);raw[-1]^=1;parts[member]=bytes(raw)
        bad=self.cfg.backups_dir/'forged-tag.ptm'
        with zipfile.ZipFile(bad,'w') as dest:
            for name,data in parts.items():dest.writestr(name,data)
        bad.chmod(0o600)
        expected={**backups.point(p['point_id']),'sha256':hashlib.sha256(bad.read_bytes()).hexdigest()}
        with self.assertRaisesRegex(BackupError,'corrupt'):
            with package(bad,expected,self.cfg,lambda:None):pass

    def test_pre_restore_primitive_is_full_and_does_not_overwrite_metadata_history(self):
        before=self.hashes();point=self.create('pre_restore',description='insurance primitive')
        self.assertEqual(point['manifest']['parent'],None);self.assertEqual(point['manifest']['kind'],'pre_restore')
        self.assertEqual(self.hashes(),before)
        self.assertEqual(self.content(point['point_id'],'code.py'),(self.source/'code.py').read_bytes())
        response=self.admin.get(f'/functions?project_id={self.pid}')
        self.assertIn('sample',response.text)
        self.assertEqual(self.admin.get(f'/api/status?project_id={self.pid}').json()['snapshot_id'],1)
        self.assertEqual(self.post(self.admin,f'/restore?project_id={self.pid}').status_code,404)


class JobAndHTTPTests(BackupFixture):
    def test_nested_virtualenv_link_reports_path_error_and_explicit_exclusion_recovers(self):
        env=self.source/'data'/'room_voice'/'tts_venv';(env/'bin').mkdir(parents=True)
        (env/'pyvenv.cfg').write_text('home = /usr/bin\n')
        (env/'bin'/'python').symlink_to('/usr/bin/python3')
        outside=self.root/'outside.txt';outside.write_text('external source must never be read')
        (env/'bin'/'outside').symlink_to(outside)
        failed=self.job()
        self.assertEqual((failed['state'],failed['error_code']),('failed','unsafe_path'))
        self.assertEqual(backups.points(),[])
        for locale in ('ru','en','pl','uk'):
            self.post(self.admin,'/account/preferences',dict(locale=locale,theme='dark',scale=100))
            page=self.admin.get(f'/backups?project_id={self.pid}')
            self.assertEqual(page.status_code,200);self.assertNotIn('engine.',page.text)
            from app import i18n
            self.assertIn(i18n.tr('engine.unsafe_path',locale=locale),page.text)
        project=projects.get_project(self.pid)
        rules=project['exclusion_rules']+['data/room_voice/tts_venv']
        projects.update_project(self.pid,project['name'],project['description'],project['category'],rules,project['scan_settings'])
        succeeded=self.job()
        self.assertEqual(succeeded['state'],'succeeded',succeeded)
        manifest=backups.verify(succeeded['result_point_id'])
        self.assertFalse(any(e['path'].startswith('data/room_voice/tts_venv') for e in manifest['files']))
        self.assertEqual(self.content(succeeded['result_point_id'],'code.py'),(self.source/'code.py').read_bytes())
        self.assertTrue((env/'bin'/'python').is_symlink());self.assertTrue(outside.exists())
        self.assertEqual(jobs.job_rows(self.pid)[1]['error_code'],'unsafe_path')

    def test_special_files_report_explicit_error_without_publishing_backup(self):
        os.mkfifo(self.source/'service.pipe')
        item=self.job()
        self.assertEqual((item['state'],item['error_code']),('failed','unsupported_file'))
        self.assertEqual(backups.points(),[])

    def test_unexpected_job_diagnostics_do_not_log_exception_secrets(self):
        secret='SECRET-in-exception-must-not-be-logged-7501'
        with patch.object(backups,'create',side_effect=RuntimeError(secret)):
            with self.assertLogs('app.jobs',level='ERROR') as logs:item=self.job()
        self.assertEqual((item['state'],item['error_code']),('failed','internal'))
        text='\n'.join(logs.output)
        self.assertIn(item['id'],text);self.assertIn('RuntimeError',text);self.assertIn('jobs.py:',text)
        self.assertNotIn(secret,text)
        self.assertNotIn(secret,self.admin.get(f'/backups?project_id={self.pid}').text)

    def test_queue_progress_cancel_and_revalidation_after_acl_revocation(self):
        item=self.job();self.assertEqual(item['state'],'succeeded',item)
        self.assertEqual(item['progress_files'],1);self.assertGreater(item['progress_bytes'],0)
        self.assertEqual(jobs.execute(item['id']),False)
        jid=jobs.enqueue(self.pid,1);jobs.cancel(jid,self.pid,1);self.assertFalse(jobs.execute(jid))
        uid=self.create_user('worker','operator');self.grant(uid,self.pid)
        jid=jobs.enqueue(self.pid,uid)
        with projects.registry() as c:c.execute('DELETE FROM project_access WHERE user_id=?',(uid,))
        jobs.execute(jid);item=next(j for j in jobs.job_rows(self.pid) if j['id']==jid)
        self.assertEqual((item['state'],item['error_code']),('failed','access'))
        self.assertEqual(len(backups.points()),1)

    def test_running_cancel_and_transient_retry_then_success(self):
        jid=jobs.enqueue(self.pid,1)
        def cancelled(*args,**kw):
            jobs.cancel(jid,self.pid,1);kw['tick']() if 'tick' in kw else args[4](force=True)
        # Engine positional tick is called before content publication.
        def force_cancel(*args,**kwargs):
            jobs.cancel(jid,self.pid,1);args[4](force=True)
        with patch.object(backups,'create',side_effect=force_cancel):jobs.execute(jid)
        self.assertEqual(jobs.job_rows(self.pid)[0]['state'],'cancelled')
        retry=jobs.enqueue(self.pid,1)
        with patch.object(backups,'create',side_effect=BackupError('busy')):jobs.execute(retry)
        row=jobs.job_rows(self.pid)[0];self.assertEqual((row['state'],row['attempts']),('queued',1))
        with projects.registry() as c:c.execute('UPDATE jobs SET not_before=0 WHERE id=?',(retry,))
        jobs.execute(retry);self.assertEqual(jobs.job_rows(self.pid)[0]['state'],'succeeded')

    def test_schedule_daily_weekly_dedup_missed_intervals_and_disabled_cleanup(self):
        now=time.time()
        for task in ('backup','snapshot','verify','retention'):jobs.schedule(self.pid,1,task,'full',86400,True)
        with projects.registry() as c:c.execute('UPDATE job_schedules SET next_run=?',(now-10*86400,))
        jobs.due(now);jobs.due(now)
        rows=jobs.job_rows(self.pid);self.assertEqual(len(rows),4)
        with projects.registry() as c:self.assertTrue(all(r[0]>now for r in c.execute('SELECT next_run FROM job_schedules')))
        for item in reversed(rows):jobs.execute(item['id'])
        rows=jobs.job_rows(self.pid)
        self.assertEqual(next(j for j in rows if j['task']=='retention')['error_code'],'retention_disabled')
        self.assertTrue(all(j['state']=='succeeded' for j in rows if j['task']!='retention'),rows)
        jobs.schedule(self.pid,1,'backup','incremental',604800,False)
        with projects.registry() as c:self.assertEqual(tuple(c.execute("SELECT interval_seconds,enabled FROM job_schedules WHERE task='backup'").fetchone()),(604800,0))
        self.assertTrue(all(p['state']=='available' for p in backups.points()))

    def test_restart_reconciles_committed_job_and_never_repeats_incomplete_operation(self):
        completed=jobs.enqueue(self.pid,1);incomplete=jobs.enqueue(self.pid,1)
        with projects.registry() as c:c.execute("UPDATE jobs SET state='running',attempts=1")
        p=self.create(job_id=completed)
        jobs.recover_interrupted();jobs.recover_interrupted()
        rows={j['id']:j for j in jobs.job_rows(self.pid)}
        self.assertEqual(rows[completed]['state'],'succeeded');self.assertEqual(rows[completed]['result_point_id'],p['point_id'])
        self.assertEqual(rows[incomplete]['state'],'interrupted');self.assertFalse(jobs.execute(incomplete))
        self.assertEqual(len(backups.points()),1)

    def test_new_web_controls_are_localized_scoped_and_password_guarded(self):
        for locale in ('ru','en','pl','uk'):
            self.post(self.admin,'/account/preferences',dict(locale=locale,theme='dark',scale=100))
            response=self.admin.get(f'/backups?project_id={self.pid}')
            self.assertEqual(response.status_code,200,response.text[:400]);self.assertNotIn('engine.',response.text)
        r=self.post(self.admin,f'/actions/backup?project_id={self.pid}',dict(kind='checkpoint',description='web checkpoint'))
        self.assertEqual(r.status_code,303);row=jobs.job_rows(self.pid)[0];self.assertEqual(row['state'],'queued')
        jobs.execute(row['id']);point_id=jobs.job_rows(self.pid)[0]['result_point_id']
        r=self.admin.get(f'/backups/download?project_id={self.pid}&id=1');self.assertEqual(r.status_code,200)
        self.assertEqual(r.headers['content-type'],'application/octet-stream')
        bad=self.post(self.admin,f'/backups/policy?project_id={self.pid}',dict(secret_policy='exclude',auto_delete='on',current_password='wrong'))
        self.assertEqual(bad.status_code,403);self.assertFalse(backups.policy(self.pid)['auto_delete'])
        good=self.post(self.admin,f'/backups/policy?project_id={self.pid}',dict(secret_policy='exclude',current_password=stage2.PASSWORD))
        self.assertEqual(good.status_code,303)
        self.assertEqual(self.post(self.admin,f'/backups/protect?project_id={self.pid}',dict(point_id=point_id,protected='on',current_password=stage2.PASSWORD)).status_code,303)
        uid=self.create_user();self.grant(uid,self.pid);reader=self.client();self.signin(reader,'reader',stage2.USER_PASSWORD)
        self.assertEqual(reader.get(f'/api/jobs?project_id={self.pid}').status_code,200)
        self.assertEqual(self.post(reader,f'/actions/cancel?project_id={self.pid}',dict(job_id=row['id'])).status_code,403)
        other,_=self.project('hidden')
        self.assertEqual(reader.get(f'/api/jobs?project_id={other}').status_code,404)
        self.assertEqual(self.post(self.admin,f'/backups/cleanup?project_id={self.pid}',dict(confirm='no',current_password=stage2.PASSWORD)).status_code,400)
        self.assertEqual(self.post(self.admin,f'/actions/backup?project_id={self.pid}',dict(kind='invalid')).status_code,400)
        path=Path(backups.point(point_id)['archive_path']);path.write_bytes(b'corrupt')
        self.assertEqual(self.admin.get(f'/backups/download?project_id={self.pid}&id=1').status_code,400)

    def test_worker_start_stop_and_single_dispatcher_reuse_persistent_queue(self):
        jid=jobs.enqueue(self.pid,1)
        first=jobs.Runner();second=jobs.Runner()
        try:
            first.start();second.start();self.assertIsNone(second.fd)
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                if jobs.job_rows(self.pid)[0]['state'] in jobs.TERMINAL:break
                time.sleep(.05)
            self.assertEqual(jobs.job_rows(self.pid)[0]['state'],'succeeded',jobs.job_rows(self.pid))
        finally:first.close();second.close()
        third=jobs.Runner()
        try:third.start();self.assertIsNotNone(third.fd)
        finally:third.close()
        self.assertEqual(len(backups.points()),1)

    def test_process_restart_uses_same_queue_and_preserves_interrupted_state(self):
        from dataclasses import asdict
        config=asdict(projects.base_settings)
        config.pop('agent_root');config.pop('project_id')
        path=self.root/'child-config.json';path.write_text(json.dumps(config,default=str))
        interrupted=jobs.enqueue(self.pid,1)
        with projects.registry() as conn:conn.execute("UPDATE jobs SET state='running',attempts=1 WHERE id=?",(interrupted,))
        queued=jobs.enqueue(self.pid,1)
        code="""import os,sys
sys.path[1:1]=os.environ['PTM_TEST_DEPS'].split(os.pathsep)
from app import jobs
jobs.recover_interrupted()
assert jobs.execute(os.environ['PTM_QUEUE_TEST_ID'])
"""
        env={**os.environ,'PTM_CONFIG':str(path),'PTM_QUEUE_TEST_ID':queued}
        result=subprocess.run([sys.executable,'-B','-c',code],cwd=Path(__file__).resolve().parents[1],env=env,capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        rows={j['id']:j for j in jobs.job_rows(self.pid)}
        self.assertEqual(rows[interrupted]['state'],'interrupted');self.assertEqual(rows[queued]['state'],'succeeded')
        self.assertEqual(len(backups.points()),1)

    def test_publication_failure_keeps_orphan_unregistered_and_source_unchanged(self):
        before=self.hashes();real=backups.fsync_dir
        with patch.object(backups,'fsync_dir',side_effect=OSError('simulated archive publication interruption')):
            with self.assertRaises(OSError):self.create()
        self.assertEqual(self.hashes(),before);self.assertEqual(backups.points(),[])
        self.assertEqual(len(list(self.cfg.backups_dir.rglob('*.ptm'))),1)
        jobs.recover_interrupted()
        self.assertEqual(backups.points(),[])  # Orphan cannot become a successful point silently.
        self.assertEqual(self.create()['manifest']['kind'],'full')

    def test_external_key_generator_is_private_and_never_overwrites(self):
        output=self.root/'private-key-dir/encryption.key'
        command=[sys.executable,'-B','scripts/generate_backup_key.py',str(output)]
        result=subprocess.run(command,cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(len(output.read_bytes()),32)
        self.assertEqual(output.stat().st_mode&0o777,0o600);self.assertEqual(output.parent.stat().st_mode&0o777,0o700)
        before=output.read_bytes()
        self.assertNotIn(before.hex(),result.stdout)
        self.assertNotEqual(subprocess.run(command,capture_output=True,text=True,timeout=15).returncode,0)
        self.assertEqual(output.read_bytes(),before)

    def test_new_archives_use_private_subdirectory_without_changing_legacy_permissions(self):
        from app import services
        legacy=services.create_and_store_backup();path=Path(legacy['archive_path']);before=path.read_bytes()
        self.cfg.backups_dir.chmod(0o755)
        item=self.create()
        self.assertEqual(Path(item['archive_path']).parent,self.cfg.backups_dir/'engine-v1')
        self.assertEqual(Path(item['archive_path']).parent.stat().st_mode&0o777,0o700)
        self.assertEqual(self.cfg.backups_dir.stat().st_mode&0o777,0o755);self.assertEqual(path.read_bytes(),before)

    def test_native_windows_jobs_fail_closed_without_blocking_login_startup(self):
        with patch('app.jobs.os.name','nt'):
            runner=jobs.Runner();runner.start();self.assertIsNone(runner.fd)
            with self.assertRaisesRegex(BackupError,'platform'):jobs.enqueue(self.pid,1)

    def test_job_history_paginates_past_one_hundred_and_polling_keeps_old_active_job(self):
        active=jobs.enqueue(self.pid,1)
        with projects.registry() as conn:
            for n in range(110):
                conn.execute("INSERT INTO jobs(id,project_id,actor_id,actor_version,task,kind,state,created_at) VALUES(?,?,1,1,'backup','full','cancelled',?)",
                             (f'{n:032x}',self.pid,time.time()+n))
        response=self.admin.get(f'/backups?project_id={self.pid}&jobs_page=5')
        self.assertEqual(response.status_code,200)
        self.assertIn(f'data-job-id=\"{active}\"',response.text)
        self.assertEqual(jobs.job_page(self.pid,5)['total'],111)
        polled=self.admin.get(f'/api/jobs?project_id={self.pid}').json()['jobs']
        self.assertIn(active,{j['id'] for j in polled})
        self.assertEqual(self.admin.get(f'/backups?project_id={self.pid}&jobs_page=invalid').status_code,400)

    def test_worker_status_commit_failure_reconciles_without_restart_or_duplicate_backup(self):
        jid=jobs.enqueue(self.pid,1);runner=jobs.Runner()
        def lost_status_commit(jid,stop):
            with projects.registry() as conn:
                conn.execute("UPDATE jobs SET state='running',attempts=1 WHERE id=?",(jid,))
            token=projects.current_settings.set(self.cfg)
            try:backups.create(job_id=jid,actor_id=1)
            finally:projects.current_settings.reset(token)
            raise OSError('synthetic private exception must not enter audit')
        try:
            with patch.object(jobs,'execute',side_effect=lost_status_commit):
                runner.start();deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    if jobs.job_rows(self.pid)[0]['state']=='succeeded':break
                    time.sleep(.05)
                self.assertEqual(jobs.job_rows(self.pid)[0]['state'],'succeeded',jobs.job_rows(self.pid))
        finally:runner.close()
        self.assertEqual(len(backups.points()),1)
        with projects.registry() as conn:
            self.assertNotIn('synthetic private',str(conn.execute('SELECT * FROM user_audit').fetchall()))
