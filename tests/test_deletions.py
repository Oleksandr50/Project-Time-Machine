"""Deletion scenarios use only isolated fixture storage and source directories."""
from pathlib import Path
from unittest.mock import patch
import json,re,os,time,sqlite3,shutil
import test_stage4 as stage4
from app import projects,db,backups,jobs,deletions,auth,i18n
from app.backup_storage import project_lock


class DeletionTests(stage4.BackupFixture):
    def principal(self):return auth.session(self.admin.cookies.get(auth.COOKIE))
    def preview(self,archive=None):
        url='/backups/delete-preview?project_id='+str(self.pid) if archive else '/projects/delete-preview'
        response=self.post(self.admin,url,{'archive_id':archive['backup_id']} if archive else {'project_id':self.pid})
        self.assertEqual(response.status_code,200,response.text)
        return re.search('name="confirmation_token" value="([^"]+)"',response.text)[1]
    def remove(self,token,archive=None,confirmation=None):
        url='/backups/delete?project_id='+str(self.pid) if archive else '/projects/delete'
        data={'archive_id':archive['backup_id']} if archive else {'project_id':self.pid}
        data.update(confirmation_token=token,confirmation=confirmation if confirmation is not None else str(archive['backup_id']) if archive else 'sample')
        return self.post(self.admin,url,data)
    def disable(self):projects.remove_project(self.pid)
    def test_project_confirmation_active_direct_request_and_cancel(self):
        self.assertEqual(self.post(self.admin,'/projects/delete',{'project_id':self.pid}).status_code,400)
        self.disable();token=self.preview();self.assertTrue(self.source.exists())
        self.assertEqual(self.remove(token,confirmation='wrong').status_code,400)
        self.assertEqual(projects.get_project(self.pid,True)['enabled'],0)
        self.assertTrue(self.cfg.db_path.exists())
        self.assertEqual(self.remove(token).status_code,303)
        self.assertTrue((self.source/'code.py').exists());self.assertFalse(self.cfg.db_path.exists())
        self.assertEqual(self.remove(token).status_code,400)
        with projects.registry() as c:
            self.assertEqual(c.execute("SELECT count(*) FROM user_audit WHERE event='project_deleted'").fetchone()[0],1)
            self.assertEqual(c.execute('PRAGMA foreign_key_check').fetchall(),[])
        replacement=projects.add_project(str(self.source),'sample')
        self.assertGreater(replacement,self.pid)
        self.assertEqual(self.remove(token).status_code,400)
    def test_project_removes_owned_data_only_and_preserves_other_project(self):
        full=self.create();other,source=self.project('other');self.disable();token=self.preview()
        self.assertEqual(self.remove(token).status_code,303)
        self.assertFalse(Path(full['archive_path']).exists());self.assertTrue(source.exists())
        self.assertTrue(projects.get_project(other)['enabled']);self.assertTrue(self.source.exists())
    def test_project_queued_jobs_removed_but_running_and_lock_block(self):
        jid=jobs.enqueue(self.pid,1);self.disable();token=self.preview()
        with project_lock(self.pid):self.assertEqual(self.remove(token).status_code,400)
        with projects.registry() as c:c.execute("UPDATE jobs SET state='running' WHERE id=?",(jid,))
        self.assertEqual(self.remove(token).status_code,400)
        with projects.registry() as c:c.execute("UPDATE jobs SET state='queued' WHERE id=?",(jid,))
        self.assertEqual(self.remove(token).status_code,303)
        with projects.registry() as c:self.assertFalse(c.execute('SELECT * FROM jobs WHERE id=?',(jid,)).fetchone())
    def test_project_failure_is_retryable_and_reattach_blocked(self):
        self.disable();token=self.preview()
        with patch('app.deletions.shutil.rmtree',side_effect=PermissionError):self.assertEqual(self.remove(token).status_code,400)
        self.assertTrue(deletions.pending(self.pid))
        with self.assertRaisesRegex(ValueError,'delete.pending'):projects.add_project(str(self.source))
        self.assertEqual(self.remove(self.preview()).status_code,303)
    def test_project_storage_symlink_and_external_binding_rejected(self):
        other,source=self.project('other');self.disable();token=self.preview()
        with projects.registry() as c:c.execute('UPDATE projects SET backup_path=? WHERE id=?',(str(source),self.pid))
        self.assertEqual(self.remove(token).status_code,400);self.assertTrue(source.exists())
        with projects.registry() as c:c.execute('UPDATE projects SET backup_path=? WHERE id=?',(str(self.cfg.backups_dir),self.pid))
        self.cfg.backups_dir.parent.mkdir(parents=True,exist_ok=True);self.cfg.backups_dir.symlink_to(source,target_is_directory=True)
        self.assertEqual(self.remove(self.preview()).status_code,400);self.assertTrue((source/'code.py').exists())
    def test_backup_delete_independent_keeps_metadata_snapshot_and_source(self):
        full=self.create();other=self.create('checkpoint');before=self.hashes();token=self.preview(full)
        self.assertEqual(self.remove(token,full).status_code,303)
        self.assertEqual(self.hashes(),before);self.assertFalse(Path(full['archive_path']).exists());self.assertTrue(Path(other['archive_path']).exists())
        with db.db_conn() as c:
            self.assertFalse(c.execute('SELECT * FROM backups WHERE id=?',(full['backup_id'],)).fetchone())
            self.assertEqual(c.execute('SELECT content_status FROM snapshots WHERE id=?',(full['snapshot_id'],)).fetchone()[0],'unavailable')
            self.assertEqual(c.execute('SELECT content_status FROM snapshots WHERE id=1').fetchone()[0],'metadata_only')
            self.assertEqual(c.execute('PRAGMA foreign_key_check').fetchall(),[])
        self.assertEqual(self.content(other['point_id'],'code.py'),(self.source/'code.py').read_bytes())
    def test_incremental_chain_protected_and_active_job_block(self):
        full=self.create();child=self.create('incremental');response=self.remove(self.preview(full),full)
        self.assertEqual(response.status_code,400);self.assertIn(str(child['backup_id']),response.text)
        self.assertEqual(self.remove(self.preview(child),child).status_code,303)
        backups.protect(full['point_id'],True)
        self.assertEqual(self.remove(self.preview(full),full).status_code,400)
        backups.protect(full['point_id'],False);jobs.enqueue(self.pid,1)
        self.assertEqual(self.remove(self.preview(full),full).status_code,400)
    def test_archive_unlink_failure_journal_retry_and_symlink_rejection(self):
        full=self.create();token=self.preview(full);original=Path(full['archive_path']);raw=original.read_bytes()
        unlink=os.unlink
        def fail_archive(path,*args,**kwargs):
            if str(path).endswith('.ptm'):raise PermissionError
            return unlink(path,*args,**kwargs)
        with patch('app.backups.os.unlink',side_effect=fail_archive):self.assertEqual(self.remove(token,full).status_code,400)
        self.assertTrue(original.exists());self.assertEqual(json.loads(deletions.journal_path(self.pid,full['backup_id']).read_text())['phase'],'deleting')
        self.assertEqual(self.remove(self.preview(full),full).status_code,303)
        other=self.create();path=Path(other['archive_path']);path.unlink();path.symlink_to(self.source/'code.py')
        self.assertEqual(self.remove(self.preview(other),other).status_code,400);self.assertTrue((self.source/'code.py').exists())
    def test_confirmation_session_csrf_and_roles_cannot_be_bypassed(self):
        full=self.create();self.assertEqual(self.remove('',full).status_code,400)
        self.create_user();reader=self.client();self.signin(reader,'reader',stage4.stage2.USER_PASSWORD)
        for route in ['/projects/delete-preview','/projects/delete','/backups/delete-preview','/backups/delete']:
            self.assertEqual(self.post(reader,route,{'project_id':self.pid,'archive_id':full['backup_id']}).status_code,403)
        self.assertEqual(self.admin.post('/backups/delete?project_id='+str(self.pid),data={'archive_id':full['backup_id']},follow_redirects=False).status_code,403)
        self.assertTrue(Path(full['archive_path']).exists())
    def test_confirmation_is_bound_to_project_and_cannot_be_replayed(self):
        full=self.create();token=self.preview(full);other,source=self.project('other')
        result=self.post(self.admin,'/backups/delete?project_id='+str(other),{'archive_id':full['backup_id'],'confirmation_token':token,'confirmation':str(full['backup_id'])})
        self.assertEqual(result.status_code,400);self.assertTrue(Path(full['archive_path']).exists())
        self.assertEqual(self.remove(token,full).status_code,303)
        self.assertEqual(self.remove(token,full).status_code,400)
    def test_four_locales_and_deterministic_dashboard_order(self):
        with db.db_conn() as c:
            for stamp in ['2030-01-01T00:00:00','2029-01-01T00:00:00','2030-01-01T00:00:00']:
                c.execute("INSERT INTO file_events(created_at,event_type,path_a) VALUES(?,'created',?)",(stamp,'long-name-'+str(time.time_ns())+'.py'))
        for locale in i18n.LANGUAGES:
            self.post(self.admin,'/account/preferences',dict(locale=locale,theme='dark',scale=100,return_to='/'))
            page=self.admin.get('/');self.assertEqual(page.status_code,200,page.text)
            self.assertIn('data-visible-limit="4"',page.text)
            self.assertLess(page.text.index('2030-01-01'),page.text.index('2029-01-01'))
            self.assertIn('data-visible-limit="5"',self.admin.get('/backups?project_id='+str(self.pid)).text)

    def test_live_restore_preview_blocks_backup_deletion(self):
        full=self.create()
        with projects.registry() as c:
            c.execute('INSERT INTO restore_previews(id,project_id,user_id,session_digest,user_version,token_digest,created_at,expires_at,spec_json) VALUES(?,?,1,?,1,?,?,?,?)',
                      ('preview',self.pid,self.principal()['digest'],'synthetic',time.time(),time.time()+600,json.dumps({'point_id':full['point_id']})))
        self.assertEqual(self.remove(self.preview(full),full).status_code,400)
        self.assertTrue(Path(full['archive_path']).exists())

    def test_sqlite_failure_after_unlink_is_diagnosable_and_retryable(self):
        full=self.create();finish=backups.finish_deletion
        def failed(point):
            finish(point)
            raise sqlite3.OperationalError('synthetic failure')
        with patch('app.deletions.backups.finish_deletion',side_effect=failed):self.assertEqual(self.remove(self.preview(full),full).status_code,503)
        self.assertFalse(Path(full['archive_path']).exists())
        self.assertEqual(self.remove(self.preview(full),full).status_code,303)

    def test_partial_project_cleanup_can_be_retried(self):
        full=self.create();self.disable();remove=shutil.rmtree;calls=[]
        def partial(path,*args,**kwargs):
            calls.append(path)
            if len(calls)==2:raise PermissionError
            return remove(path,*args,**kwargs)
        with patch('app.deletions.shutil.rmtree',side_effect=partial):self.assertEqual(self.remove(self.preview()).status_code,400)
        self.assertFalse(self.cfg.db_path.exists());self.assertTrue(Path(full['archive_path']).exists())
        self.assertEqual(self.remove(self.preview()).status_code,303)
        self.assertTrue((self.source/'code.py').exists())

    def test_owned_committed_restore_workspace_is_cleaned_without_source_deletion(self):
        from app.restore_fs import WORK_PREFIX,root_id
        opid='d'*32;work=self.source/(WORK_PREFIX+opid);work.mkdir(mode=0o700)
        (work/'owner.json').write_text(json.dumps(dict(id=opid,nonce='test-nonce')));(work/'owner.json').chmod(0o600)
        (work/'undo').mkdir();(work/'undo/old.txt').write_text('previous content')
        with projects.registry() as c:
            c.execute("INSERT INTO restore_operations(id,project_id,actor_id,actor_version,session_digest,job_id,state,created_at,updated_at,target_path,work_path,work_identity,nonce,spec_json) VALUES(?,?,1,1,?,?,'committed',?,?,?,?,?,?,?)",
                      (opid,self.pid,self.principal()['digest'],opid,time.time(),time.time(),str(self.source),str(work),json.dumps(dict(work=root_id(work))),'test-nonce',json.dumps(dict(target=str(self.source),exists=True))))
        self.disable();self.assertEqual(self.remove(self.preview()).status_code,303)
        self.assertFalse(work.exists());self.assertTrue((self.source/'code.py').exists())
