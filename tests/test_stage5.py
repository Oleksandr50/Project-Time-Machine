"""Every restore destination is inside a fresh TemporaryDirectory, never a real project."""
from dataclasses import asdict,replace
from pathlib import Path
from unittest.mock import patch
import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import tarfile
import time
import unittest
import test_stage4 as stage4
import test_stage2 as stage2
from app import restores,restore_fs as fs,projects,backups,jobs,db,auth,services
from app.scanner import iter_files
from app.backup_storage import BackupError,project_lock


class RestoreFixture(stage4.BackupFixture):
    def hashes(self):
        from app.restore_state import workspaces
        owned=[Path(p) for p in workspaces(self.pid)]
        return {p.relative_to(self.source).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in self.source.rglob('*')
                if p.is_file() and not any(p.is_relative_to(work) for work in owned)}
    def principal(self,client=None):
        c=client or self.admin;raw=c.cookies.get(auth.COOKIE);return auth.session(raw),raw
    def preview(self,point,mode='full',target='',files=(),source_type='point',client=None):
        user,raw=self.principal(client)
        return restores.preview(user,raw,source_type,point,mode,str(target),files)
    def confirm(self,shown,client=None):
        c=client or self.admin
        r=self.post(c,f'/restore/confirm?project_id={self.pid}',dict(preview_id=shown['id'],confirmation_token=shown['token'],acknowledge='on',confirmation='RESTORE'))
        self.assertEqual(r.status_code,303,r.text[:500])
        with projects.registry() as conn:return conn.execute('SELECT id FROM jobs WHERE point_id=? ORDER BY created_at DESC',(shown['id'],)).fetchone()[0]
    def apply_preview(self,shown,client=None):
        jid=self.confirm(shown,client);jobs.execute(jid)
        return next(j for j in jobs.job_rows(self.pid) if j['id']==jid)
    def recovery(self,opid,method='undo'):
        user,raw=self.principal();return restores.recovery_preview(user,raw,opid,method)
    def interrupt(self,point,after=1):
        shown=self.preview(point);jid=self.confirm(shown);real=restores.Journal.done;count=0
        def crash(journal,seq):
            nonlocal count
            real(journal,seq);count+=1
            if count==after:raise OSError('simulated interruption')
        with patch.object(restores.Journal,'done',crash):jobs.execute(jid)
        row=next(j for j in jobs.job_rows(self.pid) if j['id']==jid)
        self.assertEqual(row['state'],'interrupted',row)
        return row['restore_op_id']


class RestoreEngineTests(RestoreFixture):
    def test_full_preview_then_restore_and_verified_protected_insurance(self):
        (self.source/'empty').mkdir();(self.source/'old.txt').write_text('old')
        original=self.hashes();point=self.create();(self.source/'code.py').write_text('new value');(self.source/'extra.txt').write_text('extra');(self.source/'old.txt').unlink()
        before=self.hashes();shown=self.preview(point['point_id'])
        self.assertEqual(self.hashes(),before)
        changes={e['path']:e['change'] for e in shown['spec']['plan']['changes']}
        self.assertEqual(changes['extra.txt'],'deleted');self.assertEqual(changes['old.txt'],'added');self.assertEqual(changes['code.py'],'modified')
        row=self.apply_preview(shown);self.assertEqual(row['state'],'succeeded',row)
        self.assertEqual(self.hashes(),original)
        op=restores.operation(row['restore_op_id']);self.assertEqual(op['state'],'committed')
        safety=backups.point(op['safety_point_id']);self.assertEqual(safety['kind'],'pre_restore');self.assertEqual(safety['protected'],1)
        self.assertEqual(self.content(safety['id'],'code.py'),b'new value')
        self.assertTrue((self.source/'empty').is_dir())
        self.assertTrue((Path(op['work_path'])/'undo').is_dir())
        self.assertEqual({p.relative_to(self.source).as_posix() for p,_ in iter_files(self.source)},set(original))
        with db.db_conn() as conn:self.assertEqual(conn.execute('SELECT content_status FROM snapshots WHERE id=1').fetchone()[0],'metadata_only')

    def test_incremental_chain_and_checkpoint_restore(self):
        full=self.create();(self.source/'a.txt').write_text('first');first=self.create('incremental')
        (self.source/'code.py').write_text('checkpoint version');second=self.create('incremental')
        (self.source/'code.py').write_text('later');(self.source/'a.txt').unlink()
        row=self.apply_preview(self.preview(second['point_id']));self.assertEqual(row['state'],'succeeded',row)
        self.assertEqual((self.source/'code.py').read_text(),'checkpoint version');self.assertEqual((self.source/'a.txt').read_text(),'first')
        checkpoint=self.create('checkpoint');(self.source/'code.py').write_text('later again')
        self.assertEqual(self.apply_preview(self.preview(checkpoint['point_id']))['state'],'succeeded')
        self.assertEqual((self.source/'code.py').read_text(),'checkpoint version')

    def test_selected_files_preserve_others_and_create_missing_parents(self):
        (self.source/'sub').mkdir();(self.source/'sub/one.txt').write_text('saved');(self.source/'other.txt').write_text('old')
        point=self.create();(self.source/'sub/one.txt').unlink();(self.source/'sub').rmdir();(self.source/'other.txt').write_text('preserve')
        row=self.apply_preview(self.preview(point['point_id'],'files',files=['sub/one.txt']));self.assertEqual(row['state'],'succeeded',row)
        self.assertEqual((self.source/'sub/one.txt').read_text(),'saved');self.assertEqual((self.source/'other.txt').read_text(),'preserve')
        with self.assertRaises(BackupError):self.preview(point['point_id'],'files',files=['../outside'])

    def test_alternate_directory_does_not_modify_source_and_can_restore_missing_source(self):
        point=self.create();before=self.hashes();target=self.root/'sources/copy'
        row=self.apply_preview(self.preview(point['point_id'],'alternate',target));self.assertEqual(row['state'],'succeeded',row)
        self.assertEqual(self.hashes(),before);self.assertEqual((target/'code.py').read_bytes(),(self.source/'code.py').read_bytes())
        with self.assertRaises(BackupError):self.preview(point['point_id'],'alternate',target)
        parked=self.root/'offline-source';self.source.rename(parked)
        missing=self.apply_preview(self.preview(point['point_id']));self.assertEqual(missing['state'],'succeeded',missing)
        self.assertEqual((self.source/'code.py').read_bytes(),(parked/'code.py').read_bytes())

    def test_snapshot_requires_real_content_and_legacy_archive_is_validated(self):
        point=self.create();(self.source/'code.py').write_text('changed')
        with self.assertRaisesRegex(BackupError,'restore_metadata'):self.preview('1',source_type='snapshot')
        row=self.apply_preview(self.preview(str(point['snapshot_id']),source_type='snapshot'));self.assertEqual(row['state'],'succeeded',row)
        legacy=services.create_and_store_backup();(self.source/'code.py').write_text('changed again')
        row=self.apply_preview(self.preview(str(legacy['backup_id']),source_type='legacy'));self.assertEqual(row['state'],'succeeded',row)
        self.assertEqual((self.source/'code.py').read_text(),'def sample():\n    return 1\n')

    def test_cas_only_recoverable_snapshot(self):
        point=self.create()
        with db.db_conn() as conn:conn.execute('UPDATE snapshots SET backup_point_id=NULL WHERE id=?',(point['snapshot_id'],))
        (self.source/'code.py').write_text('changed')
        row=self.apply_preview(self.preview(str(point['snapshot_id']),source_type='snapshot'));self.assertEqual(row['state'],'succeeded',row)
        self.assertEqual((self.source/'code.py').read_text(),'def sample():\n    return 1\n')

    def test_sqlite_restore_integrity_and_removes_previewed_sidecars(self):
        database=self.source/'live.db'
        with sqlite3.connect(database) as conn:conn.execute('CREATE TABLE sample(value TEXT)');conn.execute("INSERT INTO sample VALUES('saved')")
        point=self.create()
        with sqlite3.connect(database) as conn:conn.execute("UPDATE sample SET value='current'")
        (self.source/'live.db-shm').write_bytes(b'disposable stale sidecar')
        shown=self.preview(point['point_id'],'files',files=['live.db'])
        self.assertIn('live.db-shm',shown['spec']['plan']['remove'])
        row=self.apply_preview(shown);self.assertEqual(row['state'],'succeeded',row)
        with sqlite3.connect(database) as conn:
            self.assertEqual(conn.execute('PRAGMA integrity_check').fetchone()[0],'ok');self.assertEqual(conn.execute('SELECT value FROM sample').fetchone()[0],'saved')
        self.assertFalse((self.source/'live.db-shm').exists())

    def test_encrypted_restore_wrong_key_and_key_loss_refuse_before_mutation(self):
        key=self.key();original=key.read_bytes();backups.save_policy(self.pid,'local','test-key',False,20,30)
        (self.source/'.env').write_text('PASSWORD=private-synthetic-value');point=self.create();(self.source/'code.py').write_text('current')
        row=self.apply_preview(self.preview(point['point_id']));self.assertEqual(row['state'],'succeeded',row)
        shown=self.preview(point['point_id']);before=self.hashes();key.write_bytes(os.urandom(32))
        row=self.apply_preview(shown);self.assertEqual(row['state'],'failed',row);self.assertEqual(self.hashes(),before)
        key.write_bytes(original);shown=self.preview(point['point_id']);key.rename(key.with_suffix('.offline'))
        row=self.apply_preview(shown);self.assertEqual(row['state'],'failed',row);self.assertEqual(self.hashes(),before)

    def test_corrupt_archive_stale_preview_and_no_space_preserve_target(self):
        point=self.create();(self.source/'code.py').write_text('current');shown=self.preview(point['point_id']);before=self.hashes()
        path=Path(point['archive_path']);raw=path.read_bytes();path.write_bytes(b'corrupt')
        row=self.apply_preview(shown);self.assertEqual(row['state'],'failed',row);self.assertEqual(self.hashes(),before);path.write_bytes(raw)
        shown=self.preview(point['point_id']);(self.source/'new.txt').write_text('racing new data');before=self.hashes()
        row=self.apply_preview(shown);self.assertEqual(row['state'],'failed',row);self.assertEqual(self.hashes(),before)
        shown=self.preview(point['point_id'])
        with patch('app.restores.ensure_space',side_effect=BackupError('space')):row=self.apply_preview(shown)
        self.assertEqual(row['state'],'failed',row);self.assertEqual(self.hashes(),before)

    def test_safety_failure_and_corrupt_safety_never_overwrite(self):
        point=self.create();(self.source/'code.py').write_text('must remain');before=self.hashes();shown=self.preview(point['point_id'])
        with patch.object(backups,'_create_locked',side_effect=OSError('insurance unavailable')):row=self.apply_preview(shown)
        self.assertEqual(row['state'],'failed',row);self.assertEqual(self.hashes(),before)
        real=restores.Journal.safety
        def invalid(journal,*a,**kw):
            item=real(journal,*a,**kw);Path(item['archive_path']).write_bytes(b'damaged safety');return item
        # Publication and the immediate insurance verifier must both succeed.
        shown=self.preview(point['point_id'])
        with patch.object(restores.Journal,'safety',new=invalid):row=self.apply_preview(shown)
        self.assertEqual(row['state'],'failed',row);self.assertEqual(self.hashes(),before)

    def test_excluded_data_and_nested_registered_project_are_preserved(self):
        (self.source/'node_modules').mkdir();(self.source/'node_modules/user.db').write_text('preserve dependency data')
        point=self.create();(self.source/'code.py').write_text('current')
        nested=self.source/'nested';nested.mkdir();(nested/'data.txt').write_text('another project')
        other=projects.add_project(str(nested))
        row=self.apply_preview(self.preview(point['point_id']));self.assertEqual(row['state'],'succeeded',row)
        self.assertEqual((nested/'data.txt').read_text(),'another project');self.assertEqual((self.source/'node_modules/user.db').read_text(),'preserve dependency data')
        with self.assertRaises(BackupError):self.preview(point['point_id'],'alternate',nested/'copy')

    def test_symlink_traversal_storage_and_cross_project_targets_are_denied(self):
        point=self.create();outside=self.root/'outside';outside.mkdir();(outside/'safe').write_text('external')
        (self.source/'link').symlink_to(outside,target_is_directory=True)
        with self.assertRaises(ValueError):self.preview(point['point_id'])
        (self.source/'link').unlink()
        for target in (self.root/'sources/../escape',self.cfg.content_dir/'copy',self.source/'nested-copy',outside/'copy'):
            with self.assertRaises(ValueError,msg=str(target)):self.preview(point['point_id'],'alternate',target)
        self.assertEqual((outside/'safe').read_text(),'external')

    def test_file_directory_type_changes_and_empty_directories(self):
        (self.source/'folder').mkdir();(self.source/'folder/data.txt').write_text('saved');(self.source/'file.txt').write_text('was file')
        point=self.create();(self.source/'folder/data.txt').unlink();(self.source/'folder').rmdir();(self.source/'folder').write_text('now file')
        (self.source/'file.txt').unlink();(self.source/'file.txt').mkdir();(self.source/'file.txt/other').write_text('now directory')
        row=self.apply_preview(self.preview(point['point_id']));self.assertEqual(row['state'],'succeeded',row)
        self.assertEqual((self.source/'folder/data.txt').read_text(),'saved');self.assertEqual((self.source/'file.txt').read_text(),'was file')

    def test_confirm_token_session_binding_single_use_and_csrf(self):
        point=self.create();shown=self.preview(point['point_id']);before=self.hashes()
        self.assertEqual(self.admin.post(f'/restore/confirm?project_id={self.pid}',data={'preview_id':shown['id']}).status_code,403)
        user,raw=self.principal()
        with self.assertRaises(BackupError):restores.confirm(user,raw,shown['id'],shown['token'],'off','RESTORE')
        with self.assertRaises(BackupError):restores.confirm(user,raw,shown['id'],'bad-token','on','RESTORE')
        other=self.client();self.signin(other)
        r=self.post(other,f'/restore/confirm?project_id={self.pid}',dict(preview_id=shown['id'],confirmation_token=shown['token'],acknowledge='on',confirmation='RESTORE'))
        self.assertEqual(r.status_code,400)
        jid=self.confirm(shown)
        with self.assertRaises(BackupError):restores.confirm(user,raw,shown['id'],shown['token'],'on','RESTORE')
        jobs.cancel(jid,self.pid,1);self.assertEqual(self.hashes(),before)
        self.assertEqual(restores.operations()[0]['state'],'failed');self.assertEqual(self.create()['manifest']['kind'],'full')

    def test_operator_needs_explicit_permission_and_acl_revocation_cancels_queued_restore(self):
        point=self.create();uid=self.create_user('operator','operator');self.grant(uid,self.pid)
        operator=self.client();self.signin(operator,'operator',stage2.USER_PASSWORD)
        r=self.post(operator,f'/restore/preview?project_id={self.pid}',dict(source_type='point',source_id=point['point_id']))
        self.assertEqual(r.status_code,403)
        self.grant(uid,self.pid,True);self.signin(operator,'operator',stage2.USER_PASSWORD)
        shown=self.preview(point['point_id'],client=operator);jid=self.confirm(shown,operator)
        self.grant(uid,self.pid,False);before=self.hashes();jobs.execute(jid)
        row=next(j for j in jobs.job_rows(self.pid) if j['id']==jid)
        self.assertEqual(row['state'],'failed',row);self.assertEqual(self.hashes(),before);self.assertEqual(restores.operations()[0]['state'],'failed')

    def test_cancel_during_apply_interrupts_and_blocks_backups_until_explicit_undo(self):
        point=self.create();(self.source/'code.py').write_text('current');before=self.hashes()
        opid=self.interrupt(point['point_id'])
        with self.assertRaisesRegex(BackupError,'restore_pending'):self.create()
        with self.assertRaisesRegex(BackupError,'restore_pending'):services.run_analysis()
        self.assertNotEqual(self.hashes(),before)
        row=self.apply_preview(self.recovery(opid));self.assertEqual(row['state'],'succeeded',row)
        self.assertEqual(self.hashes(),before);self.assertEqual(restores.operation(opid)['state'],'rolled_back')
        self.assertEqual(self.create()['manifest']['kind'],'full')

    def test_undo_conflict_refuses_and_insurance_recovery_requires_new_preview(self):
        point=self.create();(self.source/'code.py').write_text('before restore')
        # Interrupt after the newly restored file was installed.
        opid=self.interrupt(point['point_id'],after=2);(self.source/'code.py').write_text('new user work after interruption')
        with self.assertRaisesRegex(BackupError,'restore_conflict'):self.recovery(opid)
        shown=self.recovery(opid,'insurance');row=self.apply_preview(shown)
        self.assertEqual(row['state'],'succeeded',row);self.assertEqual((self.source/'code.py').read_text(),'before restore')
        op=restores.operation(row['restore_op_id']);self.assertEqual(self.content(op['safety_point_id'],'code.py'),b'new user work after interruption')
        self.assertEqual(restores.operation(opid)['state'],'superseded')

    def test_interrupted_undo_can_be_explicitly_retried(self):
        point=self.create();(self.source/'code.py').write_text('before restore');before=self.hashes();opid=self.interrupt(point['point_id'],after=2)
        shown=self.recovery(opid);jid=self.confirm(shown);real=fs.noreplace
        def fail_after_move(*args):real(*args);raise OSError('interrupted undo after rename')
        with patch.object(fs,'noreplace',side_effect=fail_after_move):jobs.execute(jid)
        self.assertEqual(restores.operation(opid)['state'],'interrupted')
        row=self.apply_preview(self.recovery(opid));self.assertEqual(row['state'],'succeeded',row);self.assertEqual(self.hashes(),before)

    def test_preview_expiry_settings_change_and_filename_injection(self):
        point=self.create();shown=self.preview(point['point_id']);user,raw=self.principal()
        with projects.registry() as conn:conn.execute('UPDATE restore_previews SET expires_at=0 WHERE id=?',(shown['id'],))
        with self.assertRaisesRegex(BackupError,'restore_preview'):restores.get_preview(user,raw,shown['id'])
        shown=self.preview(point['point_id']);backups.save_policy(self.pid,'exclude','',False,20,30)
        with self.assertRaisesRegex(BackupError,'restore_stale'):restores.confirm(user,raw,shown['id'],shown['token'],'on','RESTORE')

    def test_restore_wizard_translated_and_no_secrets_in_preview_or_journal(self):
        (self.source/'.env').write_text('PASSWORD=private-preview-marker-8871');point=self.create();(self.source/'.env').write_text('PASSWORD=private-preview-marker-8872')
        for language in ('ru','en','pl','uk'):
            self.post(self.admin,'/account/preferences',dict(locale=language,theme='dark',scale=100))
            r=self.admin.get(f'/restore?project_id={self.pid}');self.assertEqual(r.status_code,200,r.text[:300]);self.assertNotIn('restore.wizard_hint',r.text)
        r=self.post(self.admin,f'/restore/preview?project_id={self.pid}',dict(source='point:'+point['point_id']))
        self.assertEqual(r.status_code,303,r.text);page=self.admin.get(r.headers['location']);self.assertEqual(page.status_code,200,page.text[:200])
        self.assertNotIn('private-preview-marker',page.text)
        with projects.registry() as conn:
            exported=str([tuple(r) for r in conn.execute('SELECT * FROM restore_previews')])+str([tuple(r) for r in conn.execute('SELECT * FROM user_audit')])
        self.assertNotIn('private-preview-marker',exported)

    def test_process_exit_after_durable_move_requires_explicit_recovery(self):
        point=self.create();(self.source/'code.py').write_text('before killed process');before=self.hashes()
        shown=self.preview(point['point_id']);jid=self.confirm(shown)
        config=asdict(projects.base_settings);config.pop('agent_root');config.pop('project_id')
        cfg=self.root/'process-settings.json';cfg.write_text(json.dumps(config,default=str))
        code="""import os,sys
sys.path[1:1]=os.environ['PTM_TEST_DEPS'].split(os.pathsep)
from app import jobs,restores
real=restores.Journal.done
def exit_after_move(self,seq):
 real(self,seq)
 os._exit(73)
restores.Journal.done=exit_after_move
jobs.execute(os.environ['PTM_RESTORE_TEST_JOB'])
"""
        env={**os.environ,'PTM_CONFIG':str(cfg),'PTM_RESTORE_TEST_JOB':jid}
        result=subprocess.run([sys.executable,'-B','-c',code],cwd=Path(__file__).resolve().parents[1],env=env,capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,73,result.stderr)
        op=next(j for j in jobs.job_rows(self.pid) if j['id']==jid)['restore_op_id']
        self.assertEqual(restores.operation(op)['state'],'applying')
        partial=self.hashes();jobs.recover_interrupted();self.assertEqual(self.hashes(),partial)
        self.assertEqual(restores.operation(op)['state'],'interrupted')
        row=self.apply_preview(self.recovery(op));self.assertEqual(row['state'],'succeeded',row);self.assertEqual(self.hashes(),before)

    def test_detected_running_process_blocks_restore_without_stopping_it(self):
        point=self.create();(self.source/'code.py').write_text('current');before=self.hashes()
        process=subprocess.Popen([sys.executable,'-B','-c',"import os,sys,time;os.chdir(sys.argv[1]);print('ready',flush=True);time.sleep(30)",str(self.source)],stdout=subprocess.PIPE,text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(),'ready')
            shown=self.preview(point['point_id']);self.assertIn(process.pid,shown['spec']['processes']['pids'])
            row=self.apply_preview(shown);self.assertEqual(row['state'],'failed',row);self.assertEqual(self.hashes(),before)
            self.assertIsNone(process.poll())
        finally:process.terminate();process.wait(timeout=5);process.stdout.close()

    def test_cancel_after_first_move_observed_before_next_file_mutation(self):
        point=self.create();(self.source/'code.py').write_text('current');before=self.hashes()
        shown=self.preview(point['point_id']);jid=self.confirm(shown);real=restores.Journal.done
        def cancel(journal,seq):
            real(journal,seq);jobs.cancel(jid,self.pid,1)
        with patch.object(restores.Journal,'done',new=cancel):jobs.execute(jid)
        row=next(j for j in jobs.job_rows(self.pid) if j['id']==jid)
        self.assertEqual(row['state'],'interrupted',row)
        self.assertFalse((self.source/'code.py').exists())
        undo=self.apply_preview(self.recovery(row['restore_op_id']));self.assertEqual(undo['state'],'succeeded',undo);self.assertEqual(self.hashes(),before)

    def test_queued_insurance_recovery_cancellation_reactivates_original_lease(self):
        point=self.create();(self.source/'code.py').write_text('current');op=self.interrupt(point['point_id'])
        jid=self.confirm(self.recovery(op,'insurance'));jobs.cancel(jid,self.pid,1)
        self.assertEqual(restores.operation(op)['state'],'interrupted')
        with self.assertRaisesRegex(BackupError,'restore_pending'):self.create()
        self.assertEqual(self.apply_preview(self.recovery(op))['state'],'succeeded')

    def test_target_created_after_preview_and_parent_symlink_swap_preserve_external_files(self):
        point=self.create();target=self.root/'sources/new-target';shown=self.preview(point['point_id'],'alternate',target)
        target.mkdir();(target/'other-user.txt').write_text('preserve')
        row=self.apply_preview(shown);self.assertEqual(row['state'],'failed',row);self.assertEqual((target/'other-user.txt').read_text(),'preserve')
        (self.source/'sub').mkdir();(self.source/'sub/item.txt').write_text('saved');point=self.create()
        shown=self.preview(point['point_id'],'files',files=['sub/item.txt'])
        original=self.source/'sub';parked=self.root/'parked-sub';original.rename(parked)
        external=self.root/'external';external.mkdir();(external/'item.txt').write_text('external original');original.symlink_to(external,target_is_directory=True)
        row=self.apply_preview(shown);self.assertEqual(row['state'],'failed',row);self.assertEqual((external/'item.txt').read_text(),'external original')

    def test_replaced_workspace_never_traversed_or_deleted_and_insurance_remains_usable(self):
        point=self.create();(self.source/'code.py').write_text('current');op=self.interrupt(point['point_id'])
        work=Path(restores.operation(op)['work_path']);parked=self.root/'saved-undo';work.rename(parked)
        outside=self.root/'outside-workspace';outside.mkdir();(outside/'private.txt').write_text('do not touch');work.symlink_to(outside,target_is_directory=True)
        with self.assertRaises((BackupError,OSError)):self.recovery(op)
        row=self.apply_preview(self.recovery(op,'insurance'));self.assertEqual(row['state'],'succeeded',row)
        self.assertEqual((outside/'private.txt').read_text(),'do not touch');self.assertTrue(parked.is_dir());self.assertEqual((self.source/'code.py').read_text(),'current')

    def test_nested_file_and_directory_undo_restores_original_inodes_and_bytes(self):
        (self.source/'a').mkdir();(self.source/'a/original').write_text('saved');(self.source/'original-file').write_text('saved file')
        point=self.create();(self.source/'a/original').unlink();(self.source/'a').rmdir();(self.source/'a').write_text('current file')
        (self.source/'original-file').unlink();(self.source/'original-file').mkdir();(self.source/'original-file/extra').write_text('current nested')
        before=self.hashes();op=self.interrupt(point['point_id'],after=4)
        row=self.apply_preview(self.recovery(op));self.assertEqual(row['state'],'succeeded',row);self.assertEqual(self.hashes(),before)

    def test_new_directory_publish_interruption_undo_removes_only_owned_target(self):
        point=self.create();target=self.root/'sources/new-copy';shown=self.preview(point['point_id'],'alternate',target);jid=self.confirm(shown)
        real=restores.Journal.done
        def interrupted(journal,seq):real(journal,seq);raise OSError('crash after atomic publish')
        with patch.object(restores.Journal,'done',new=interrupted):jobs.execute(jid)
        op=next(j for j in jobs.job_rows(self.pid) if j['id']==jid)['restore_op_id'];self.assertTrue(target.exists())
        row=self.apply_preview(self.recovery(op));self.assertEqual(row['state'],'succeeded',row);self.assertFalse(target.exists())

    def test_registry_cannot_claim_pending_target_and_disabled_project_can_be_reattached(self):
        point=self.create();(self.source/'code.py').write_text('current');op=self.interrupt(point['point_id'])
        with self.assertRaises(ValueError):projects.add_project(str(self.source.parent))
        projects.remove_project(self.pid);self.assertEqual(projects.add_project(str(self.source)),self.pid)
        row=self.apply_preview(self.recovery(op));self.assertEqual(row['state'],'succeeded',row)

    def test_secret_policy_is_respected_and_uncovered_secret_overwrite_is_refused(self):
        (self.source/'.env').write_text('TOKEN=saved');point=self.create();(self.source/'.env').write_text('TOKEN=current-excluded-secret')
        (self.source/'code.py').write_text('current');backups.save_policy(self.pid,'exclude','',False,20,30)
        row=self.apply_preview(self.preview(point['point_id'],'files',files=['code.py']));self.assertEqual(row['state'],'succeeded',row)
        op=restores.operation(row['restore_op_id']);insurance=backups.verify(op['safety_point_id'])
        self.assertNotIn('.env',{e['path'] for e in insurance['files']});before=self.hashes()
        row=self.apply_preview(self.preview(point['point_id']));self.assertEqual(row['state'],'failed',row);self.assertEqual(self.hashes(),before)

    def test_incremental_after_restore_uses_regular_point_not_insurance_workspace_rules(self):
        original=self.create();(self.source/'code.py').write_text('newer backup');checkpoint=self.create('checkpoint')
        row=self.apply_preview(self.preview(original['point_id']));self.assertEqual(row['state'],'succeeded',row)
        incremental=self.create('incremental');self.assertEqual(incremental['manifest']['parent']['id'],checkpoint['point_id'])
        self.assertEqual(self.content(incremental['point_id'],'code.py'),(self.source/'code.py').read_bytes())

    def test_late_write_to_original_inode_survives_commit_and_is_not_recursively_archived(self):
        point=self.create();(self.source/'code.py').write_text('current before restore')
        fd=os.open(self.source/'code.py',os.O_RDWR)
        try:
            row=self.apply_preview(self.preview(point['point_id']));self.assertEqual(row['state'],'succeeded',row)
            op=restores.operation(row['restore_op_id'])
            data=b'late write to retained original inode';os.lseek(fd,0,0);os.write(fd,data);os.ftruncate(fd,len(data));os.fsync(fd)
            with projects.registry() as conn:step=conn.execute("SELECT seq FROM restore_steps WHERE operation_id=? AND kind='move'",(op['id'],)).fetchone()[0]
            self.assertEqual((Path(op['work_path'])/'undo'/str(step)).read_bytes(),data)
            self.assertEqual((self.source/'code.py').read_text(),'def sample():\n    return 1\n')
            new=self.create();self.assertFalse(any('.ptm-restore-' in e['path'] for e in new['manifest']['files']))
        finally:os.close(fd)

    def test_sqlite_family_fragment_cannot_be_restored_over_excluded_database(self):
        database=self.source/'records.db';conn=sqlite3.connect(database)
        try:
            conn.execute('PRAGMA journal_mode=WAL');conn.execute('PRAGMA wal_autocheckpoint=0');conn.execute('CREATE TABLE records(value TEXT)')
            conn.execute("INSERT INTO records VALUES('committed')");conn.commit()
            p=projects.get_project(self.pid)
            projects.update_project(self.pid,p['name'],p['description'],p['category'],p['exclusion_rules']+['*.db'],p['scan_settings'])
            self.cfg=projects.project_settings(projects.get_project(self.pid));projects.current_settings.set(self.cfg)
            point=self.create();self.assertIn('records.db-wal',{e['path'] for e in point['manifest']['files']})
            before=self.hashes();row=self.apply_preview(self.preview(point['point_id']))
            self.assertEqual(row['state'],'failed',row);self.assertEqual(row['error_code'],'restore_sqlite_family');self.assertEqual(self.hashes(),before)
        finally:conn.close()

    def test_workspace_swap_during_staging_never_writes_through_replacement_symlink(self):
        from app.filesystem import PRIVATE_FDS,validate_project
        point=self.create();(self.source/'code.py').write_text('current');before=self.hashes();shown=self.preview(point['point_id'])
        victim=self.root/'unrelated-directory';victim.mkdir();(victim/'keep.txt').write_text('unchanged')
        parked=self.root/'pinned-private-workspace';real=restores.Journal.stage
        def swap(journal):
            journal.canonical_work.rename(parked)
            journal.canonical_work.symlink_to(victim,target_is_directory=True)
            return real(journal)
        with patch.object(restores.Journal,'stage',new=swap):row=self.apply_preview(shown)
        self.assertIn(row['state'],('failed','interrupted'),row)
        self.assertEqual(self.hashes(),before);self.assertEqual([p.name for p in victim.iterdir()],['keep.txt'])
        self.assertEqual((victim/'keep.txt').read_text(),'unchanged');self.assertTrue((parked/'stage').is_dir())
        self.assertEqual(PRIVATE_FDS.get(),{})
        with self.assertRaises(ValueError):validate_project('/proc/self/fd/0',self.cfg)

    def test_multi_component_exclusion_preserves_nested_registered_project(self):
        (self.source/'outer').mkdir();nested=self.source/'outer/inner';nested.mkdir();(nested/'data').write_text('saved')
        point=self.create();projects.add_project(str(nested));(nested/'data').write_text('private current data')
        shown=self.preview(point['point_id']);self.assertNotIn('outer/inner/data',shown['spec']['plan']['desired'])
        row=self.apply_preview(shown);self.assertEqual(row['state'],'succeeded',row);self.assertEqual((nested/'data').read_text(),'private current data')

    def test_legacy_credential_directory_cannot_bypass_filesystem_policy(self):
        archive=self.cfg.backups_dir/'credentials.tar.gz';archive.parent.mkdir(parents=True,exist_ok=True)
        with tarfile.open(archive,'w:gz') as tar:
            data=b'not-a-real-key';entry=tarfile.TarInfo(self.source.name+'/.ssh/key');entry.size=len(data);tar.addfile(entry,io.BytesIO(data))
        archive.chmod(0o600)
        with db.db_conn() as conn:
            bid=conn.execute('INSERT INTO backups(created_at,archive_path,archive_size,sha256) VALUES(?,?,?,?)',('2026-11-11',str(archive),archive.stat().st_size,hashlib.sha256(archive.read_bytes()).hexdigest())).lastrowid
        with self.assertRaisesRegex(BackupError,'unsafe_path'):self.preview(str(bid),source_type='legacy')
        self.assertFalse((self.source/'.ssh').exists())

    def test_two_recovery_previews_cannot_queue_conflicting_undo_or_insurance(self):
        point=self.create();(self.source/'code.py').write_text('current');op=self.interrupt(point['point_id'])
        first=self.recovery(op);second=self.recovery(op);insurance=self.recovery(op,'insurance')
        jid=self.confirm(first);user,raw=self.principal()
        for shown in (second,insurance):
            with self.assertRaisesRegex(BackupError,'restore_pending'):
                restores.confirm(user,raw,shown['id'],shown['token'],'on','RESTORE')
        jobs.execute(jid);self.assertEqual(restores.operation(op)['state'],'rolled_back')

    def test_worker_system_exit_is_not_success_and_dispatcher_can_run_recovery(self):
        point=self.create();(self.source/'code.py').write_text('current');before=self.hashes();jid=self.confirm(self.preview(point['point_id']))
        real=restores.Journal.done;once=False;runner=jobs.Runner()
        def exit_worker(journal,seq):
            nonlocal once
            real(journal,seq)
            if not once:once=True;raise SystemExit('test worker interruption')
        try:
            with patch.object(restores.Journal,'done',new=exit_worker):
                runner.start();deadline=time.monotonic()+20
                while time.monotonic()<deadline:
                    row=next(j for j in jobs.job_rows(self.pid) if j['id']==jid)
                    if row['state'] in jobs.TERMINAL:break
                    time.sleep(.05)
                self.assertEqual(row['state'],'failed',row);op=row['restore_op_id'];self.assertEqual(restores.operation(op)['state'],'interrupted')
                recovery=self.confirm(self.recovery(op));deadline=time.monotonic()+20
                while time.monotonic()<deadline:
                    row=next(j for j in jobs.job_rows(self.pid) if j['id']==recovery)
                    if row['state'] in jobs.TERMINAL:break
                    time.sleep(.05)
                self.assertEqual(row['state'],'succeeded',row);self.assertEqual(self.hashes(),before)
        finally:runner.close()
