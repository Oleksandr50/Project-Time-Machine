"""Deployment safety and update integration on disposable state only."""
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
import hashlib,json,os,shutil,sqlite3,subprocess,tempfile,unittest
import test_stage2 as stage2
from app import projects,db,auth,migrations,backups,maintenance,installation,release
from app.lifecycle import guard


class DeploymentTests(stage2.AuthFixture):
    def setUp(self):
        super().setUp();self.setup();self.pid,self.source=self.project('sample')
        self.project_cfg=projects.project_settings(projects.get_project(self.pid))
    def point(self):
        with guard(self.cfg.data_dir,exclusive=True):return maintenance.checkpoint(self.cfg,self.root/'checkpoint')

    def test_health_local_only_no_session_or_credentials(self):
        with projects.registry() as c:before=c.execute('SELECT count(*) FROM sessions').fetchone()[0]
        guest=self.client();r=guest.get('/healthz');self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['status'],'ok');self.assertNotIn(auth.COOKIE,guest.cookies)
        with projects.registry() as c:self.assertEqual(before,c.execute('SELECT count(*) FROM sessions').fetchone()[0])
        self.assertEqual(self.client(peer='192.168.1.7').get('/healthz').status_code,403)
        self.assertEqual(guest.get('/healthz',headers={'x-forwarded-for':'127.0.0.1'}).status_code,403)
        self.assertEqual(guest.post('/healthz').status_code,404)

    def test_live_lifecycle_prevents_maintenance(self):
        with guard(self.cfg.data_dir):
            with self.assertRaisesRegex(ValueError,'running'):
                with guard(self.cfg.data_dir,exclusive=True):pass
        with guard(self.cfg.data_dir,exclusive=True):
            with self.assertRaisesRegex(ValueError,'running'):
                with guard(self.cfg.data_dir):pass

    def test_legacy_state_parent_permissions_are_preserved(self):
        data=self.root/'legacy-permissions';data.mkdir(mode=0o755);data.chmod(0o755)
        with guard(data):pass
        self.assertEqual(data.stat().st_mode&0o777,0o755)
        self.assertEqual((data/'.maintenance').stat().st_mode&0o777,0o700)

    def test_checkpoint_preserves_ids_password_hash_history_and_archives(self):
        token=projects.current_settings.set(self.project_cfg)
        try:point=backups.create('full',actor_id=1)
        finally:projects.current_settings.reset(token)
        before=self.source.joinpath('code.py').read_bytes();archive=Path(point['archive_path']);digest=maintenance.checksum(archive)
        manifest=self.point();self.assertEqual(len(manifest['databases']),2)
        self.assertFalse(manifest['archives_copied']);self.assertFalse(manifest['content_copied'])
        maintenance.verify_checkpoint(self.root/'checkpoint');maintenance.rehearse(self.root/'checkpoint')
        self.assertEqual(maintenance.checksum(archive),digest);self.assertEqual((self.source/'code.py').read_bytes(),before)
        with closing(sqlite3.connect(self.root/'checkpoint/databases/projects.sqlite')) as c:
            self.assertEqual(c.execute('SELECT id FROM users').fetchall(),[(1,)])
            self.assertTrue(c.execute('SELECT password_hash FROM users').fetchone()[0].startswith('$argon2id$'))
        self.assertTrue(all(p.stat().st_mode&0o077==0 for p in (self.root/'checkpoint').rglob('*') if p.is_file()))

    def test_checkpoint_detects_tampering_before_migration_or_recovery(self):
        manifest=self.point();p=self.root/'checkpoint/databases'/manifest['databases'][0]['relative_path'];p.write_bytes(p.read_bytes()[:-20]+b'tampered')
        for operation in (maintenance.verify_checkpoint,maintenance.rehearse):
            with self.assertRaises(ValueError):operation(self.root/'checkpoint')
        with self.assertRaises(ValueError):maintenance.recover(self.cfg,self.root/'checkpoint')

    def test_failed_directory_sync_never_publishes_a_verified_checkpoint(self):
        before=maintenance.checksum(self.project_cfg.db_path)
        with patch.object(maintenance,'sync_directory',side_effect=OSError('simulated fsync failure')):
            with self.assertRaises(OSError):self.point()
        self.assertFalse((self.root/'checkpoint/manifest.json').exists())
        self.assertEqual(before,maintenance.checksum(self.project_cfg.db_path))

    def test_rehearsal_detects_changed_values_even_when_counts_match(self):
        self.point();before=maintenance.checksum(self.project_cfg.db_path)
        steps=[*migrations.MIGRATIONS['history'],(5,'bad-update',lambda c:c.execute("UPDATE snapshots SET description='changed without row count change'"))]
        with patch.dict(migrations.MIGRATIONS,{'history':steps}):
            with self.assertRaisesRegex(ValueError,'old rows'):maintenance.rehearse(self.root/'checkpoint')
        self.assertEqual(maintenance.checksum(self.project_cfg.db_path),before)

    def test_recovery_preserves_current_state_separately_and_restores_old_rows(self):
        self.point()
        with closing(sqlite3.connect(self.project_cfg.db_path)) as c:c.execute("UPDATE snapshots SET description='post-checkpoint'");c.commit()
        with guard(self.cfg.data_dir,exclusive=True):maintenance.recover(self.cfg,self.root/'checkpoint')
        self.assertTrue(list((self.root/'checkpoint/superseded').rglob('*.sqlite')))
        with closing(sqlite3.connect(self.project_cfg.db_path)) as c:self.assertNotEqual(c.execute('SELECT description FROM snapshots LIMIT 1').fetchone()[0],'post-checkpoint')

    def test_external_history_and_symlink_state_are_refused(self):
        outside=self.root/'outside.sqlite';outside.write_bytes(b'outside-data');before=outside.read_bytes()
        with projects.registry() as c:c.execute('UPDATE projects SET history_path=?',(str(outside),))
        with self.assertRaisesRegex(ValueError,'External history'):maintenance.databases(self.cfg)
        self.assertEqual(outside.read_bytes(),before)
        with projects.registry() as c:c.execute('UPDATE projects SET history_path=?',(str(self.project_cfg.db_path),))
        (self.cfg.data_dir/'link.sqlite').symlink_to(self.project_cfg.db_path)
        with self.assertRaisesRegex(ValueError,'Unsafe state'):maintenance.databases(self.cfg)

    def test_old_history_is_rehearsed_and_migrated_without_losing_snapshot_id(self):
        state=self.root/'old-state';state.mkdir(mode=0o700);database=state/'history.sqlite';cfg=replace(self.cfg,data_dir=state)
        with patch.dict(migrations.MIGRATIONS,{'history':migrations.MIGRATIONS['history'][:3]}):migrations.migrate(database,'history',self.root/'old-backups')
        with closing(sqlite3.connect(database)) as c:
            c.execute("INSERT INTO snapshots(id,created_at,description,agent_root,total_files,python_files,total_bytes,functions_count,classes_count,sqlite_files,log_files) VALUES(37,'2026-01-01','retained','/example',1,1,1,1,0,0,0)");c.commit()
        with guard(state,exclusive=True):
            maintenance.checkpoint(cfg,self.root/'old-checkpoint');maintenance.rehearse(self.root/'old-checkpoint');maintenance.migrate_checked(cfg,self.root/'old-checkpoint')
        with closing(sqlite3.connect(database)) as c:
            self.assertEqual(c.execute('SELECT id,description,content_status FROM snapshots').fetchall(),[(37,'retained','metadata_only')])
            self.assertEqual(c.execute('PRAGMA user_version').fetchone()[0],4)

    def test_startup_refuses_interrupted_update_and_keeps_data(self):
        prefix=self.root/'managed';(prefix/'state').mkdir(parents=True,mode=0o700)
        (prefix/'installation.json').write_text('{}');(prefix/'update-journal.json').write_text('{"phase":"migrating"}')
        with self.assertRaisesRegex(ValueError,'Interrupted update'):
            with guard(prefix/'state'):pass
        with guard(prefix/'state',exclusive=True):pass

    def test_interrupted_database_recovery_can_resume_without_losing_superseded_state(self):
        self.point();real=os.replace;cut=[]
        def interrupt(src,dest):
            real(src,dest)
            if 'superseded' in Path(dest).parts and not cut:cut.append(True);raise OSError('simulated interruption')
        with guard(self.cfg.data_dir,exclusive=True),patch.object(maintenance.os,'replace',side_effect=interrupt):
            with self.assertRaises(OSError):maintenance.recover(self.cfg,self.root/'checkpoint')
        with guard(self.cfg.data_dir,exclusive=True):maintenance.recover(self.cfg,self.root/'checkpoint')
        self.assertTrue(list((self.root/'checkpoint/superseded').rglob('*.sqlite')))
        with projects.registry() as c:self.assertEqual(c.execute('SELECT id FROM users').fetchall()[0][0],1)

    def test_pending_container_deployment_blocks_startup(self):
        maintenance.atomic_json(self.cfg.data_dir/'deployment-journal.json',dict(phase='migrating'))
        with self.assertRaisesRegex(ValueError,'Interrupted deployment'):
            with guard(self.cfg.data_dir):pass
        with guard(self.cfg.data_dir,exclusive=True):pass

    def test_container_process_visibility_is_explicitly_incomplete(self):
        from app.restore_fs import processes
        with patch.dict(os.environ,{'PTM_CONTAINER':'1'}):self.assertFalse(processes(self.source)['complete'])


class PackagingTests(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()

    def test_public_export_excludes_all_runtime_and_personal_configuration(self):
        result=release.build(self.root/'export');self.assertEqual(result['status'],'verified');self.assertFalse(result['published'])
        tree=self.root/'export'/('project-time-machine-'+__import__('app.version',fromlist=['VERSION']).VERSION)
        self.assertEqual(release.scan(tree,history=True)['status'],'passed')
        import tarfile
        with tarfile.open(self.root/'export'/(tree.name+'.tar.gz')) as archive:
            self.assertTrue(all(m.uid==m.gid==m.mtime==0 and not m.uname and not m.gname and not m.pax_headers for m in archive.getmembers()))
        self.assertFalse(any(p.suffix in ('.db','.sqlite','.key','.ptm') or p.name=='settings.local.json' for p in tree.rglob('*')))
        self.assertFalse(any(p.name.startswith('private-stage') or p.name in ('runtime','.venv','checkpoints') for p in tree.rglob('*')))
        manifest=json.loads((tree/'release-manifest.json').read_text())
        self.assertTrue(all(maintenance.checksum(tree/name)==digest for name,digest in manifest['files'].items()))
        self.assertNotIn(str(Path.home())+'/',(tree/'README.md').read_text())

    def test_export_and_scanner_do_not_print_secret_values(self):
        marker='ghp_'+'q'*36;p=self.root/'unsafe.txt';p.write_text(marker)
        report=release.scan(self.root);self.assertEqual(report['status'],'failed');self.assertNotIn(marker,json.dumps(report))
        p.write_bytes(b'SQLite format 3\0' + b'x'*50);self.assertIn('sqlite_database',release.inspect_bytes(p.name,p.read_bytes()))
        (self.root/'.env').write_text('PASSWORD=unpublished-marker')
        self.assertTrue(any(x['kind']=='private_file' for x in release.scan(self.root)['findings']))

    def test_scan_history_detects_removed_secret_without_outputting_it(self):
        if not shutil.which('git'):self.skipTest('git is not installed')
        subprocess.run(['git','init','-q',str(self.root)],check=True,env={**os.environ,'GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_NOSYSTEM':'1'})
        marker='ghp_'+'r'*36;(self.root/'gone.txt').write_text(marker)
        env={**os.environ,'GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_NOSYSTEM':'1','GIT_AUTHOR_NAME':'Fixture','GIT_AUTHOR_EMAIL':'fixture@example.invalid','GIT_COMMITTER_NAME':'Fixture','GIT_COMMITTER_EMAIL':'fixture@example.invalid'}
        subprocess.run(['git','-C',str(self.root),'add','gone.txt'],check=True,env=env);subprocess.run(['git','-C',str(self.root),'commit','-qm','fixture'],check=True,env=env)
        subprocess.run(['git','-C',str(self.root),'rm','-q','gone.txt'],check=True,env=env);subprocess.run(['git','-C',str(self.root),'commit','-qm','remove fixture'],check=True,env=env)
        report=release.scan(self.root,history=True);self.assertEqual(report['status'],'failed');self.assertEqual(report['git_history'],'scanned');self.assertNotIn(marker,json.dumps(report))

    def test_scan_skips_large_private_backups_without_reading_them(self):
        private=self.root/'private-stage0';private.mkdir();p=private/'large.tar';p.write_bytes(b'not inspected')
        real=Path.read_bytes
        with patch.object(Path,'read_bytes',lambda x:(_ for _ in ()).throw(AssertionError('Private backup read')) if x==p else real(x)):
            report=release.scan(self.root)
        self.assertEqual(report['status'],'failed')

    def test_installer_rejects_nonempty_unmarked_and_dangerous_prefixes(self):
        p=self.root/'not-app';p.mkdir();(p/'keep').write_text('keep')
        with self.assertRaisesRegex(ValueError,'empty'):installation.install(release.ROOT,p,no_start=True)
        self.assertEqual((p/'keep').read_text(),'keep')
        for value in ('/','/tmp',str(Path.home())):
            with self.assertRaises(ValueError):installation.prefix_path(value)

    def test_pid_reuse_or_forged_pid_cannot_signal_another_process(self):
        prefix=self.root/'app';prefix.mkdir(mode=0o700)
        maintenance.atomic_json(prefix/'installation.json',dict(format_version=1,id='synthetic-instance',prefix=str(prefix),port=13011,owner_uid=os.geteuid()))
        maintenance.atomic_json(prefix/'process.json',dict(pid=os.getpid(),start_time='wrong-start-time'))
        with patch.object(installation.os,'kill') as kill,patch.object(installation,'pidfd_send_signal') as send:
            with self.assertRaisesRegex(ValueError,'identity'):installation.stop(prefix)
            kill.assert_not_called();send.assert_not_called()

    def test_owned_process_is_stopped_through_pidfd_without_environment_exit_race(self):
        import sys
        prefix=self.root/'owned';prefix.mkdir(mode=0o700)
        maintenance.atomic_json(prefix/'installation.json',dict(format_version=1,id='synthetic-child',prefix=str(prefix),port=13011,owner_uid=os.geteuid()))
        env={**os.environ,'PTM_MANAGED_ID':'synthetic-child','PTM_CONFIG':str(prefix/'config/settings.json')}
        child=subprocess.Popen([sys.executable,'-B','-c','import time;time.sleep(30)'],env=env)
        try:
            stat=(Path('/proc')/str(child.pid)/'stat').read_text().split(') ',1)[1].split()
            maintenance.atomic_json(prefix/'process.json',dict(pid=child.pid,start_time=stat[19]))
            self.assertTrue(installation.stop(prefix));self.assertEqual(child.wait(timeout=3),-15)
        finally:
            if child.poll() is None:child.terminate();child.wait(timeout=3)

    def test_busy_port_is_reported_without_stopping_its_owner(self):
        import socket
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
            with patch.object(installation.os,'kill') as kill:
                with self.assertRaisesRegex(ValueError,'occupied'):installation.choose_port(port)
                kill.assert_not_called()
        self.assertEqual(installation.choose_port(port),port)

    def test_zombie_and_exit_race_do_not_require_reading_dead_process_environment(self):
        prefix=self.root/'exiting';prefix.mkdir(mode=0o700)
        maintenance.atomic_json(prefix/'installation.json',dict(format_version=1,id='synthetic-instance',prefix=str(prefix),port=13011,owner_uid=os.geteuid()))
        maintenance.atomic_json(prefix/'process.json',dict(pid=os.getpid(),start_time='1234'))
        real_text=Path.read_text;real_bytes=Path.read_bytes;proc=Path('/proc')/str(os.getpid())
        for states in (['Z'],['X'],['S','Z'],['S','X']):
            sequence=list(states)
            def text(path,*args,**kwargs):
                if path==proc/'stat':return str(os.getpid())+' (fixture) '+' '.join([sequence.pop(0),*['0']*18,'1234'])
                return real_text(path,*args,**kwargs)
            def raw(path,*args,**kwargs):
                if path==proc/'environ':raise PermissionError('exited during read')
                return real_bytes(path,*args,**kwargs)
            with patch.object(Path,'read_text',text),patch.object(Path,'read_bytes',raw),patch.object(installation.os,'kill') as kill:
                self.assertIsNone(installation.process(prefix));kill.assert_not_called()

    def test_service_definition_uses_only_owned_unit_and_retains_data(self):
        prefix=self.root/'app';prefix.mkdir(mode=0o700)
        maintenance.atomic_json(prefix/'installation.json',dict(format_version=1,id='synthetic-instance',prefix=str(prefix),port=13011,owner_uid=os.geteuid()))
        with patch.object(Path,'home',return_value=self.root/'home'),patch.object(installation.subprocess,'run',return_value=__import__('types').SimpleNamespace(returncode=0)) as run:
            installation.install_service(prefix);unit=installation.unit_path(prefix)
            self.assertIn('UMask=0077',unit.read_text());self.assertIn('NoNewPrivileges=true',unit.read_text())
            self.assertTrue(all('--user' in call.args[0] for call in run.call_args_list))
            unit.write_text('# unrelated service')
            with self.assertRaisesRegex(ValueError,'ownership'):installation.service_owned(prefix)

    def test_docker_prepare_is_empty_idempotent_and_refuses_recursive_mounts(self):
        script=release.ROOT/'scripts/docker_prepare.py'
        for _ in range(2):subprocess.run([__import__('sys').executable,'-B',str(script),'--directory',str(self.root)],check=True,capture_output=True)
        cfg=json.loads((self.root/'docker-config/settings.json').read_text());self.assertEqual(cfg['allowed_roots'],['/projects'])
        self.assertEqual(cfg['encryption_keys'],{});self.assertFalse(list((self.root/'docker-state').rglob('*.sqlite')))
        result=subprocess.run([__import__('sys').executable,'-B',str(script),'--directory',str(self.root),'--projects',str(self.root)],capture_output=True)
        self.assertNotEqual(result.returncode,0)

    def test_windows_wrappers_pass_arguments_directly_and_do_not_require_docker(self):
        installer=(release.ROOT/'Install-Windows.ps1').read_text();starter=(release.ROOT/'Start-Windows.ps1').read_text()
        self.assertIn('--exec bash',installer);self.assertNotIn('Invoke-Expression',installer+starter);self.assertNotIn('docker.exe',installer+starter)
        self.assertIn('--exec $manager start',starter)
