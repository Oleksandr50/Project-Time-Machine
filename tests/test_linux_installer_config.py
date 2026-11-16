"""Only installer/settings checks: no app install, database, daemon or browser."""
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch,MagicMock
import copy,importlib.util,json,os,subprocess,tempfile,unittest
from app import installation as i,setup_config as c
from app.filesystem import validate_project,validate_allowed_root


class LinuxInstallerConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ptm-config-check-');self.root=Path(self.temp.name)
        self.home=self.root/'home with spaces';self.home.mkdir();self.prefix=self.home/'ProjectTimeMachine';self.prefix.mkdir(mode=0o700)
        self.home_patch=patch.object(i,'user_home',return_value=self.home);self.home_patch.start()
        self.doc=i.fresh_configuration(self.prefix)
        for value in self.doc.values():
            if isinstance(value,str) and value.startswith(str(self.prefix)) and not value.endswith('.sqlite'):Path(value).mkdir(parents=True,exist_ok=True)
        (self.prefix/'updates').mkdir(exist_ok=True);(self.prefix/'keys').mkdir(exist_ok=True)
        (self.prefix/'current/app').mkdir(parents=True);(self.prefix/'current/app/setup_config.py').write_text('# capability marker\n')
        self.info=dict(format_version=1,id='synthetic-owned-install',prefix=str(self.prefix),owner_uid=os.geteuid(),port=13011,bind_address='127.0.0.1',autostart_after_install=True,autostart_on_boot=False)
        c.atomic_json(self.prefix/'installation.json',self.info);c.atomic_json(self.prefix/'config/settings.json',self.doc)
        self.patches=[patch.object(i,'process',return_value=None),patch.object(i,'service_active',return_value=False),patch.object(i,'stop'),patch.object(i,'start'),patch('app.lifecycle.guard',return_value=nullcontext()),patch.object(c.socket,'socket')]
        for p in self.patches:p.start()
    def tearDown(self):
        self.assertFalse(list(self.root.rglob('*.sqlite')),'Configuration checks must never create a database')
        for p in reversed(self.patches):p.stop()
        self.home_patch.stop();self.temp.cleanup()
    def test_home_is_from_system_account_not_developer_home_or_environment(self):
        self.home_patch.stop()
        with patch('pwd.getpwuid',return_value=SimpleNamespace(pw_dir=str(self.home))),patch.dict(os.environ,{'HOME':'/unrelated-home'}):
            self.assertEqual(i.user_home(),self.home);self.assertEqual(i.default_prefix(),self.home/'ProjectTimeMachine')
        self.home_patch.start()
    def test_fresh_layout_is_dynamic_and_home_is_a_parent_authorization(self):
        cfg=c.settings_object(self.doc);self.assertEqual(self.doc['allowed_roots'],[str(self.home)])
        self.assertEqual(validate_allowed_root(self.home,cfg),self.home)
        source=self.home/'my-project';source.mkdir();before=source.stat().st_mode
        self.assertEqual(validate_project(source,cfg),source);self.assertEqual(source.stat().st_mode,before)
        for path in (self.prefix,self.prefix/'keys',self.home):
            with self.assertRaises(ValueError):validate_project(path,cfg)
        for field in ('data_dir','config_dir','backups_dir','reports_dir','content_dir','logs_dir','temp_dir','metadata_dir','migrations_dir','db_path'):
            self.assertTrue(Path(self.doc[field]).is_relative_to(self.prefix))
    def test_custom_prefix_and_custom_project_root(self):
        source=self.home/'code';source.mkdir();custom=self.home/'custom install'
        value=i.fresh_configuration(custom,source)
        self.assertEqual(value['allowed_roots'],[str(source)]);self.assertEqual(value['data_dir'],str(custom/'state'))
    def test_tilde_expands_through_system_home_and_paths_reject_traversal(self):
        self.assertEqual(c.user_path('~/code'),self.home/'code')
        for bad in ('relative','~/../other','/tmp/a/../b','/tmp/a\nfile'):
            with self.assertRaises(ValueError):c.user_path(bad)
    def test_symlinks_credentials_and_protected_children_are_not_allowed(self):
        actual=self.home/'code';actual.mkdir();link=self.home/'link';link.symlink_to(actual,target_is_directory=True)
        for path in (link,self.prefix/'keys'):
            with self.assertRaises(ValueError):validate_allowed_root(path,c.settings_object(self.doc))
        ssh=self.home/'.ssh';ssh.mkdir()
        with self.assertRaises(ValueError):validate_project(ssh,c.settings_object(self.doc))
    def test_home_and_custom_roots_can_be_saved_without_editing_json(self):
        source=self.home/'code';source.mkdir();doc=copy.deepcopy(self.doc);doc['allowed_roots'].append(str(source))
        c.apply(self.prefix,self.info,self.doc,self.info,doc)
        self.assertEqual(c.load(self.prefix)[1]['allowed_roots'],[str(self.home),str(source)])
        i.start.assert_not_called()
    def test_new_backups_keep_old_archive_roots_and_redirect_existing_project_bindings(self):
        destination=self.home/'archive store';doc=copy.deepcopy(self.doc);doc['backups_dir']=str(destination)
        rows=[(7,str(self.home/'code'),str(self.prefix/'backups/projects/7'))]
        def query(document,sql,params=()):return rows if 'SELECT id,path,backup_path' in sql else []
        with patch.object(c,'registry_rows',side_effect=query),patch.object(c,'write_bindings') as write,patch.object(c,'capture_registry'):
            c.apply(self.prefix,self.info,self.doc,self.info,doc,allow_create=True)
        saved=c.load(self.prefix)[1]
        self.assertTrue(destination.is_dir());self.assertEqual(saved['backups_dir'],str(destination))
        self.assertIn(self.doc['backups_dir'],saved['archive_roots'])
        self.assertIn(rows[0][2],saved['archive_roots'])
        self.assertEqual(write.call_args.args[1],[dict(id=7,old=rows[0][2],new=str(destination/'projects/7'))])
        self.assertTrue((self.prefix/'backups').is_dir())
    def test_backup_storage_rejects_registered_project_and_internal_keys(self):
        source=self.home/'code';source.mkdir()
        with patch.object(c,'registry_rows',return_value=[(4,str(source),'old')]):
            with self.assertRaises(ValueError):c.validate_storage(source,self.prefix,self.doc)
        with self.assertRaises(ValueError):c.validate_storage(self.prefix/'keys',self.prefix,self.doc)
    def test_storage_space_and_creation_require_confirmation(self):
        missing=self.home/'new-storage'
        with self.assertRaises(ValueError):c.validate_storage(missing,self.prefix,self.doc)
        with patch.object(c.shutil,'disk_usage',return_value=SimpleNamespace(free=1)):
            with self.assertRaisesRegex(ValueError,'free space'):c.validate_storage(missing,self.prefix,self.doc,True)
        self.assertFalse(missing.exists())
    def test_port_change_does_not_change_identity_state_or_permissions(self):
        info=dict(self.info,port=13021);before=self.prefix.stat().st_mode
        c.apply(self.prefix,self.info,self.doc,info,self.doc)
        actual,doc=c.load(self.prefix)
        self.assertEqual(actual['port'],13021);self.assertEqual(actual['id'],self.info['id']);self.assertEqual(doc['data_dir'],self.doc['data_dir'])
        self.assertEqual(self.prefix.stat().st_mode,before)
    def test_occupied_port_is_rejected_before_stop_or_save(self):
        i.stop.reset_mock()
        c.socket.socket.return_value.__enter__.return_value.bind.side_effect=OSError('occupied')
        with self.assertRaisesRegex(ValueError,'occupied'):c.apply(self.prefix,self.info,self.doc,dict(self.info,port=13022),self.doc)
        i.stop.assert_not_called();self.assertEqual(c.load(self.prefix),(self.info,self.doc))
    def test_wildcard_binding_is_allowed_before_web_setup_without_rewriting_auth_state(self):
        info,doc=c.validate(self.prefix,self.info,self.doc,dict(self.info,bind_address='0.0.0.0'),self.doc)
        self.assertEqual(info['bind_address'],'0.0.0.0');self.assertNotIn('network_enabled',doc)
    def test_health_probe_uses_loopback_source_even_for_specific_bind_address(self):
        connection=MagicMock();connection.getresponse.return_value.status=200;connection.getresponse.return_value.read.return_value=b'{"status":"ok"}'
        with patch.object(c.http.client,'HTTPConnection',return_value=connection) as factory:
            self.assertEqual(c.health_connection(dict(self.info,bind_address='192.0.2.10')),{'status':'ok'})
            factory.assert_called_with('192.0.2.10',13011,timeout=.3,source_address=('127.0.0.1',0))
            self.assertEqual(connection.request.call_args.kwargs['headers']['Host'],'127.0.0.1')
    def test_saved_bind_overrides_ambient_environment_and_old_markers_stay_loopback(self):
        with patch.dict(os.environ,{'PTM_HOST':'0.0.0.0'}):self.assertEqual(i.environment(self.prefix)['PTM_HOST'],'127.0.0.1')
    def test_repeated_noop_save_keeps_all_files_and_data_unchanged(self):
        marker=self.prefix/'state/history.keep';marker.write_bytes(b'unchanged history')
        files={p:p.read_bytes() for p in self.prefix.rglob('*') if p.is_file()}
        for _ in range(2):c.apply(self.prefix,self.info,self.doc,self.info,self.doc)
        self.assertTrue(all(p.read_bytes()==raw for p,raw in files.items()));self.assertFalse((self.prefix/'configuration-journal.json').exists())
    def test_concurrent_settings_change_is_not_overwritten(self):
        changed=dict(self.info,port=13031);c.atomic_json(self.prefix/'installation.json',changed)
        with self.assertRaisesRegex(ValueError,'concurrently'):c.apply(self.prefix,self.info,self.doc,dict(self.info,port=13021),self.doc)
        self.assertEqual(c.load(self.prefix)[0],changed)
    def test_interrupted_save_does_not_start_and_explicit_recovery_preserves_state(self):
        real=c.atomic_json;failed=[]
        def once(path,value):
            if Path(path)==self.prefix/'config/settings.json' and not failed:failed.append(True);raise OSError('interrupted')
            return real(path,value)
        with patch.object(c,'atomic_json',side_effect=once):
            with self.assertRaises(OSError):c.apply(self.prefix,self.info,self.doc,dict(self.info,port=13021),self.doc)
        self.assertTrue(i.pending(self.prefix));i.start.assert_not_called()
        c.recover(self.prefix);self.assertFalse(i.pending(self.prefix));self.assertEqual(c.load(self.prefix),(self.info,self.doc))
    def test_boot_opt_in_uses_only_owned_user_service_and_never_disables_linger(self):
        with patch.object(c.subprocess,'run',return_value=SimpleNamespace(stdout='no')) as command,patch.object(i,'install_service') as service:
            with self.assertRaisesRegex(ValueError,'explicit'):c.set_boot(self.prefix,True)
            service.assert_not_called();c.set_boot(self.prefix,True,True);service.assert_called_once_with(self.prefix)
            self.assertTrue(any(call.args[0][:2]==['loginctl','enable-linger'] for call in command.call_args_list))
        with patch.object(i,'service_owned',return_value=True),patch.object(c.subprocess,'run') as command:
            c.set_boot(self.prefix,False);self.assertEqual(command.call_args.args[0][:3],['systemctl','--user','disable'])
            self.assertNotIn('disable-linger',str(command.call_args_list))
    def test_autostart_after_install_setting_is_persistent_without_starting(self):
        c.apply(self.prefix,self.info,self.doc,dict(self.info,autostart_after_install=False),self.doc)
        self.assertFalse(c.load(self.prefix)[0]['autostart_after_install']);i.start.assert_not_called()
    def test_interactive_exit_from_arbitrary_directory_has_no_side_effects(self):
        spec=importlib.util.spec_from_file_location('ptm_setup_cli',Path(__file__).resolve().parents[1]/'scripts/setup.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with patch.dict(os.environ,{},clear=False):
            self.assertEqual(module.main(['--prefix',str(self.prefix)],input_fn=lambda _: '0',out=lambda _:None),0)
        i.start.assert_not_called();i.stop.assert_not_called();self.assertEqual(c.load(self.prefix),(self.info,self.doc))
    def test_uv_venv_uses_real_base_interpreter(self):
        actual=self.root/'base python';actual.write_text('placeholder')
        link=self.root/'python-link';link.symlink_to(actual)
        with patch.object(i.sys,'_base_executable',str(link)):
            self.assertEqual(i.base_interpreter(),str(actual))
    def test_port_falls_back_to_os_selection_if_all_standard_ports_are_busy(self):
        sock=c.socket.socket.return_value.__enter__.return_value
        sock.bind.side_effect=[*[OSError('occupied')]*21,None];sock.getsockname.return_value=('127.0.0.1',49123)
        self.assertEqual(i.choose_port(),49123);self.assertEqual(sock.bind.call_args.args[0],('127.0.0.1',0))
    def test_failed_boot_activation_does_not_claim_success_or_start_a_stopped_app(self):
        with patch.object(c,'set_boot',side_effect=ValueError('Policy refused')):
            with self.assertRaisesRegex(ValueError,'refused'):
                c.apply(self.prefix,self.info,self.doc,dict(self.info,autostart_on_boot=True),self.doc,enable_linger=True)
        self.assertFalse(c.load(self.prefix)[0]['autostart_on_boot']);i.start.assert_not_called()
    def test_uv_discovery_is_offline_independent_of_current_project_and_never_installs(self):
        root=Path(__file__).resolve().parents[1];fakebin=self.root/'fakebin';fakebin.mkdir();capture=self.root/'capture';uvargs=self.root/'uvargs'
        for name in ('python3','python3.11','python3.12','python3.13'):
            p=fakebin/name;p.write_text('#!/bin/sh\nexit 1\n');p.chmod(0o755)
        interpreter=self.root/'uv python';interpreter.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$PTM_CAPTURE"\n');interpreter.chmod(0o755)
        uv=fakebin/'uv';uv.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$PTM_UV_ARGS"\nprintf "%s\\n" "$PTM_FAKE_INTERPRETER"\n');uv.chmod(0o755)
        env={**os.environ,'PATH':str(fakebin)+':/usr/bin:/bin','PTM_CAPTURE':str(capture),'PTM_UV_ARGS':str(uvargs),'PTM_FAKE_INTERPRETER':str(interpreter)};env.pop('PTM_PYTHON',None)
        subprocess.run([str(root/'install.sh'),'--no-start'],cwd=self.root,env=env,check=True)
        self.assertIn('--offline',uvargs.read_text());self.assertIn('--no-project',uvargs.read_text());self.assertIn('--no-python-downloads',uvargs.read_text())
        self.assertEqual(capture.read_text().splitlines(),['-B',str(root/'scripts/install.py'),'--no-start'])

    def test_shell_wrappers_resolve_source_directory_and_pass_custom_prefix_verbatim(self):
        root=Path(__file__).resolve().parents[1];fake=self.root/'fake python';capture=self.root/'args'
        fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$PTM_CAPTURE"\n');fake.chmod(0o755)
        for name,script in [('install.sh','install.py'),('setup.sh','setup.py'),('start.sh','start.py')]:
            subprocess.run([str(root/name),'--prefix',str(self.prefix)],cwd=self.root,env={**os.environ,'PTM_PYTHON':str(fake),'PTM_CAPTURE':str(capture)},check=True)
            self.assertEqual(capture.read_text().splitlines(),['-B',str(root/'scripts'/script),'--prefix',str(self.prefix)])


if __name__=='__main__':unittest.main()
