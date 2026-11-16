"""Targeted release resource paths, launcher errors and blank setup input only."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import copy,hashlib,importlib.util,json,os,shlex,shutil,socket,sqlite3,subprocess,sys,tarfile,tempfile,unittest
from urllib.request import build_opener,ProxyHandler,Request
from app import config,installation as install


class ResourcePathTests(unittest.TestCase):
    def test_resources_always_follow_imported_code_and_legacy_prefix_stays_protected(self):
        with tempfile.TemporaryDirectory(prefix='ptm-resource-check-') as tmp:
            prefix=Path(tmp)/'custom installation';prefix.mkdir()
            cfg=config.Settings(app_root=prefix,data_dir=prefix/'state')
            self.assertEqual(cfg.app_root,config.CODE_ROOT)
            self.assertEqual(cfg.static_dir,config.CODE_ROOT/'app/static')
            self.assertEqual(cfg.templates_dir,config.CODE_ROOT/'app/templates')
            self.assertEqual(cfg.locales_dir,config.CODE_ROOT/'app/locales')
            self.assertIn(prefix,cfg.storage_roots);self.assertEqual(cfg.data_dir,prefix/'state')
    def test_loading_legacy_json_changes_neither_persistent_paths_nor_the_file(self):
        with tempfile.TemporaryDirectory(prefix='ptm-legacy-path-check-') as tmp:
            prefix=Path(tmp);document=install.fresh_configuration(prefix);document['app_root']=str(prefix/'releases/old-version')
            file=prefix/'settings.json';file.write_text(json.dumps(document));before=file.read_bytes()
            with patch.dict(os.environ,{'PTM_CONFIG':str(file)}):cfg=config.load_settings()
            self.assertEqual(cfg.app_root,config.CODE_ROOT)
            for key in ('data_dir','backups_dir','content_dir','reports_dir','db_path','metadata_dir','logs_dir','temp_dir'):
                self.assertEqual(str(getattr(cfg,key)),document[key])
            self.assertEqual(file.read_bytes(),before)
    def test_fresh_configuration_does_not_persist_a_release_or_prefix_as_app_root(self):
        with tempfile.TemporaryDirectory(prefix='ptm-fresh-path-check-') as tmp:
            prefix=Path(tmp)/'custom';doc=install.fresh_configuration(prefix)
            self.assertNotIn('app_root',doc);self.assertIn(str(prefix),doc['protected_roots'])
    def test_template_and_translation_directories_are_resolved_code_paths(self):
        from app import ui,i18n
        self.assertEqual(ui.templates.env.loader.searchpath,[str(config.CODE_ROOT/'app/templates')])
        self.assertEqual(i18n.DIRECTORY,config.CODE_ROOT/'app/locales')
        self.assertTrue({'ru','en','pl','uk'}<=set(i18n.CATALOGS))
    def test_empty_enter_in_ip_and_port_preserves_saved_values_without_errors(self):
        with tempfile.TemporaryDirectory(prefix='ptm-enter-check-') as tmp:
            prefix=Path(tmp);(prefix/'config').mkdir();(prefix/'current/app').mkdir(parents=True)
            (prefix/'current/app/setup_config.py').write_text('# marker')
            info=dict(format_version=1,id='synthetic-setup',prefix=str(prefix),owner_uid=os.geteuid(),port=13021,bind_address='127.0.0.1')
            doc=install.fresh_configuration(prefix)
            install.atomic_json(prefix/'installation.json',info);install.atomic_json(prefix/'config/settings.json',doc)
            spec=importlib.util.spec_from_file_location('ptm_setup_enter',Path(__file__).resolve().parents[1]/'scripts/setup.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            answers=iter(['3','','4','   ','11','y','0']);output=[]
            with patch.dict(os.environ),patch.object(install,'start') as start,patch.object(install,'stop') as stop:
                self.assertEqual(module.main(['--prefix',str(prefix)],input_fn=lambda _:next(answers),out=output.append),0)
            self.assertFalse(any(line.startswith('Error:') for line in output));start.assert_not_called();stop.assert_not_called()
            self.assertEqual(json.loads((prefix/'installation.json').read_text()),info)
    def test_diagnostics_show_current_failure_not_stale_port_guess_and_mask_secrets(self):
        with tempfile.TemporaryDirectory(prefix='ptm-error-check-') as tmp:
            prefix=Path(tmp);(prefix/'logs').mkdir();log=prefix/'logs/server.log'
            stale=b'previous attempt: port occupied\n';log.write_bytes(stale+b"RuntimeError: Directory '/custom/app/static' does not exist\npassword=synthetic-sensitive-value\n")
            detail=install.startup_failure(prefix,'Application exited with code 1',len(stale))
            self.assertIn("Directory '/custom/app/static' does not exist",detail)
            self.assertNotIn('port occupied',detail);self.assertNotIn('synthetic-sensitive-value',detail)
    def test_launcher_exit_reports_the_actual_traceback(self):
        with tempfile.TemporaryDirectory(prefix='ptm-launch-error-') as tmp:
            prefix=Path(tmp);(prefix/'logs').mkdir();(prefix/'current').mkdir()
            info=dict(format_version=1,id='synthetic-error',prefix=str(prefix),owner_uid=os.geteuid(),port=13021)
            install.atomic_json(prefix/'installation.json',info)
            child=SimpleNamespace(pid=os.getpid(),returncode=1,poll=lambda:1)
            def fail(*args,**kwargs):
                kwargs['stdout'].write(b'RuntimeError: synthetic resource failure\n');kwargs['stdout'].flush();return child
            with patch.object(install,'check_process_handles'),patch.object(install,'process',return_value=None),patch.object(install,'service_owned',return_value=False),patch.object(install.subprocess,'Popen',side_effect=fail):
                with self.assertRaisesRegex(ValueError,'synthetic resource failure'):install.start(prefix)


class SeparateReleaseStartupTests(unittest.TestCase):
    def test_real_startup_assets_setup_languages_and_release_switch(self):
        if not os.environ.get('PTM_STARTUP_ARCHIVE'):self.skipTest('Set PTM_STARTUP_ARCHIVE for the focused real-startup check')
        archive=Path(os.environ['PTM_STARTUP_ARCHIVE']).resolve()
        with tempfile.TemporaryDirectory(prefix='ptm-separate-release-') as tmp:
            root=Path(tmp);home=root/'different-user home';home.mkdir();prefix=home/'custom PTM';prefix.mkdir(mode=0o700)
            releases=[prefix/'releases/0.7.2-first',prefix/'releases/0.7.2-second']
            with tarfile.open(archive) as t:
                app_files={m.name.split('/',1)[1]:t.extractfile(m).read() for m in t.getmembers() if m.isfile() and m.name.split('/',1)[1].startswith('app/')}
            for release in releases:
                for name,data in app_files.items():
                    path=release/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
                # Reuse the existing test interpreter; do not install Python/dependencies or create a venv.
                interpreter=release/'venv/bin/python';interpreter.parent.mkdir(parents=True)
                interpreter.write_text('#!/bin/sh\nexec '+shlex.quote(sys.executable)+' "$@"\n');interpreter.chmod(0o755)
            doc=install.fresh_configuration(prefix);doc['allowed_roots']=[str(home)]
            for field in ('config_dir','data_dir','backups_dir','reports_dir','metadata_dir','content_dir','logs_dir','temp_dir','migrations_dir'):Path(doc[field]).mkdir(parents=True,exist_ok=True)
            (prefix/'updates').mkdir();sentinel=prefix/'state/persistent-data.marker';sentinel.write_bytes(b'preserve between releases')
            with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
            info=dict(format_version=1,id='synthetic-startup-instance',prefix=str(prefix),owner_uid=os.geteuid(),port=port,bind_address='127.0.0.1')
            install.atomic_json(prefix/'installation.json',info)
            http=build_opener(ProxyHandler({}));base='http://127.0.0.1:'+str(port);children=[];popen=subprocess.Popen
            def track(*args,**kwargs):
                child=popen(*args,**kwargs);children.append(child);return child
            for release,legacy in [(releases[0],None),(releases[0],prefix),(releases[1],releases[0])]:
                current=copy.deepcopy(doc)
                if legacy is not None:current['app_root']=str(legacy)
                install.atomic_json(prefix/'config/settings.json',current);saved=(prefix/'config/settings.json').read_bytes()
                install.activate(prefix,release)
                # Import from a release while cwd is unrelated, with the exact same config used by the server.
                code='import sys,json;sys.path.insert(0,'+repr(str(release))+');from app.config import base_settings as s;from app import ui,i18n;print(json.dumps(dict(app_root=str(s.app_root),static=str(s.static_dir),templates=ui.templates.env.loader.searchpath,locales=str(i18n.DIRECTORY),data=str(s.data_dir))))'
                paths=json.loads(subprocess.check_output([sys.executable,'-B','-c',code],cwd=root,env=install.environment(prefix),text=True))
                self.assertEqual(paths,dict(app_root=str(release),static=str(release/'app/static'),templates=[str(release/'app/templates')],locales=str(release/'app/locales'),data=str(prefix/'state')))
                try:
                    with patch.object(install.subprocess,'Popen',side_effect=track):install.start(prefix)
                    for path in ('/static/css/app.css','/static/js/app.js'):
                        with http.open(base+path,timeout=5) as response:
                            self.assertEqual(response.status,200);self.assertTrue(response.read())
                    for language in ('ru','en','pl','uk'):
                        with http.open(Request(base+'/setup?lang='+language),timeout=5) as response:
                            self.assertEqual(response.status,200);self.assertIn('lang="'+language+'"',response.read().decode())
                    self.assertEqual((prefix/'config/settings.json').read_bytes(),saved)
                    self.assertEqual(sentinel.read_bytes(),b'preserve between releases')
                    self.assertFalse((release/'runtime').exists())
                    with sqlite3.connect('file:'+str(prefix/'state/projects.sqlite')+'?mode=ro',uri=True) as database:
                        self.assertEqual(database.execute('SELECT count(*) FROM users').fetchone()[0],0)
                        self.assertEqual(database.execute('SELECT count(*) FROM projects').fetchone()[0],0)
                finally:
                    install.stop(prefix)
                    for child in children:
                        if child.poll() is None:child.wait(timeout=10)
            self.assertEqual(len(children),3)
            # Reproduce the user's exact failure on disposable release files only.
            static=releases[1]/'app/static';held=releases[1]/'app/static-held'
            static.rename(held)
            try:
                with patch.object(install.subprocess,'Popen',side_effect=track):
                    with self.assertRaises(ValueError) as failure:install.start(prefix)
                message=str(failure.exception)
                self.assertIn('RuntimeError: Directory',message)
                self.assertIn(str(static),message);self.assertIn('does not exist',message)
                self.assertNotIn('port may be occupied',message)
            finally:
                install.stop(prefix)
                for child in children:
                    if child.poll() is None:child.wait(timeout=10)
                held.rename(static)
            self.assertEqual(len(children),4)


if __name__=='__main__':unittest.main()
