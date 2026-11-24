"""Portable checks and executable PowerShell mocks; not a real Windows/WSL trial."""
from pathlib import Path
import os,shutil,subprocess,tempfile,unittest
from app import release,installation

ROOT=Path(__file__).resolve().parents[1]


class WindowsWslTests(unittest.TestCase):
    def test_executable_powershell_scenarios(self):
        shell=os.environ.get('PTM_PWSH') or shutil.which('pwsh')
        if not shell:self.skipTest('PowerShell unavailable; Windows CI runs the executable WSL mocks separately')
        with tempfile.TemporaryDirectory(prefix='ptm-pwsh-cache-') as temp:
            result=subprocess.run([shell,'-NoProfile','-File',str(ROOT/'tests/windows_wsl_mock.ps1')],cwd=ROOT,
                env={**os.environ,'XDG_CACHE_HOME':temp,'XDG_CONFIG_HOME':temp,'POWERSHELL_TELEMETRY_OPTOUT':'1'},capture_output=True,text=True,timeout=90)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('PASS: 19 mocked PowerShell scenarios',result.stdout)

    def test_linux_installer_reports_missing_python_without_creating_state(self):
        if os.name!='posix':self.skipTest('POSIX shell test')
        with tempfile.TemporaryDirectory(prefix='ptm-python-missing-') as temp:
            folder=Path(temp);binary=folder/'bin';binary.mkdir();(binary/'dirname').symlink_to(shutil.which('dirname'))
            result=subprocess.run(['/bin/sh',str(ROOT/'install.sh'),'--prefix',str(folder/'installation')],env={**os.environ,'PATH':str(binary),'PTM_PYTHON':''},capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0);self.assertIn('Python 3.11',result.stderr);self.assertFalse((folder/'installation').exists())

    def test_shared_helper_tests_and_manual_are_in_public_export(self):
        names=release.inventory()
        for name in ['scripts/windows-wsl.ps1','tests/test_windows_wsl.py','tests/windows_wsl_mock.ps1','docs/windows-wsl.md']:
            self.assertIn(name,names)

    def test_cmd_uses_sibling_script_forwards_arguments_and_preserves_exit_code(self):
        text=(ROOT/'Start-Windows.cmd').read_text()
        self.assertIn('-File "%~dp0Start-Windows.ps1" %*',text)
        self.assertIn('exit /b %errorlevel%',text)
        self.assertIn('where wsl.exe',text)
        self.assertIn('-ExecutionPolicy RemoteSigned',text)
        self.assertNotIn('wsl --unregister',text)

    def test_wrappers_do_not_reset_wsl_or_compose_user_shell_code(self):
        text='\n'.join((ROOT/name).read_text() for name in ['Install-Windows.ps1','Start-Windows.ps1','scripts/windows-wsl.ps1'])
        for dangerous in ['Invoke-Expression','--unregister','--shutdown','--import','--set-version','bash -c']:
            if dangerous=='--set-version':
                self.assertNotIn('& wsl.exe --set-version',text)
                continue
            self.assertNotIn(dangerous,text)
        self.assertNotIn('.local/share/project-time-machine',text)
        self.assertIn('ProjectTimeMachine',text)
