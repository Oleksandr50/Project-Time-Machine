@echo off
setlocal
where wsl.exe >nul 2>nul
if errorlevel 1 (
  echo WSL2 is required. Run Install-Windows.ps1 first.
  exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0Start-Windows.ps1" %*
exit /b %errorlevel%
