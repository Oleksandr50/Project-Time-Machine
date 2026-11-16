param([string]$Distribution = 'Ubuntu-24.04', [int]$Port = 13011)
$ErrorActionPreference = 'Stop'
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw 'WSL2 is required. Run as Administrator: wsl --install -d Ubuntu-24.04, reboot if requested, create your Ubuntu user, then run this installer again.'
}
$distros = ((& wsl.exe --list --quiet) -join "`n").Replace([string][char]0, '')
if ($LASTEXITCODE -ne 0 -or $distros -notmatch [regex]::Escape($Distribution)) {
    throw "Install WSL2 first: wsl --install -d $Distribution. Complete Ubuntu user setup, then run this installer again."
}
if ($Port -lt 1024 -or $Port -gt 65535) { throw 'Port must be 1024-65535.' }
$linuxSource = ((& wsl.exe -d $Distribution --exec wslpath -a $PSScriptRoot) -join '').Trim()
if ($LASTEXITCODE -ne 0 -or -not $linuxSource) { throw 'Could not translate the source path for WSL.' }
# Pass arguments directly, without composing shell code from Windows paths.
& wsl.exe -d $Distribution --exec bash "$linuxSource/install.sh" --port $Port
if ($LASTEXITCODE -ne 0) { throw 'Installation failed. If Ubuntu reports missing venv: sudo apt install python3-venv, then retry.' }
Write-Host "Open http://localhost:$Port and create your own administrator."
Write-Host 'The engine and project data live on the Linux filesystem in WSL2. Docker is not required.'
