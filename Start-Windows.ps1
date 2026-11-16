param([string]$Distribution = 'Ubuntu-24.04')
$ErrorActionPreference = 'Stop'
$linuxHome = ((& wsl.exe -d $Distribution --exec printenv HOME) -join '').Trim()
if ($LASTEXITCODE -ne 0 -or -not $linuxHome.StartsWith('/')) { throw 'Start Ubuntu and complete its user setup first.' }
$manager = "$linuxHome/.local/share/project-time-machine/bin/ptm"
& wsl.exe -d $Distribution --exec $manager start
if ($LASTEXITCODE -ne 0) { throw 'Could not start Project Time Machine. Run Install-Windows.ps1 first.' }
$status = (& wsl.exe -d $Distribution --exec $manager status) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Could not read installation status.' }
Start-Process "http://localhost:$($status.port)"
