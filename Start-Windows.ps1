param([string]$Distribution = 'Ubuntu-24.04', [string]$Prefix = '')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'scripts/windows-wsl.ps1')
$context = Get-PTMWslContext $Distribution $Prefix
$manager = $context.Manager
& wsl.exe -d $Distribution --exec test -x $manager
if ($LASTEXITCODE -ne 0) { throw "PTM manager was not found or is not executable: $manager. Run Install-Windows.ps1 with the same -Distribution and -Prefix." }
& wsl.exe -d $Distribution --exec $manager start
if ($LASTEXITCODE -ne 0) { throw 'Could not start Project Time Machine. See the Linux diagnostics above; check -Distribution and -Prefix. If not installed, run Install-Windows.ps1 first.' }
$status = Get-PTMWslStatus $Distribution $manager
if (-not $status.running) { throw 'PTM is not running. Inspect its status and Linux logs before opening the browser.' }
Start-Process "http://localhost:$($status.port)"
