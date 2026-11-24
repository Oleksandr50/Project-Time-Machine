param([string]$Distribution = 'Ubuntu-24.04', [int]$Port, [string]$Prefix = '')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'scripts/windows-wsl.ps1')
if ($PSBoundParameters.ContainsKey('Port') -and ($Port -lt 1024 -or $Port -gt 65535)) { throw 'Port must be 1024-65535.' }
$context = Get-PTMWslContext $Distribution $Prefix
$linuxSource = Convert-PTMWslText (Invoke-PTMWsl $Distribution @('wslpath', '-a', $PSScriptRoot))
if (-not $linuxSource.StartsWith('/')) { throw 'Could not translate the source path for WSL.' }
$installArguments = @('--prefix', $context.Prefix)
if ($PSBoundParameters.ContainsKey('Port')) { $installArguments += @('--port', [string]$Port) }
& wsl.exe -d $Distribution --exec bash -l "$linuxSource/install.sh" @installArguments
if ($LASTEXITCODE -ne 0) { throw 'Installation failed. See the Linux error above. Ubuntu 24.04 prerequisites: sudo apt update; sudo apt install python3 python3-venv ca-certificates. Python 3.11-3.13 (including uv-managed Python) is required. Run this installer without sudo.' }
$status = Get-PTMWslStatus $Distribution $context.Manager
Write-Host "Installed in $($context.Prefix). Server URL: http://localhost:$($status.port)"
if (-not $status.running) { Write-Host 'Application is stopped by its existing settings. Run Start-Windows.ps1 with the same -Distribution and -Prefix.' }
Write-Host 'The application and its data live in the Linux filesystem in WSL2. Docker is not required.'
Write-Host 'For first administrator setup, run bin/ptm setup-code inside the installation if the browser requests an owner code. Existing installations retain their current administrator.'
