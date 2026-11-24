param([string]$SourceRoot = (Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference = 'Stop'
$global:PtmScenario = 'ok'
$global:PtmCalls = @()
$global:PtmBrowser = @()
function global:wsl.exe {
    $global:PtmCalls += ,@($args)
    $global:LASTEXITCODE = 0
    $command = @($args)
    if ($command[0] -eq '--list') {
        if ($global:PtmScenario -eq 'list-failed') { $global:LASTEXITCODE = 1; return }
        if ($command[1] -eq '--quiet') {
            if ($global:PtmScenario -eq 'wrong-distro') { return 'Ubuntu-24.04-Old' }
            return "Ubuntu-24.04`0"
        }
        if ($global:PtmScenario -eq 'wsl1') { return '* Ubuntu-24.04 Stopped 1' }
        return "  NAME STATE VERSION`n* Ubuntu-24.04 Angehalten 2`0"
    }
    if ($command[0] -ne '-d' -or $command[1] -ne 'Ubuntu-24.04' -or $command[2] -ne '--exec') { throw 'Arguments to WSL were not preserved' }
    switch ($command[3]) {
        'id' { if ($global:PtmScenario -eq 'root') { return '0' }; return '1000' }
        'getent' { return 'test:x:1000:1000:Test:/home/test user:/bin/bash' }
        'cat' { if ($global:PtmScenario -eq 'not-ubuntu') { return 'ID=debian' }; return 'ID=ubuntu' }
        'realpath' { return $command[6] }
        'wslpath' { return '/mnt/c/Installer with spaces & symbols' }
        'test' { if ($global:PtmScenario -eq 'missing-manager') { $global:LASTEXITCODE = 1 }; return }
        'bash' {
            if ($global:PtmScenario -in @('python-missing', 'venv-missing')) { $global:LASTEXITCODE = 42; return 'Python/venv prerequisite is missing' }
            return 'Linux installer output'
        }
        default {
            if ($command[3] -notlike '*/bin/ptm') { throw 'Unexpected manager path' }
            if ($command[4] -eq 'start') {
                if ($global:PtmScenario -eq 'start-failed') { $global:LASTEXITCODE = 1 }
                return
            }
            if ($command[4] -eq 'status') {
                if ($global:PtmScenario -eq 'status-failed') { $global:LASTEXITCODE = 7; return 'not JSON: failed command' }
                if ($global:PtmScenario -eq 'bad-json') { return 'not JSON' }
                return '{"port":13021,"running":true}'
            }
            throw 'Unexpected manager command'
        }
    }
}
function global:Get-Command {
    param([string]$Name, [string]$ErrorAction)
    if ($Name -eq 'wsl.exe' -and $global:PtmScenario -eq 'missing-wsl') { return $null }
    return Microsoft.PowerShell.Core\Get-Command @PSBoundParameters
}
function global:Start-Process { param([string]$FilePath); $global:PtmBrowser += $FilePath }
function Assert-PTM { param([bool]$Condition, [string]$Message); if (-not $Condition) { throw $Message } }
$passed = 0
function Invoke-PTMCase {
    param([string]$Scenario, [scriptblock]$Action, [bool]$Fails = $false)
    $global:PtmScenario = $Scenario; $global:PtmCalls = @(); $global:PtmBrowser = @()
    $failed = $false
    try { & $Action | Out-Null } catch { $failed = $true; if (-not $Fails) { throw } }
    Assert-PTM ($failed -eq $Fails) "Unexpected outcome: $Scenario"
    if ($Fails) { Assert-PTM ($global:PtmBrowser.Count -eq 0) 'Browser opened after failure' }
    $script:passed++
}
$temp = Join-Path ([IO.Path]::GetTempPath()) ('PTM WSL ; arguments ' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $temp 'scripts') -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $SourceRoot 'Install-Windows.ps1') -Destination $temp
Copy-Item -LiteralPath (Join-Path $SourceRoot 'Start-Windows.ps1') -Destination $temp
Copy-Item -LiteralPath (Join-Path $SourceRoot 'scripts/windows-wsl.ps1') -Destination (Join-Path $temp 'scripts')
try {
    $installer = Join-Path $temp 'Install-Windows.ps1'; $starter = Join-Path $temp 'Start-Windows.ps1'
    Invoke-PTMCase 'ok' { & $installer }
    $installCall = @($global:PtmCalls | Where-Object { $_[3] -eq 'bash' })[0]
    Assert-PTM ($installCall[4] -eq '-l') 'Login PATH required for user-managed uv/Python was not loaded'
    Assert-PTM ($installCall[5] -eq '/mnt/c/Installer with spaces & symbols/install.sh') 'Source path with spaces was split'
    Assert-PTM ($installCall[6] -eq '--prefix' -and $installCall[7] -eq '/home/test user/ProjectTimeMachine') 'Default prefix differs from Linux installer'
    Assert-PTM ($installCall -notcontains '--port') 'Default port was forced on update'
    Invoke-PTMCase 'ok' { & $installer -Prefix '~/PTM ; literal $value' -Port 13021 }
    $installCall = @($global:PtmCalls | Where-Object { $_[3] -eq 'bash' })[0]
    Assert-PTM ($installCall[7] -eq '/home/test user/PTM ; literal $value' -and $installCall[9] -eq '13021') 'Prefix/port arguments changed'
    Invoke-PTMCase 'ok' { & $starter }
    Assert-PTM ($global:PtmBrowser[0] -eq 'http://localhost:13021') 'Actual status port not used'
    Assert-PTM (@($global:PtmCalls | Where-Object { $_[3] -eq '/home/test user/ProjectTimeMachine/bin/ptm' -and $_[4] -eq 'start' }).Count -eq 1) 'Wrong default manager'
    Invoke-PTMCase 'ok' { & $starter -Prefix '/home/test user/Custom PTM' }
    Assert-PTM (@($global:PtmCalls | Where-Object { $_[3] -eq '/home/test user/Custom PTM/bin/ptm' -and $_[4] -eq 'start' }).Count -eq 1) 'Custom prefix not used by start'
    foreach ($scenario in @('missing-wsl','list-failed','wrong-distro','wsl1','root','not-ubuntu','python-missing','venv-missing')) {
        Invoke-PTMCase $scenario { & $installer } $true
    }
    foreach ($scenario in @('missing-manager','start-failed','status-failed','bad-json')) { Invoke-PTMCase $scenario { & $starter } $true }
    Invoke-PTMCase 'ok' { & $installer -Port 80 } $true
    Invoke-PTMCase 'ok' { & $installer -Prefix 'C:\Wrong' } $true
    Invoke-PTMCase 'ok' { & $installer -Prefix '/mnt/c/PTM' } $true
    foreach ($file in @('Install-Windows.ps1','Start-Windows.ps1','scripts/windows-wsl.ps1','tests/windows_wsl_mock.ps1')) {
        $parseErrors = $null; $tokens = $null
        [Management.Automation.Language.Parser]::ParseFile((Join-Path $SourceRoot $file), [ref]$tokens, [ref]$parseErrors) | Out-Null
        Assert-PTM ($parseErrors.Count -eq 0) "PowerShell syntax error in $file"
    }
    Write-Host "PASS: $passed mocked PowerShell scenarios; syntax checked. No real Windows, WSL, installation or browser used."
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
