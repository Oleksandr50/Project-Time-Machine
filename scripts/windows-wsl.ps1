function Convert-PTMWslText {
    param([object[]]$Lines)
    return (($Lines | ForEach-Object { [string]$_ }) -join "`n").Replace([string][char]0, '').Trim()
}

function Invoke-PTMWsl {
    param([string]$Distribution, [string[]]$LinuxArguments)
    & wsl.exe -d $Distribution --exec @LinuxArguments
    if ($LASTEXITCODE -ne 0) { throw "WSL command failed (exit $LASTEXITCODE). See the Linux diagnostics above." }
}

function Get-PTMWslContext {
    param([string]$Distribution, [string]$Prefix)
    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
        throw 'WSL2 is required. In Administrator PowerShell run: wsl --install -d Ubuntu-24.04. Reboot if requested, open Ubuntu and create your Linux user.'
    }
    $listed = & wsl.exe --list --quiet
    if ($LASTEXITCODE -ne 0) { throw 'Could not list WSL distributions. Run wsl --status and complete WSL installation.' }
    $distros = (Convert-PTMWslText $listed) -split "`n" | ForEach-Object { $_.Trim() }
    if ($distros -notcontains $Distribution) { throw "Distribution '$Distribution' is not installed. Run wsl --install -d Ubuntu-24.04, or choose its exact name with -Distribution (see wsl --list --verbose)." }
    $listed = & wsl.exe --list --verbose
    if ($LASTEXITCODE -ne 0) { throw 'Could not check WSL version. Update WSL with wsl --update, then retry.' }
    $pattern = '(?m)^\s*\*?\s*' + [regex]::Escape($Distribution) + '\s+.+?\s+2\s*$'
    if ((Convert-PTMWslText $listed) -notmatch $pattern) { throw "Distribution '$Distribution' must use WSL2. Back up important WSL data, then run: wsl --set-version $Distribution 2. No conversion was performed automatically." }
    $linuxUid = Convert-PTMWslText (Invoke-PTMWsl $Distribution @('id', '-u'))
    if ($linuxUid -notmatch '^\d+$' -or $linuxUid -eq '0') { throw 'Open Ubuntu and configure a normal default Linux user. Do not install or start PTM as root.' }
    $record = (Convert-PTMWslText (Invoke-PTMWsl $Distribution @('getent', 'passwd', $linuxUid))) -split ':'
    if ($record.Count -ne 7 -or -not $record[5].StartsWith('/')) { throw 'Could not determine the Linux user home from the system account database.' }
    $linuxHome = $record[5]
    $osRelease = Convert-PTMWslText (Invoke-PTMWsl $Distribution @('cat', '/etc/os-release'))
    if ($osRelease -notmatch '(?m)^ID="?ubuntu"?$') { throw 'These Windows launchers support Ubuntu on WSL2. Select an Ubuntu distribution with -Distribution.' }
    if (-not $Prefix) { $Prefix = "$linuxHome/ProjectTimeMachine" }
    elseif ($Prefix.StartsWith('~/')) { $Prefix = $linuxHome + $Prefix.Substring(1) }
    if (-not $Prefix.StartsWith('/') -or $Prefix -match '[\x00-\x1f"]') { throw 'Prefix must be an absolute Linux path or ~/path, without control characters or double quotes. Windows C:\ paths are not installation prefixes.' }
    $resolved = Convert-PTMWslText (Invoke-PTMWsl $Distribution @('realpath', '-m', '--', $Prefix))
    if (-not $resolved.StartsWith('/') -or $resolved -in @('/', $linuxHome, '/tmp', '/home')) { throw 'Choose a dedicated Linux installation directory.' }
    if ($resolved -match '^/(mnt|media|run/media)(/|$)') { throw 'Install PTM on the Linux filesystem inside WSL, not a Windows/removable mount. Use ~/ProjectTimeMachine or another Linux directory.' }
    return [pscustomobject]@{ Prefix = $resolved; Manager = "$resolved/bin/ptm" }
}

function Get-PTMWslStatus {
    param([string]$Distribution, [string]$Manager)
    $lines = Invoke-PTMWsl $Distribution @($Manager, 'status')
    try { $status = (Convert-PTMWslText $lines) | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'PTM returned invalid status JSON. Inspect the Linux diagnostics; the browser was not opened.' }
    if ($null -eq $status.port -or [int]$status.port -lt 1024 -or [int]$status.port -gt 65535) { throw 'PTM returned an invalid server port.' }
    return $status
}
