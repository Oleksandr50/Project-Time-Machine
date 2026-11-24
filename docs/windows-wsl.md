# Windows 10/11: installation through WSL2

Project Time Machine runs **inside Ubuntu on WSL2**. There is no native Windows EXE.
Docker and Python for Windows are not required. This guide covers the PowerShell
launchers in the source checkout; the Linux-only installer archive does not contain
these Windows launchers. Download the repository ZIP from GitHub's **Code → Download
ZIP**, or clone the repository. Extract the complete tree, including `scripts/`.
Use the [main branch source ZIP](https://github.com/Oleksandr50/Project-Time-Machine/archive/refs/heads/main.zip)
containing `scripts/windows-wsl.ps1`. The original v0.7.7 tag predates these fixes;
choose main rather than the tag's source archive. [Русская инструкция](windows-wsl_RU.md).

## 1. Prepare Windows and Ubuntu

Use Windows 11, or Windows 10 version 2004/build 19041 or later with virtualization
enabled. See [Microsoft's WSL installation guide](https://learn.microsoft.com/en-us/windows/wsl/install).
Initial WSL installation requires an elevated PowerShell:

```powershell
wsl --install -d Ubuntu-24.04
```

Restart Windows if requested. Open Ubuntu from Start and create a normal Linux user
and password. Do not use root as the default account. In ordinary PowerShell check:

```powershell
wsl --list --verbose
```

The selected distribution must show version **2**. If it shows 1, back up important
Linux data before running `wsl --set-version Ubuntu-24.04 2`. PTM scripts never convert,
reset, unregister or replace a distribution automatically. If WSL is outdated,
follow Microsoft's instructions for `wsl --update`. Organizational policies may
require administrator assistance; PTM does not bypass them.

## 2. Prepare Linux packages

Open Ubuntu and run:

```sh
sudo apt update
sudo apt install python3 python3-venv ca-certificates
python3 --version
```

PTM requires Python 3.11–3.13. Ubuntu 24.04 supplies Python 3.12. Existing compatible
Python installations managed by `uv` are also supported by `install.sh`.
The Windows installer uses Bash's login environment so user-level PATH additions
for `uv` can take effect; open a fresh Ubuntu login after installing `uv`.
Windows Python installations do not satisfy Linux requirements. Do not run the PTM installer
with sudo. A package installation needs sudo only for the commands above.

## 3. Install PTM

In ordinary PowerShell, open the extracted source directory. Spaces in its path are
supported. If Windows marks downloaded files as blocked, first verify the trusted
download, then unblock the extracted files (without changing machine policy):

```powershell
Get-ChildItem -LiteralPath . -Recurse -File | Unblock-File
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Install-Windows.ps1
```

The default installation is the selected Linux user's **`~/ProjectTimeMachine`**;
its manager is **`~/ProjectTimeMachine/bin/ptm`**. It is not installed in Windows HOME
or `.local/share/project-time-machine`. The source can be extracted on a Windows
drive; the installed code, virtual environment and state must live on Linux storage.

By default, the Linux installer chooses an available port and prints the actual
localhost URL. To choose a port and installation folder:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Install-Windows.ps1 -Distribution Ubuntu-24.04 -Prefix '~/PTM Custom' -Port 13021
```

`-Prefix` is an absolute **Linux** path or `~/...`, not `C:\...` or `/mnt/c/...`.
Use the exact distribution name from `wsl --list --verbose`. Existing installations
retain their configuration, users, history and archives. For updates, omit `-Port`;
an explicitly different port is rejected by the normal updater. Back up installation
data before an update. Linux installer errors are shown before the PowerShell error.

## 4. Start and create the administrator

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Start-Windows.ps1
```

Or double-click `Start-Windows.cmd`. It starts its sibling PowerShell script and
opens the actual port returned by PTM status. From a CMD window, custom arguments are:

```bat
Start-Windows.cmd -Distribution Ubuntu-24.04 -Prefix "/home/your-linux-user/PTM Custom"
```

Use the same distribution and prefix as installation. The browser opens
`http://localhost:<actual-port>`. WSL2 normally forwards Linux services to Windows
localhost; see [Microsoft's WSL networking guide](https://learn.microsoft.com/en-us/windows/wsl/networking).
If it does not work, inspect WSL networking/firewall/VPN settings; do not open the
application to the public Internet as a workaround. `0.0.0.0` is a bind address, not
a browser address. The Linux default bind remains unchanged by these wrappers.

The setup wizard creates your own administrator; there is no default password.
If Windows localhost forwarding is treated as a remote client and the wizard requests
an owner code, obtain it from Ubuntu:

```sh
"$HOME/ProjectTimeMachine/bin/ptm" setup-code
```

Use your custom prefix if applicable. Existing users sign in normally. Keep the code
private. Add projects under the Linux user's home through the UI. Windows drive
projects require deliberate allowed-root configuration and have different mount
semantics; this verification does not certify restore on `/mnt/c`, SMB or NFS.

## 5. Status, stop, update and uninstall

In Ubuntu (substitute your prefix):

```sh
"$HOME/ProjectTimeMachine/bin/ptm" status
"$HOME/ProjectTimeMachine/bin/ptm" stop
"$HOME/ProjectTimeMachine/bin/setup"
"$HOME/ProjectTimeMachine/bin/ptm" uninstall
```

Uninstall disconnects PTM and retains data, archives, keys and rollback releases.
Do **not** use `wsl --unregister`: it destroys the entire selected Linux distribution,
including unrelated files. Starting again requires WSL to remain running; an explicit
`wsl --shutdown` stops Linux applications too. These wrappers do not enable boot
autostart or install global Windows/systemd services. To update, extract a trusted new
source version and run its Install-Windows.ps1 with the same prefix/distribution,
without a new port. Retain a verified backup of your current installation.

## Troubleshooting and verification scope

- Missing WSL/Ubuntu: follow steps 1–2; the launcher does not install or reset them.
- WSL1: select/convert to WSL2 explicitly after backing up existing distribution data.
- Missing Python or venv: read the Linux error and install the Ubuntu packages above.
- Missing manager: check both the distribution and prefix, then installation logs.
- Failed startup/status: the launcher stops without opening the browser. Linux
  diagnostics remain visible; inspect the installation's `logs/server.log`.
- Download policy blocks PowerShell: verify and unblock files; ask your administrator
  if Group Policy still blocks them. The scripts do not bypass execution policy.
- Double-click window closes on failure: open PowerShell/CMD and run the same command
  there to retain the error output.

Validation performed on Linux includes executable PowerShell mocks, syntax checks,
argument/path/error scenarios, Linux installer prerequisite handling and public
regression tests. No actual Windows 10/11, Windows PowerShell 5.1, `cmd.exe`, WSL2
kernel, localhost forwarding, GUI startup or Windows-drive restore trial has been
performed. The CMD wrapper is checked statically; real Windows/WSL2 acceptance
testing is still required. Mock tests are not a full Windows compatibility claim.
