# Project Time Machine 0.7.5 — Linux

## Install

Requirements: Linux kernel 5.3+, Python 3.11–3.13 with venv, tar/gzip, and internet for
pinned dependencies. Ubuntu: `sudo apt install python3-venv`. Run the installer as your
normal user, without sudo. Existing uv-managed Python is detected automatically.

```sh
sha256sum -c SHA256SUMS
tar -xzf project-time-machine-0.7.5-linux.tar.gz
cd project-time-machine-0.7.5
./install.sh
```

Extract anywhere. Default destination: `$HOME/ProjectTimeMachine`; persistent data is
separate from release code. Custom directory and port:

```sh
./install.sh --prefix "$HOME/MyPTM" --port 13021
```

Port 13011 is preferred; another free port is selected if busy. An explicit occupied port
fails without stopping other processes. `--no-start` suppresses startup. `--wheelhouse
/absolute/wheels` uses offline packages. The installer needs no root and never modifies
firewall/system services. Its built-in self-check uses disposable data.

## Direct interface access

Default bind: **0.0.0.0, all IPv4 interfaces**. Installation prints actual interface URLs.
Open `http://SERVER_ADDRESS:PORT` using Ethernet/Wi-Fi/VPN, including 100.64.0.0/10.
No SSH tunnel or manual subnet list is required. **0.0.0.0 is not a browser destination.**
Use bind `::` for IPv6. HTTP is allowed directly through server interface addresses and is
unencrypted; use HTTPS on untrusted networks. Unknown Hosts and untrusted forwarding
headers are not automatically trusted. Explicit owner IP/Host restrictions remain.
Routing and OS firewall rules are not modified; connection failures differ from HTTP 403.

## Administrator

If you already created an administrator, open `/login` and use the existing credentials.
There is no new setup or activation-code requirement for existing accounts.
For a fresh installation, open `/setup` directly through a network address. On the server:

```sh
"$HOME/ProjectTimeMachine/bin/ptm" setup-code
```

For a custom prefix, use its launcher. Enter the one-time owner code, select a language,
choose your username and password (at least 12 characters) and confirm it. The code is
removed after administrator creation; it is never sent in a URL or logged by the server.
No admin/admin exists. Local setup is also available.

## Use

1. Projects → Add: enter a name and an absolute directory on the server. HOME authorizes
   nested projects without CLI steps. PTM's installation/data/keys/backups are protected.
2. Select a project, create Full Backup and wait for success.
3. After edits, create Incremental or Checkpoint; use Compare to review snapshots.
   Metadata-only snapshots do not guarantee recoverable content.
4. Restore: select a backup/recoverable snapshot, whole project/files/new directory,
   inspect the preview and explicitly confirm RESTORE. Verified insurance precedes
   overwriting. Stop writers to the project. Use a small disposable project for your first try.
5. Backups provides daily/weekly schedules. Automatic deletion is off by default.
6. Analysis/Audit never auto-fix source. Logs/SQLite are bounded views with recognized
   secrets masked; SQLite browsing does not edit records.
7. Users: assign Viewer/Operator, selected projects, and separate restore permission.
   Settings offers ru/en/pl/uk, theme and scale.

In Projects → Edit → Exclusions, add relative paths for virtual environments with custom
names, for example `data/voice/tts_venv`. Standard `venv` and `.venv` are already excluded;
arbitrary names are not excluded automatically. Symbolic links and special files stop
the backup with an explicit error instead of being copied outside the project.

## Manage

```sh
"$HOME/ProjectTimeMachine/bin/setup"
"$HOME/ProjectTimeMachine/bin/ptm" status
"$HOME/ProjectTimeMachine/bin/ptm" start
"$HOME/ProjectTimeMachine/bin/ptm" stop
"$HOME/ProjectTimeMachine/bin/ptm" restart
```

The extracted `./setup.sh [--prefix "$HOME/MyPTM"]` also works. It controls project roots,
future backup storage, bind, port, post-install startup and opt-in user-service boot
startup. Save applies changes. Blank IP/port input retains the value. Old archives are
never moved or deleted. A boot user-service is created only after explicit selection;
linger may require OS authorization. Unrelated services are not changed.

An explicit Administrator network-disable preference survives updates. The installation
owner can re-enable access from the terminal without a tunnel or account reset:

```sh
"$HOME/ProjectTimeMachine/bin/ptm" network-on
# Disable: bin/ptm network-off
```

Project parents accept absolute paths or ~/; system/credential/symlink paths are protected.

## Update / uninstall

Extract a new package separately and run:

```sh
./install.sh --prefix "$HOME/ProjectTimeMachine"
```

Users, IDs, history, archives, bind/port and settings persist. If previously bound to
127.0.0.1, choose 0.0.0.0 in setup. Old incorrect app_root values need no manual edits or
symlinks. SQLite checkpoints precede migration. Interrupted update: `bin/ptm recover-update`;
interrupted settings save: `bin/setup --recover`, followed by an explicit start.
No automatic database downgrade follows a completed update.

```sh
"$HOME/ProjectTimeMachine/bin/ptm" uninstall
```

This disables only this instance/launchers. Databases, projects, archives, keys and rollback
code remain. Do not erase data directories when retaining history.

Author: Oleksandr. © 2026 Oleksandr. Contact: omtimemachineom@gmail.com.
Project Time Machine Non-Commercial License 1.0 is provided in LICENSE.
Free for non-commercial use. Commercial use requires prior written permission.
Personal, educational and non-commercial use, study, modification and non-commercial
redistribution are permitted subject to attribution and identification of changes.
Commercial use and distribution require prior written permission. Third-party terms
are preserved separately in THIRD_PARTY_NOTICES.md and third_party/.
