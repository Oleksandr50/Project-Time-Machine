# Changelog

## Unreleased — Windows/WSL2 launchers

- Align install/start paths with the Linux installer, support a shared custom prefix and preserve the existing port during updates.
- Validate the exact Ubuntu distribution, WSL2 and non-root Linux account; retain Linux diagnostics and open the browser only after successful startup/status.
- Add executable mocked PowerShell scenarios and English/Russian Windows 10/11 instructions. Real Windows/WSL2 acceptance testing remains required.

## 0.7.7 — compact lists and confirmed deletion

- Bound dashboard/job lists to four visible entries and backup tables to five rows with internal scrolling.
- Add administrator-only confirmed deletion of disabled projects and individual backups, durable cleanup journals and incremental/restore dependency guards.
- Add all new messages in English, Russian, Polish and Ukrainian. No database schema change.


## 0.7.6 — path validation and installation verification

- Reject forbidden system paths before resolving special procfs descriptors; preserve allowed-root, symlink and project boundary checks.
- Create the disposable installation verification project outside protected installation storage and explicitly allow its parent directory.
- Preserve existing accounts, configuration, project history and backups during updates; no database schema changes.

## 0.7.5 — publication preparation

- Record Oleksandr as author and copyright holder, © 2026 Oleksandr.
- Adopt the owner-provided Project Time Machine Non-Commercial License 1.0.
- Add English/Russian/Polish/Ukrainian READMEs and full third-party license notices.
- Update public packaging inventories to carry the selected license and notices.
- Export only public files without runtime state or internal development history.

## 0.7.5 — backup scan failure reporting

- Preserve typed unsafe-path and unsupported-file errors from strict scans in background jobs instead of reporting them as internal errors.
- Explain explicit virtual-environment exclusions in all four languages; keep links rejected and user exclusion choices intact.
- Record bounded application code locations for unexpected worker failures without logging exception messages, source contents or credentials.
- Ignore creation/deletion of recognized SQLite WAL/SHM/rollback files during final inventory comparison after a coherent SQLite Backup API capture; keep ordinary file changes blocked.
- Retry disappearing scan entries as source changes; never silently omit directories named like SQLite sidecars.
- No database schema changes or automatic changes to project source files.

## 0.7.4 — direct server interface access

- Discover assigned interface addresses through Linux netlink, including VPN/CGNAT and secondary addresses; authenticate directly through server IPs without subnet guesswork.
- First network setup uses an owner-only one-time code; existing administrators sign in normally. No SSH tunnel is required.
- Keep explicit allowlists, Host/origin checks, CSRF, roles, rate limits and audited network controls; add owner network-on/network-off recovery commands.
- Installation guides in Russian, English, Polish and Ukrainian.

## 0.7.3 — LAN startup

- Fresh Linux installs bind 0.0.0.0; binding no longer depends on completed web setup.
- Default private-network allowlist and direct LAN HTTP login; explicit IP/Host limits and Administrator network-disable decisions remain authoritative.
- Keep localhost-only initial setup, authentication, CSRF, roles, rate limits, and untrusted-proxy/public-client restrictions.
- Existing bind/port/data and accounts are retained; no schema or data migrations added.

## 0.7.2 — release startup fix

- Resolve app_root and bundled resources from the imported release, independently of saved installation-prefix/old-release values.
- Keep all persistent data paths and protect legacy app_root paths; no schema migration or configuration rewrite required.
- Blank Enter retains current setup IP/port; launcher reports bounded, masked diagnostics from the actual failed startup.
- Focused separate-release startup, assets, translations and switching checks only.

## 0.7.1 — Linux installer

- System-account HOME/ProjectTimeMachine default, HOME parent authorization and protected application storage.
- Portable install/setup/start wrappers, offline uv discovery and resolved base interpreter.
- Per-instance interactive settings, checked backup-location changes and explicit journal recovery.
- Persisted bind/port/autostart preferences; opt-in owned user service/linger for boot.
- Clean Linux runtime package and Russian/English installation guides; no schema changes.

## 0.7.0 — candidate

- Universal local projects with stable history, allowlisted paths and shared exclusions.
- Administrator/Operator/Viewer, session security, setup without a default password.
- Responsive ru/en/pl/uk interface, history, diff, protected backups and scheduling.
- Full/Incremental/Checkpoint, verified CAS and encryption with external keys.
- Confirmed restore, pre-restore insurance, staging and explicit interrupted recovery.
- Python adapters, explainable heuristic audit, bounded logs and read-only SQLite views.
- Linux/WSL user installer, persistent non-root Docker, checked update/rollback metadata,
  clean public exports and tests. Native Windows executable is not available.
- User state/accounts are never bundled. License selection is recorded in LICENSE; publication requires owner approval.
