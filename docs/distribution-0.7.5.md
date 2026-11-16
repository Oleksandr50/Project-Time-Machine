# Final 0.7.5 source / installer synchronization

The publication source is this repository. The Linux installer is built directly with
the included dependency-free packaging script; no development checkout, private data,
installed application or local wheel directory is needed.

## Reproduce the installer

Run from a clean checkout using Python 3 (no application dependencies required):

```sh
python3 -B scripts/build_linux_installer.py --output dist/0.7.5-final
cd dist/0.7.5-final
sha256sum -c SHA256SUMS
```

The output directory must not already exist. The six output files are the Linux archive,
SHA256SUMS and INSTALL.md / INSTALL_EN.md / INSTALL_PL.md / INSTALL_UK.md.
The script fixes tar ownership, timestamps, permissions, file order and gzip timestamp.
It writes a SHA-256 release-manifest.json and compares every packed byte with its input.
For byte-for-byte archive reproduction, use the same Python/zlib toolchain recorded
in distribution-0.7.5.json. Different compression toolchains can produce different gzip
bytes even when all unpacked payload hashes match.

The verification report lists every shared source/payload SHA-256, every repository-only
file and the generated archive-only manifest. GITHUB_FILES.txt lists the public files;
it includes itself. Runtime application files, templates, assets and translations match
the repository. app/release.py and packaging/build/test/CI files are development-only.
The archive includes the selected LICENSE, AUTHORS, COPYRIGHT, THIRD_PARTY_NOTICES.md
and original third-party notices. Binary dependency wheels are not bundled; pinned
dependencies are installed by the owner's installer invocation.

## Manual owner update (not performed during preparation)

Run these commands on the installation host when ready:

```sh
cd "$HOME/PTM_Installer/0.7.5-final"
sha256sum -c SHA256SUMS
PTM_UPDATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ptm-update-0.7.5.XXXXXX")
tar -xzf project-time-machine-0.7.5-linux.tar.gz -C "$PTM_UPDATE_DIR"
"$PTM_UPDATE_DIR/project-time-machine-0.7.5/install.sh" --prefix "$HOME/ProjectTimeMachine"
```

Only the owner runs the update. It may stop/restart this PTM instance, install dependencies,
run its built-in temporary self-check, checkpoint databases and activate a retained
release. Existing users, history, backup paths, bind and port settings are retained.
Do not pass a new port or project root during the update. No setup wizard is needed
for an existing administrator. The extracted directory is retained for owner inspection.

Preparation performs packaging, hashes, file inventory, license/attribution checks,
documentation link checks and heuristic secret scans only. No server, installation,
database migration, functional/browser test or project restore is run. The previous
0.7.5 installer is retained unchanged. No Git commit, remote publication or GitHub Release
is created. After the owner validates the application, publication still needs approval.

Secret scans recognize known patterns and forbidden artifacts; they cannot prove absence
of every possible unknown secret. Synthetic test credentials remain in public tests;
no active user credentials or runtime databases are distributed.
