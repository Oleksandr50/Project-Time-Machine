# Installation

Use the maintained 0.7.7 instructions in your language:
[English](../INSTALL_EN.md), [Русский](../INSTALL.md),
[Polski](../INSTALL_PL.md), [Українська](../INSTALL_UK.md).

From a source checkout, run `./install.sh` directly; archive extraction and SHA256SUMS
commands apply only to a separately downloaded installer archive. Default native prefix
is `$HOME/ProjectTimeMachine`; default native bind is `0.0.0.0`.

Docker: run `python3 scripts/docker_prepare.py`, then `docker compose up -d --build`.
Review compose.yaml and the generated configuration before starting. The supplied Docker
profile uses host networking and loopback binding; expose only explicitly mounted projects.
No prebuilt container or bundled third-party binary is included in this repository.

Windows uses WSL2 Linux storage and the supplied PowerShell launchers. It is not a native
Windows executable. Python, Docker and operating-system components retain their own licenses.
