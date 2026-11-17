# Security

Report vulnerabilities privately to **omtimemachineom@gmail.com**. Include the affected
version, impact and a sanitized reproduction using synthetic data. Do not post real
keys, databases, logs or private backups in public issues. No response-time guarantee
is currently published. Version 0.7.6 is the current review target.

Native Linux installation binds all IPv4 interfaces by default. Network initial setup
requires an owner-only one-time code. There is no default administrator password.
Use HTTPS or VPN over untrusted networks; review host/client restrictions and network
controls before exposure. Docker's supplied profile uses loopback binding.

Grant only the required projects and restore permission. Masking detects common patterns
but cannot recognize every secret. Protect backup storage, runtime state and external
keys with operating-system permissions. Keep independent backups on another device.

Stop project writes before restore. Whole-tree atomic replacement is not guaranteed.
Do not delete interrupted restore journals, staging/undo or verified insurance copies.
Undo data is plaintext even when a portable backup is encrypted. Ordinary source writes
may prevent backup publication; SQLite consistency is per database. Review exclusion
rules explicitly, including custom virtual environments and temporary runtime files.
