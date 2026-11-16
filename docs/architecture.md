# Architecture — 0.7.5

FastAPI serves Jinja2 templates with local CSS/JavaScript and four JSON locale dictionaries.
No external CDN, embedded font library or vendored frontend package is used.
A SQLite registry holds projects, users, sessions, ACLs, jobs and restore operations;
per-project SQLite databases hold historical snapshots, audit and backup metadata.
Registry schema 5 and history schema 4 use checked, backed-up transactional migrations.

Code, configuration, state, metadata, immutable content, backups, logs and temporary
files are separate. ContextVar selects the project for each request or worker. File
reads use allowlisted roots and anchored no-follow access. Exclusions are shared by
analysis and backup; application storage is always protected.

The backup engine uses SHA-256 file-level content addressing, versioned manifests,
verified Full/Incremental/Checkpoint chains, SQLite Backup API and optional AES-GCM.
SQLite sidecar lifecycles are accounted for separately; ordinary source races still
block publication. Persistent jobs, project locks and bounded concurrency coordinate
operations. Retention deletion is disabled by default.

Restore requires preview and confirmation, verified pre-restore insurance and checked
staging. A durable operation journal supports explicit interruption recovery; whole-tree
atomic replacement is not promised. Analysis never executes project code or auto-fixes it.

Native Linux deployment uses immutable release directories and per-release environments,
with persistent state outside code. Updates retain rollback releases and verified database
checkpoints. See SECURITY.md and the installation guides for access and reliability limits.
