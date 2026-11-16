#!/bin/sh
set -eu
PTM_SOURCE_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
if [ -n "${PTM_PYTHON:-}" ]; then
  exec "$PTM_PYTHON" -B "$PTM_SOURCE_DIR/scripts/setup.py" "$@"
fi
for PTM_CANDIDATE in python3 python3.13 python3.12 python3.11; do
  if command -v "$PTM_CANDIDATE" >/dev/null 2>&1 && "$PTM_CANDIDATE" -c 'import sys;sys.exit(not ((3,11)<=sys.version_info[:2]<(3,14)))' >/dev/null 2>&1; then
    exec "$PTM_CANDIDATE" -B "$PTM_SOURCE_DIR/scripts/setup.py" "$@"
  fi
done
if command -v uv >/dev/null 2>&1; then
  for PTM_VERSION in 3.13 3.12 3.11; do
    if PTM_CANDIDATE=$(uv python find --offline --no-project --no-config --no-python-downloads --resolve-links "$PTM_VERSION" 2>/dev/null) && [ -x "$PTM_CANDIDATE" ]; then
      exec "$PTM_CANDIDATE" -B "$PTM_SOURCE_DIR/scripts/setup.py" "$@"
    fi
  done
fi
echo 'Python 3.11–3.13 is required. Install a supported Python or use Docker.' >&2
exit 1
