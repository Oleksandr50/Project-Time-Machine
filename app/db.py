from __future__ import annotations
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from .config import settings
from .migrations import migrate


def connect(db_path: Path | None = None):
    conn=sqlite3.connect(str(db_path or settings.db_path),timeout=30)
    conn.row_factory=sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


@contextmanager
def db_conn():
    conn=connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally: conn.close()


def init_db():
    migrate(settings.db_path,'history',settings.migrations_dir,settings.project_id)
