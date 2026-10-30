"""Database engine construction for Ensign."""
from __future__ import annotations

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine

from .models import Base


def make_engine(db_url: str) -> Engine:
    engine = create_engine(
        db_url,
        pool_size=10,
        max_overflow=10,
        pool_pre_ping=True,
        pool_recycle=3600,
        connect_args={"check_same_thread": False, "timeout": 30},
    )

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        # Note: this was previously misspelled "synchronious" — SQLite
        # silently ignores unknown pragmas, so it never took effect.
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

    Base.metadata.create_all(engine)
    _migrate(engine)
    return engine


def _migrate(engine: Engine) -> None:
    """Add columns that create_all() won't add to pre-existing tables."""
    _ensure_column(engine, "files", "mtime_ns", "INTEGER")
    _ensure_column(engine, "files", "ctime_ns", "INTEGER")
    _ensure_column(engine, "files", "sig_version", "INTEGER")
    _ensure_column(engine, "directories", "mtime_ns", "INTEGER")


def _ensure_column(engine: Engine, table: str, column: str, ddl_type: str) -> None:
    with engine.connect() as conn:
        existing = {row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})")}
        if column not in existing:
            conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}")
            conn.commit()
