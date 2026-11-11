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
    """Add columns that create_all() won't add to pre-existing tables,
    then run any one-time data upgrades this database hasn't had yet."""
    _ensure_column(engine, "files", "mtime_ns", "INTEGER")
    _ensure_column(engine, "files", "ctime_ns", "INTEGER")
    _ensure_column(engine, "files", "sig_version", "INTEGER")
    _ensure_column(engine, "directories", "mtime_ns", "INTEGER")
    _upgrade_data(engine)


# SQLite keeps a free integer in every database file (PRAGMA user_version)
# for exactly this: recording which one-time upgrades have run. 0 is the
# value every existing Ensign database has.
DATA_VERSION = 1


def _upgrade_data(engine: Engine) -> None:
    with engine.connect() as conn:
        version = conn.exec_driver_sql("PRAGMA user_version").scalar() or 0
        if version < 1:
            _upgrade_to_fd_passing(conn)
            conn.exec_driver_sql(f"PRAGMA user_version = {DATA_VERSION}")
            conn.commit()


def _upgrade_to_fd_passing(conn) -> None:
    """Version 1: the switch to passing open files to clamd.

    Older versions hashed every file, credential files included, and
    stored those hashes. Now credential files are never read, so:

      * credential files (HIGH secrets patterns): the stored hash is wiped,
        and ctime_ns is cleared so the next run re-decides them -- normally
        CLASSIFIED without being opened, or scanned if the file turns out
        to be executable.
      * INTEGRITY_WATCHED files (authorized_keys, ~/.ssh/config, ...) keep
        their hash -- it's the baseline the change check compares against
        -- and are rescanned once, since they were usually CLASSIFIED or
        permission-denied before and never got a real verdict.
      * permission-denied errors are rescanned once: clamd can read those
        files now, through the descriptor Ensign passes it.

    Clearing ctime_ns reuses the existing "ctime unknown -> rescan once"
    rule in the scanner, so no special-case code is needed there.

    secure_delete makes SQLite overwrite the old values on disk instead of
    just marking the space free, and the TRUNCATE checkpoint empties the
    write-ahead log, which would otherwise still hold copies of the pages
    as they were before. (A backup or filesystem snapshot taken earlier
    still has them; nothing here can reach those.)
    """
    from . import secrets
    from .clamd import is_permission_error

    # Streamed row by row, with the result text fetched only for errors:
    # a database with millions of rows must not be loaded into memory.
    rows = conn.exec_driver_sql(
        "SELECT id, filepath, scan_status, "
        "CASE WHEN scan_status = 'error' THEN scan_result END FROM files"
    )
    wipe: list[tuple[int]] = []
    rescan: list[tuple[int]] = []
    for row_id, path, status, result in rows:
        if isinstance(path, bytes):  # a name that isn't valid UTF-8 (see models.FsPath)
            path = path.decode("utf-8", "surrogateescape")
        if secrets.is_integrity_watched(path):
            if status in ("classified", "error"):
                rescan.append((row_id,))
        elif status == "infected":
            continue  # a found infection keeps its record, whatever its name
        elif secrets.is_high_confidence_secrets_path(path):
            wipe.append((row_id,))
        elif status == "error" and is_permission_error(result or ""):
            rescan.append((row_id,))

    if not (wipe or rescan):
        return
    print(f"[ensign] One-time database upgrade: removing stored hashes of "
          f"{len(wipe)} credential file(s); {len(rescan)} file(s) will be rescanned.")
    conn.exec_driver_sql("PRAGMA secure_delete = ON")
    if wipe:
        conn.exec_driver_sql(
            "UPDATE files SET file_hash = '', ctime_ns = NULL WHERE id = ?", wipe)
    if rescan:
        conn.exec_driver_sql("UPDATE files SET ctime_ns = NULL WHERE id = ?", rescan)
    conn.commit()
    conn.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
    # Pooled connections are reused; don't leave the slower mode on.
    conn.exec_driver_sql("PRAGMA secure_delete = OFF")


def _ensure_column(engine: Engine, table: str, column: str, ddl_type: str) -> None:
    with engine.connect() as conn:
        existing = {row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})")}
        if column not in existing:
            conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}")
            conn.commit()
