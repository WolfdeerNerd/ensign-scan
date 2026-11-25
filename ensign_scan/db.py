"""Database engine construction for Ensign."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine

from .models import Base
from .protect import DECISION_TABLES


def make_engine(db_url: str, decisions: Path | None = None) -> Engine:
    """The engine for a database. With `decisions` (protected mode, see
    protect.py), root's decisions file is attached read-only on every
    connection, and a temporary view for each decision table is put in
    front of the database's own table of that name.

    SQLite looks an unqualified table name up in the temp schema first,
    then main, then attached databases, so every existing query on
    allowances, allowed_folders and persistence_entries reads root's copy
    without any change, and a write to one fails: a view can't be changed.
    Your own tables of those names are left as they are, unused. root's
    file is opened read-only by the operating system (only root can write
    it), and it uses a rollback journal, so reading it writes nothing."""
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
        if decisions is not None:
            cursor.execute("ATTACH DATABASE ? AS decisions", (str(decisions),))
            for table in DECISION_TABLES:
                cursor.execute(f"CREATE TEMP VIEW {table} AS SELECT * FROM decisions.{table}")
        cursor.close()

    Base.metadata.create_all(engine)
    # Protected: the decision tables are root's (the views above); this
    # database's own copies are unused, so they're left for whenever it's
    # unprotected again, when an engine without views upgrades them.
    _migrate(engine, decision_tables=decisions is None)
    return engine


def _migrate(engine: Engine, decision_tables: bool = True) -> None:
    """Add columns that create_all() won't add to pre-existing tables,
    then run any one-time data upgrades this database hasn't had yet."""
    _ensure_column(engine, "files", "threat_engine", "TEXT")
    if decision_tables:
        with engine.begin() as conn:
            upgrade_decision_tables(conn)
    _ensure_column(engine, "files", "mtime_ns", "INTEGER")
    _ensure_column(engine, "files", "ctime_ns", "INTEGER")
    _ensure_column(engine, "files", "sig_version", "INTEGER")
    _ensure_column(engine, "directories", "mtime_ns", "INTEGER")
    _ensure_column(engine, "directories", "ctime_ns", "INTEGER")
    _ensure_column(engine, "files", "format_mismatch", "TEXT")
    _ensure_column(engine, "files", "last_error", "TEXT")
    _upgrade_data(engine)


# SQLite keeps a free integer in every database file (PRAGMA user_version)
# for exactly this: recording which one-time upgrades have run. 0 is the
# value every existing Ensign database has.
DATA_VERSION = 3


def _upgrade_data(engine: Engine) -> None:
    with engine.connect() as conn:
        version = conn.exec_driver_sql("PRAGMA user_version").scalar() or 0
        if version < 1:
            _upgrade_to_fd_passing(conn)
        if version < 2:
            _upgrade_to_scanning_credential_files(conn)
        if version < 3:
            _upgrade_to_findings(conn)
        if version < DATA_VERSION:
            conn.exec_driver_sql(f"PRAGMA user_version = {DATA_VERSION}")
            conn.commit()


# A sweep hit by the YARA pass, as scanner.py words it (with SWEEP_HIT_PREFIX).
_YARA_SWEEP_HIT = "sweep: % by YARA, %"


def _upgrade_to_findings(conn) -> None:
    """Version 3: findings, and which engine found what (0.10.0).

    Every recorded hit becomes a finding, open or allowed as the file is
    now. The engine was only ever written into the sweep's result text, so
    a YARA sweep hit is told apart by its wording; every other hit is
    ClamAV's. first_seen is the last scan's time: when it was first found
    wasn't kept before."""
    conn.exec_driver_sql(
        "UPDATE files SET threat_engine = 'clamav-yara' "
        "WHERE scan_status IN ('infected', 'allowed') AND scan_result LIKE ?", (_YARA_SWEEP_HIT,))
    conn.exec_driver_sql(
        "INSERT OR IGNORE INTO findings "
        "(file_id, engine, signature, detail, content_hash, first_seen, last_seen, state) "
        "SELECT id, COALESCE(threat_engine, 'clamav'), COALESCE(threat_name, 'Unknown'), scan_result, "
        "file_hash, COALESCE(last_scanned, CURRENT_TIMESTAMP), COALESCE(last_scanned, CURRENT_TIMESTAMP), "
        "CASE scan_status WHEN 'allowed' THEN 'allowed' ELSE 'open' END "
        "FROM files WHERE scan_status IN ('infected', 'allowed')")


@contextmanager
def _ddl_transaction(conn):
    """One real transaction around schema changes. Python's sqlite3 module
    (in its default mode) opens a transaction before INSERT, UPDATE and
    DELETE, but not before CREATE, ALTER or DROP: those run on their own
    and are kept at once. A crash in the middle of a table rebuild would
    then leave it half done. Here BEGIN is sent explicitly, so either all
    of it is kept, or none."""
    raw = conn.connection.driver_connection
    raw.commit()                    # nothing of the caller's is pending; never mix it in
    before = raw.isolation_level
    raw.isolation_level = None      # the module sends no BEGIN or COMMIT of its own
    try:
        raw.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            raw.execute("ROLLBACK")
            raise
        raw.execute("COMMIT")
    finally:
        raw.isolation_level = before


def _needs_rebuild(conn, table: str, old: str) -> bool:
    columns = [row[1] for row in conn.exec_driver_sql(f"PRAGMA main.table_info({table})")]
    leftover = conn.exec_driver_sql(f"PRAGMA main.table_info({old})").fetchall()
    return bool(leftover) or (bool(columns) and "engine" not in columns)


def upgrade_decision_tables(conn) -> bool:
    """Give allowances and allowed_folders their engine column (0.10.0),
    in this database's own tables (main), if they don't have it. Returns
    True if anything changed.

    Every allowance made before was for ClamAV, the only engine there was,
    and stays exactly that: a hit from another engine is never covered by
    one. The engine is also part of each table's unique key, which SQLite
    can't change in place, so each table is rebuilt once, in one real
    transaction (_ddl_transaction): renamed, made again from models.py,
    copied, dropped.

    A rebuild that a build of 0.10.0 before this fix left half done (the
    renamed table still there) is finished here: its rows are copied into
    the new table, so no allowance is lost.

    Also used on protected decisions files (protect.upgrade_all), which root
    upgrades the same way. The rebuild stays inside the same file, so it
    keeps the file's owner, mode and ACL."""
    changed = False
    for table in ("allowances", "allowed_folders"):
        old = f"{table}_before_engine"
        if not _needs_rebuild(conn, table, old):
            continue   # the usual case: checked without taking the write lock
        with _ddl_transaction(conn):
            columns = [row[1] for row in conn.exec_driver_sql(f"PRAGMA main.table_info({table})")]
            leftover = [row[1] for row in conn.exec_driver_sql(f"PRAGMA main.table_info({old})")]
            if leftover and (not columns or "engine" in columns):
                # Half done earlier: finish it.
                if not columns:
                    Base.metadata.tables[table].create(conn)
                copied = ", ".join(c for c in leftover if c != "id")
                conn.exec_driver_sql(
                    f"INSERT OR IGNORE INTO main.{table} ({copied}, engine) "
                    f"SELECT {copied}, 'clamav' FROM main.{old}")
                conn.exec_driver_sql(f"DROP TABLE main.{old}")
                changed = True
                continue
            if not columns or "engine" in columns:
                continue   # not in this database (made later by create_all), or already done
            conn.exec_driver_sql(f"ALTER TABLE main.{table} RENAME TO {old}")
            # The renamed table keeps its indexes' names; free them for the new one.
            for (index,) in conn.exec_driver_sql(
                    "SELECT name FROM main.sqlite_master WHERE type = 'index' AND tbl_name = ? "
                    "AND sql IS NOT NULL", (old,)).fetchall():
                conn.exec_driver_sql(f'DROP INDEX main."{index}"')
            Base.metadata.tables[table].create(conn)
            copied = ", ".join(columns)
            conn.exec_driver_sql(
                f"INSERT INTO main.{table} ({copied}, engine) SELECT {copied}, 'clamav' FROM main.{old}")
            conn.exec_driver_sql(f"DROP TABLE main.{old}")
            changed = True
    return changed


def _upgrade_to_scanning_credential_files(conn) -> None:
    """Version 2: credential files are scanned (0.8.6).

    Before, a file whose name matched a credential pattern was recorded
    as CLASSIFIED and never opened, so it has no verdict. Clearing
    ctime_ns sends each one through the scanner's existing "ctime
    unknown -> rescan once" rule, which scans it and replaces the
    status. Their stored hash is already "" and stays that way."""
    conn.exec_driver_sql("UPDATE files SET ctime_ns = NULL WHERE scan_status = 'classified'")


def _upgrade_to_fd_passing(conn) -> None:
    """Version 1: the switch to passing open files to clamd.

    Older versions hashed every file, credential files included, and
    stored those hashes. From 0.3.0 credential files were never read
    (from 0.8.6 they're scanned, still with no hash stored), so:

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


# A column added to allowances, allowed_folders or persistence_entries must
# also be added to protected decisions files (protect.py), which only root
# can change: protect._check_readable() stops a protected run whose file
# lacks one, rather than let it fail with "no such column" mid-run.
def _ensure_column(engine: Engine, table: str, column: str, ddl_type: str) -> None:
    # main. explicitly: in a protected run, an unqualified name can be one
    # of the temporary views in front of root's decisions (make_engine).
    with engine.connect() as conn:
        existing = {row[1] for row in conn.exec_driver_sql(f"PRAGMA main.table_info({table})")}
        if existing and column not in existing:
            conn.exec_driver_sql(f"ALTER TABLE main.{table} ADD COLUMN {column} {ddl_type}")
            conn.commit()


def make_protected_writer(decisions: Path, verdicts: str) -> Engine:
    """For `sudo ensign-scan --protected ...` (protect.py): an engine whose
    main database is the user's protected decisions file, so allowances,
    folder allowances and acknowledgments are written there.

    The evidence that a file was flagged comes from root's own database
    (`verdicts`), never from the user's, which root must not parse. It is
    attached, and a temporary view named `files` is put in front, so the
    allowlist's queries read root's records unchanged and can't change them
    (a view can't be changed). Root's runs keep their own verdicts: the
    user's runs mark the file allowed on their next pass.

    The decisions file keeps its rollback journal (see protect.py), so the
    user's runs can go on reading it without writing anything."""
    engine = create_engine(f"sqlite:///{decisions}", connect_args={"timeout": 30})

    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_conn, _record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=DELETE")
        cursor.execute("ATTACH DATABASE ? AS verdicts", (verdicts,))
        cursor.execute("CREATE TEMP VIEW files AS SELECT * FROM verdicts.files")
        cursor.close()

    return engine
