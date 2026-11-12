"""SQLAlchemy models for Ensign.

Models hold data only. Change-detection logic, scanning, and reporting
live elsewhere.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    LargeBinary,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
    and_,
    or_,
    type_coerce,
)
from sqlalchemy.orm import declarative_base

Base = declarative_base()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanStatus(str, Enum):
    CLEAN = "clean"
    INFECTED = "infected"
    ERROR = "error"
    PENDING = "pending"
    # The path matches a high-confidence credential pattern (wallets,
    # SSH/GPG keys, password vaults, ...), so Ensign deliberately never
    # opened it: no hash (file_hash is ""), no clamd verdict. Decided from
    # the path and stat() alone -- see secrets.skip_reason(). Distinct from
    # ERROR so it naturally drops out of error_summary() and
    # suggest_fixes() without either needing to special-case it.
    CLASSIFIED = "classified"
    # ClamAV did not scan all of this file: it is past a scan limit ClamAV
    # can't lift -- most often larger than ~2 GiB, which no ClamAV tool can
    # scan. Hashed and tracked for changes like any file, but its contents
    # were not checked, so it must never count as clean. threat_name holds
    # ClamAV's reason (Heuristics.Limits.Exceeded.MaxFileSize, ...).
    INCOMPLETE = "incomplete"
    # ClamAV flagged this file, and you told Ensign it's a false positive
    # (ensign-scan --allow). Only for this exact content (SHA-256) and this
    # exact signature: if the file changes, or another signature hits it,
    # it is flagged again. Listed in its own section every run, never
    # hidden; doesn't count as infected for alerts or the exit code.
    # threat_name keeps the signature. See allowlist.py.
    ALLOWED = "allowed"


# scan_result for a file Ensign itself couldn't open or read, so clamd never
# saw it. Kept apart from clamd's own error text: reports.suggest_fixes()
# explains the two differently, and error_summary() groups by this text.
OPEN_FAILED = "Ensign could not open this file"


def open_failed_result(exc: OSError) -> str:
    """e.g. "Ensign could not open this file (Permission denied)". No ": "
    in it, so error_summary() keeps the whole sentence as the cause."""
    return f"{OPEN_FAILED} ({exc.strerror or type(exc).__name__})"


def is_open_failed(raw: str | None) -> bool:
    return (raw or "").startswith(OPEN_FAILED)


class FsPath(TypeDecorator):
    """A filesystem path or name, stored so that ANY name round-trips exactly.

    Linux filenames are bytes; most are valid UTF-8, but not all (old
    archives, Wine/Proton folders and files from Windows can hold names in
    other encodings). Python represents the undecodable bytes as
    "surrogate" characters, which SQLite's text type can't store, so such
    files used to be silently dropped from the database.

    Valid UTF-8 names -- practically all of them -- are stored as TEXT,
    exactly as before, so existing databases need no migration. Any other
    name is stored as its original bytes (a BLOB) in the same column, and
    turned back into the same Python string when read. Each name has one
    stored form, so the UNIQUE constraint and == lookups work unchanged.

    The one thing that differs is sorting: SQLite orders every BLOB after
    every TEXT value, so range queries need a second, byte-wise branch --
    see path_under().
    """
    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        value = str(value)
        try:
            value.encode("utf-8")
            return value
        except UnicodeEncodeError:
            return value.encode("utf-8", "surrogateescape")

    def process_result_value(self, value, dialect):
        if isinstance(value, bytes):
            return value.decode("utf-8", "surrogateescape")
        return value


class SafeText(TypeDecorator):
    """Free text that may quote a filename: clamd's and clamscan's replies
    repeat the path they scanned. Unlike a path it's only ever displayed,
    so a name that isn't valid UTF-8 is stored with its bytes written as
    \\xNN (lossless enough to read, and valid text for SQLite)."""
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        try:
            value.encode("utf-8")
            return value
        except UnicodeEncodeError:
            return value.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")


def path_under(column, directory: str):
    """SQL condition: `column` is a path inside `directory` (at any depth).

    Not LIKE: in LIKE, "_" and "%" are wildcards and SQLite matches ASCII
    case-insensitively, so "~/my_docs/%" also matched "~/myXdocs" and
    "~/My_Docs". Instead this is a range on the text itself. Every path
    inside "/a/b" starts with "/a/b/", and sorts at or after "/a/b/" but
    before "/a/b0" -- "0" is the character right after "/". Exact, case-
    sensitive, and able to use the column's index.
    """
    base = directory.rstrip("/") + "/"
    end = base[:-1] + "0"
    text_range = and_(column >= base, column < end)
    # Names stored as bytes (see FsPath) sort after all text in SQLite, so
    # the text range never reaches them. The same range, compared as bytes,
    # finds them; for text rows it's always false, so nothing is counted
    # twice. UTF-8 sorts in the same order as the characters it encodes,
    # so both branches agree on what "inside" means.
    as_bytes = type_coerce(column, LargeBinary)
    byte_range = and_(as_bytes >= base.encode("utf-8", "surrogateescape"),
                      as_bytes < end.encode("utf-8", "surrogateescape"))
    return or_(text_range, byte_range)


class FileRecord(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True)
    filepath = Column(FsPath, unique=True, nullable=False)
    filename = Column(FsPath, nullable=False)
    file_hash = Column(String, nullable=False, index=True)
    file_size = Column(Integer)

    # Exact nanosecond mtime from stat(). Stored as an integer so
    # change detection is a plain == with no float/timezone loss.
    mtime_ns = Column(Integer)

    # Exact nanosecond ctime (inode change time). Unlike mtime, a process
    # can't set ctime backwards with utimensat(); any content write, chmod,
    # chown or rename bumps it. Checked alongside (size, mtime_ns) so a
    # file edited and then given back its old mtime still gets rescanned.
    # NULL on rows from before this column existed; those get rescanned once.
    ctime_ns = Column(Integer)

    # Version of the ClamAV signature database the last real verdict was
    # produced under (clamd's VERSION). Lets Ensign rescan files that were
    # clean under an older database. NULL = unknown (older rows, or clamd
    # didn't report a version).
    sig_version = Column(Integer)

    scan_status = Column(String, default=ScanStatus.PENDING.value, index=True)
    scan_result = Column(SafeText)
    threat_name = Column(SafeText)
    last_scanned = Column(DateTime)

    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    def __repr__(self) -> str:
        return f"<FileRecord {self.filepath!r} {self.scan_status}>"


class Allowance(Base):
    """One "allowed by you": this exact content flagged by this exact
    signature is a false positive, in your judgment. Keyed on content, not
    path -- an identical copy elsewhere is the same false positive, and a
    changed file is not covered."""
    __tablename__ = "allowances"
    __table_args__ = (UniqueConstraint("file_hash", "threat_name"),)

    id = Column(Integer, primary_key=True)
    file_hash = Column(String, nullable=False, index=True)   # SHA-256
    threat_name = Column(SafeText, nullable=False)
    # Where the file was when you allowed it: for the listing only.
    filepath = Column(FsPath, nullable=False)
    allowed_at = Column(DateTime, default=utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<Allowance {self.file_hash[:12]} {self.threat_name!r}>"


class DirectoryRecord(Base):
    """Tracked only for snapshot roots, to allow whole-subtree pruning."""

    __tablename__ = "directories"

    id = Column(Integer, primary_key=True)
    directory_path = Column(FsPath, unique=True, nullable=False)
    directory_name = Column(FsPath, nullable=False)
    mtime_ns = Column(Integer)
    last_scanned = Column(DateTime)

    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    def __repr__(self) -> str:
        return f"<DirectoryRecord {self.directory_path!r}>"
