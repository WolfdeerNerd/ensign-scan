"""SQLAlchemy models for Ensign.

Models hold data only. Change-detection logic, scanning, and reporting
live elsewhere.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanStatus(str, Enum):
    CLEAN = "clean"
    INFECTED = "infected"
    ERROR = "error"
    PENDING = "pending"
    # Permission was denied, but the path matches a known secrets
    # pattern (wallets, SSH/GPG keys, etc) -- treated as expected, not
    # an error to chase. Distinct from ERROR so it naturally drops out
    # of error_summary() and suggest_fixes() without either needing to
    # special-case it.
    CLASSIFIED = "classified"


class FileRecord(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True)
    filepath = Column(String, unique=True, nullable=False)
    filename = Column(String, nullable=False)
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
    scan_result = Column(Text)
    threat_name = Column(String)
    last_scanned = Column(DateTime)

    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    def __repr__(self) -> str:
        return f"<FileRecord {self.filepath!r} {self.scan_status}>"


class DirectoryRecord(Base):
    """Tracked only for snapshot roots, to allow whole-subtree pruning."""

    __tablename__ = "directories"

    id = Column(Integer, primary_key=True)
    directory_path = Column(String, unique=True, nullable=False)
    directory_name = Column(String, nullable=False)
    mtime_ns = Column(Integer)
    last_scanned = Column(DateTime)

    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    def __repr__(self) -> str:
        return f"<DirectoryRecord {self.directory_path!r}>"
