"""Second opinions on flagged files, from sources other than the engine
that flagged them. Evidence never changes a verdict: a flagged file stays
flagged until a scan says otherwise or you allow it. It's shown next to the
hit, so you can decide faster.

The one source so far is the package manager (pkgdb.origins): did a
package install this file, and is it still exactly what the package put
there? A file that is gets the "likely false positive" label. A package is
not a guarantee -- an AUR package is a script anyone can publish, and a
compromised mirror is rare but possible -- so the label says what was
checked, and the file stays flagged.

Each fact is stored with the hash of the content it was checked against
(models.Evidence), and shown only while the finding is about that same
content: once the file changes, the old answer no longer applies. The
package manager checks the file as it is on disk now, not the content
that was flagged, so the file is hashed again after it answers, and the
answer is kept only if that's still the flagged content. Swapping the
file in between would take root, which owns package files anyway.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from . import pkgdb
from .findings import OPEN
from .fsutil import NotScannable, open_for_scan, sha256_fd
from .models import Evidence, FileRecord, Finding, utcnow

log = logging.getLogger(__name__)

SOURCE_PACKAGE = "package"

# pkgdb states worth keeping. UNOWNED and UNKNOWN say nothing either way,
# so they aren't stored (and an older answer is removed).
_KEPT = (pkgdb.FROM_PACKAGE, pkgdb.MODIFIED, pkgdb.OWNED)


def refresh(engine: Engine) -> int:
    """Ask the package manager about every file with an open finding.
    Returns how many files have package evidence afterwards. Does nothing
    when package verification is off or unavailable. A second opinion that
    fails (the database busy past its timeout, say) never fails the run:
    it's logged, and the report goes on without it."""
    if pkgdb.active().name == "none":
        return 0
    try:
        return _refresh(engine)
    except SQLAlchemyError:
        log.exception("could not save the package manager's answers about flagged files")
        return 0


def _refresh(engine: Engine) -> int:
    with Session(engine) as session:
        rows = session.query(FileRecord.id, FileRecord.filepath, FileRecord.file_hash).join(
            Finding, Finding.file_id == FileRecord.id).filter(
            Finding.state == OPEN, Finding.content_hash == FileRecord.file_hash).distinct().all()
        if not rows:
            return 0
        try:
            answers = pkgdb.origins([r.filepath for r in rows])
        except Exception:  # a second opinion failing must not fail the run
            log.exception("could not ask the package manager about flagged files")
            return 0
        kept = 0
        for file_id, filepath, digest in rows:
            state, package = answers.get(filepath, (pkgdb.UNKNOWN, None))
            existing = session.query(Evidence).filter(
                Evidence.file_id == file_id, Evidence.source == SOURCE_PACKAGE).first()
            if state in _KEPT and digest and _hash_now(filepath) != digest:
                state = pkgdb.UNKNOWN   # the answer is about other content than what was flagged
            if state not in _KEPT or not digest:
                if existing is not None:
                    session.delete(existing)
                continue
            if existing is None:
                existing = Evidence(file_id=file_id, source=SOURCE_PACKAGE)
                session.add(existing)
            existing.verdict = state
            existing.subject = package
            existing.content_hash = digest
            existing.checked_at = utcnow()
            kept += 1
        session.commit()
        return kept


def _hash_now(filepath: str) -> str | None:
    try:
        fd, _st = open_for_scan(Path(filepath))
    except (OSError, NotScannable):
        return None
    try:
        return sha256_fd(fd)
    except OSError:
        return None
    finally:
        os.close(fd)


def for_files(session: Session, files: dict[int, str | None]) -> dict[int, Evidence]:
    """{file id: package evidence} for files given as {id: current hash},
    only where the evidence was checked against that same content."""
    result: dict[int, Evidence] = {}
    ids = list(files)
    for start in range(0, len(ids), 500):   # see allowlist.reconcile: SQLite's variable limit
        for row in session.query(Evidence).filter(
                Evidence.file_id.in_(ids[start:start + 500]), Evidence.source == SOURCE_PACKAGE):
            if files.get(row.file_id) and row.content_hash == files[row.file_id]:
                result[row.file_id] = row
    return result


def likely_false_positive(found: Evidence | None) -> bool:
    """A package installed exactly this content (decision: only an
    unchanged package file earns the label)."""
    return found is not None and found.verdict == pkgdb.FROM_PACKAGE


def describe(found: Evidence) -> str:
    """One line for the reports."""
    package = found.subject or "a package"
    if found.verdict == pkgdb.FROM_PACKAGE:
        # The label already says "likely false positive": say what was checked.
        source = ("an AUR package is a script anyone can publish"
                  if pkgdb.active().name == "pacman" else "a package is only as good as where it came from")
        return (f"Installed by the package {package}, and unchanged since. That's only as trustworthy "
                f"as the package: {source}.")
    if found.verdict == pkgdb.MODIFIED:
        return (f"Belongs to the package {package}, but differs from what it installed. A changed "
                f"package file is worth a closer look.")
    return f"Belongs to the package {package}; it couldn't be compared with what the package installed."
