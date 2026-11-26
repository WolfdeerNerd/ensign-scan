"""Second opinions on flagged files, from sources other than the engine
that flagged them. Evidence never changes a verdict: a flagged file stays
flagged until a scan says otherwise or you allow it. It's shown next to the
hit, so you can decide faster.

Two sources so far:

  package  the package manager (pkgdb.origins): did a package install this
           file, and is it still exactly what the package put there?
  steam    Steam's record of a game's files (steam.py): is a flagged file in
           a game folder exactly what Steam installed for that game?

An unchanged package file gets the "likely false positive" label; an AUR
package is a script anyone can publish, so it says what was checked, and
the file stays flagged. Steam's match never gets that label: games have
shipped malware inside their official Steam builds, so it says only where
the file came from, and it turns into a warning when ClamAV names a known
malware family. Workshop files get a caveat instead (see steam.py).

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

from . import pkgdb, steam
from .explanations import known_family
from .findings import OPEN
from .fsutil import NotScannable, open_for_scan, sha256_fd
from .models import Evidence, FileRecord, Finding, utcnow

log = logging.getLogger(__name__)

SOURCE_PACKAGE = "package"
SOURCE_STEAM = "steam"
_ORDER = {SOURCE_PACKAGE: 0, SOURCE_STEAM: 1}   # how they're listed under a file

# pkgdb states worth keeping. UNOWNED and UNKNOWN say nothing either way,
# so they aren't stored (and an older answer is removed).
_KEPT = (pkgdb.FROM_PACKAGE, pkgdb.MODIFIED, pkgdb.OWNED)


def refresh(engine: Engine) -> int:
    """Ask every source about every file with an open finding. Returns how
    many pieces of evidence there are afterwards. The package manager isn't
    asked when package verification is off or unavailable. A second opinion
    that fails (the database busy past its timeout, say) never fails the
    run: it's logged, and the report goes on without it."""
    kept = 0
    if pkgdb.active().name != "none":
        try:
            kept += _refresh(engine)
        except SQLAlchemyError:
            log.exception("could not save the package manager's answers about flagged files")
    try:
        kept += _refresh_steam(engine)
    except SQLAlchemyError:
        log.exception("could not save Steam's answers about flagged files")
    return kept


def _open_flagged(session: Session):
    return session.query(FileRecord.id, FileRecord.filepath, FileRecord.file_hash).join(
        Finding, Finding.file_id == FileRecord.id).filter(
        Finding.state == OPEN, Finding.content_hash == FileRecord.file_hash).distinct().all()


def _store(session: Session, file_id: int, source: str, verdict: str | None, subject, digest) -> bool:
    """Save one source's answer about a file (replacing the last), or remove
    the last one when there's no answer worth keeping (verdict None)."""
    existing = session.query(Evidence).filter(Evidence.file_id == file_id, Evidence.source == source).first()
    if verdict is None or not digest:
        if existing is not None:
            session.delete(existing)
        return False
    if existing is None:
        existing = Evidence(file_id=file_id, source=source)
        session.add(existing)
    existing.verdict = verdict
    existing.subject = subject
    existing.content_hash = digest
    existing.checked_at = utcnow()
    return True


def _refresh_steam(engine: Engine) -> int:
    """Steam's record, for flagged files in Steam game folders. steam.check
    hashes the file itself and answers only for the flagged content."""
    with Session(engine) as session:
        rows = [r for r in _open_flagged(session)
                if "/steamapps/common/" in r.filepath or "/steamapps/workshop/content/" in r.filepath]
        if not rows:
            return 0
        records, kept = steam.Records(), 0
        for file_id, filepath, digest in rows:
            try:
                answer = steam.check(records, filepath, digest) if digest else None
            except Exception:  # a second opinion failing must not fail the run
                log.exception("could not check a flagged file against Steam's records")
                answer = None
            kept += _store(session, file_id, SOURCE_STEAM, answer and answer.verdict,
                           answer and answer.game, digest)
        session.commit()
        return kept


def _refresh(engine: Engine) -> int:
    with Session(engine) as session:
        rows = _open_flagged(session)
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
            if state in _KEPT and digest and _hash_now(filepath) != digest:
                state = pkgdb.UNKNOWN   # the answer is about other content than what was flagged
            kept += _store(session, file_id, SOURCE_PACKAGE, state if state in _KEPT else None, package, digest)
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


def for_files(session: Session, files: dict[int, str | None]) -> dict[int, list[Evidence]]:
    """{file id: its evidence, package first} for files given as {id:
    current hash}, only where the evidence was checked against that same
    content."""
    result: dict[int, list[Evidence]] = {}
    ids = list(files)
    for start in range(0, len(ids), 500):   # see allowlist.reconcile: SQLite's variable limit
        for row in session.query(Evidence).filter(
                Evidence.file_id.in_(ids[start:start + 500]), Evidence.source.in_(tuple(_ORDER))):
            if files.get(row.file_id) and row.content_hash == files[row.file_id]:
                result.setdefault(row.file_id, []).append(row)
    for facts in result.values():
        facts.sort(key=lambda e: _ORDER[e.source])
    return result


def likely_false_positive(found: Evidence | None) -> bool:
    """A package installed exactly this content (decision: only an unchanged
    package file earns the label; Steam's match never does)."""
    return found is not None and found.source == SOURCE_PACKAGE and found.verdict == pkgdb.FROM_PACKAGE


def label(found: Evidence, threat: str | None = None) -> str:
    """The label in front of describe()'s line."""
    if likely_false_positive(found):
        return "Likely false positive"
    if found.source == SOURCE_STEAM:
        if found.verdict == steam.MATCH:
            return "Warning" if known_family(threat) else "Matches Steam's build"
        return "Workshop" if found.verdict == steam.WORKSHOP else "Steam"
    return "Package"


def describe(found: Evidence, threat: str | None = None) -> str:
    """One line for the reports. threat: the signature that flagged the file."""
    if found.source == SOURCE_STEAM:
        game = found.subject or "a game"
        if found.verdict == steam.MATCH:
            family = known_family(threat)
            if family:
                return (f"Steam shipped this file for {game}, and ClamAV names a known malware family "
                        f"({family}): real malware has shipped this way, inside games' official Steam "
                        f"builds (PirateFi, BlockBlasters). Treat it as real. Investigation required.")
            return (f"Steam installed exactly this file for {game}. That shows where it came from, not that "
                    f"it's safe: games have shipped malware inside their official Steam builds (PirateFi, "
                    f"BlockBlasters). Steam's record is in your home folder, where anything running as you "
                    f"could change it.")
        if found.verdict == steam.WORKSHOP:
            return (f"Steam Workshop content for {game}: uploaded by a community member, not reviewed like "
                    f"a game's own build. Malicious Workshop items have been found before (Wallpaper "
                    f"Engine, Project Zomboid, People Playground); items carrying programs, scripts or "
                    f"password-protected archives deserve the most suspicion.")
        return (f"Steam's record for {game} lists this file with other contents. The game may have "
                f"changed it itself (some rewrite their own files), or something else did.")
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
