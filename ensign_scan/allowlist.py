"""Allowed by you: false positives you have told Ensign to stop flagging.

ClamAV sometimes flags a harmless file. Once you have checked one and are
sure, `ensign-scan --allow PATH` records it as allowed. That is your
judgment, not Ensign's or ClamAV's, so it is kept narrow and in plain view:

- It covers one exact content (the file's SHA-256) flagged by one exact
  signature name. If the file changes, or a different signature hits it,
  it is flagged again. An identical copy elsewhere is covered, since it is
  the same bytes and the same false positive.
- Allowed files are listed in their own section at the end of every run,
  and with --list-allowed. They are never hidden.
- They don't count as infected for alerts or the exit code.
- They are still rescanned when the signatures update, so a false positive
  ClamAV has since fixed simply turns clean.
- --unallow PATH undoes it.

Everything stays in Ensign's own database. ClamAV and its signatures are
not touched, so nothing else using clamd is affected (unlike ClamAV's own
.sfp/.ign2 allow lists, which apply to every program using clamd).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from rich import print
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from .fsutil import open_for_scan, print_unwrapped, sha256_fd, shown
from .models import Allowance, FileRecord, ScanStatus, utcnow


def allowed_pairs(engine: Engine) -> set[tuple[str, str]]:
    """Every (SHA-256, signature name) you have allowed."""
    with Session(engine) as session:
        return {(h, t) for h, t in session.query(Allowance.file_hash, Allowance.threat_name)}


@dataclass
class _Candidate:
    path: str
    digest: str
    threat: str


def _candidate(engine: Engine, path: str) -> _Candidate | str:
    """What --allow would allow for `path`, or why it can't."""
    with Session(engine) as session:
        record = session.query(FileRecord).filter(FileRecord.filepath == path).first()
        if record is None:
            return "Ensign has no record of this file. Scan it first."
        if record.scan_status == ScanStatus.ALLOWED.value:
            return "This file is already allowed."
        if record.scan_status != ScanStatus.INFECTED.value:
            return (f"Only files ClamAV flagged can be allowed; this one is recorded as "
                    f"'{record.scan_status}'.")
        stored, threat = record.file_hash, record.threat_name or "Unknown"
    # Hash it again now: only the exact bytes that were flagged can be
    # allowed, never whatever the file has become since.
    try:
        fd, _st = open_for_scan(Path(path))
    except OSError as exc:
        return f"Ensign can't open this file to check it: {exc.strerror or exc}."
    try:
        digest = sha256_fd(fd)
    finally:
        os.close(fd)
    if digest != stored:
        return ("This file has changed since it was scanned, so it isn't the content ClamAV "
                "flagged. Scan it again first.")
    return _Candidate(path, digest, threat)


def allow(engine: Engine, path: str, confirm) -> bool:
    """Allow one flagged file. `confirm(prompt) -> bool` asks you to confirm.
    Returns True if it was allowed."""
    found = _candidate(engine, path)
    if isinstance(found, str):
        print_unwrapped(f"[yellow]Not allowed:[/yellow] {shown(path)}\n  {found}")
        return False
    print_unwrapped(f"\n  File:      {shown(found.path)}")
    print(f"  Signature: {shown(found.threat)}")
    print(f"  SHA-256:   {found.digest}")
    print("  Allowing tells Ensign this is a false positive: it stops counting this exact "
          "content, flagged by this exact signature, as infected. If the file changes or "
          "another signature flags it, it's flagged again. Only allow a file you've checked.")
    if not confirm("  Allow it? [y/N] "):
        print("  Not allowed.")
        return False
    with Session(engine) as session:
        exists = session.query(Allowance).filter(
            Allowance.file_hash == found.digest, Allowance.threat_name == found.threat).first()
        if exists is None:
            session.add(Allowance(file_hash=found.digest, threat_name=found.threat,
                                  filepath=found.path, allowed_at=utcnow()))
        # Every copy of the same content flagged by the same signature.
        copies = session.query(FileRecord).filter(
            FileRecord.file_hash == found.digest,
            FileRecord.threat_name == found.threat,
            FileRecord.scan_status == ScanStatus.INFECTED.value,
        ).all()
        for record in copies:
            record.scan_status = ScanStatus.ALLOWED.value
        session.commit()
    others = len(copies) - 1
    also = f" (and {others} identical {'copy' if others == 1 else 'copies'} elsewhere)" if others > 0 else ""
    print_unwrapped(f"[green]  Allowed{also}.[/green] Undo with: ensign-scan --unallow {shown(found.path)}")
    return True


def unallow(engine: Engine, path: str) -> bool:
    """Undo --allow for the content at `path` (or allowed from there, if
    the file has since gone). Its copies are flagged as infected again."""
    with Session(engine) as session:
        record = session.query(FileRecord).filter(FileRecord.filepath == path).first()
        pairs = set()
        if record is not None and record.scan_status == ScanStatus.ALLOWED.value:
            pairs.add((record.file_hash, record.threat_name))
        for row in session.query(Allowance).filter(Allowance.filepath == path):
            pairs.add((row.file_hash, row.threat_name))
        if not pairs:
            print_unwrapped(f"[yellow]Nothing to undo:[/yellow] {shown(path)} isn't allowed.")
            return False
        flagged = 0
        for digest, threat in pairs:
            session.query(Allowance).filter(
                Allowance.file_hash == digest, Allowance.threat_name == threat).delete()
            flagged += session.query(FileRecord).filter(
                FileRecord.file_hash == digest,
                FileRecord.threat_name == threat,
                FileRecord.scan_status == ScanStatus.ALLOWED.value,
            ).update({FileRecord.scan_status: ScanStatus.INFECTED.value})
        session.commit()
    print_unwrapped(f"[yellow]No longer allowed:[/yellow] {shown(path)} "
                    f"({flagged} file{'s' if flagged != 1 else ''} flagged as infected again).")
    return True


def allowed_report(engine: Engine, paths: list[str] | None = None, top: int = 10) -> int:
    """The end-of-run section: files currently allowed, within the run's
    scope (`paths`, as for the other reports). Returns how many there are."""
    from .reports import _scope_filter  # reports doesn't import this module; no cycle
    paths_filter = _scope_filter(paths)
    with Session(engine) as session:
        query = session.query(FileRecord.filepath, FileRecord.threat_name, FileRecord.file_hash).filter(
            FileRecord.scan_status == ScanStatus.ALLOWED.value)
        if paths_filter is not None:
            query = query.filter(paths_filter)
        rows = sorted(query.all(), key=lambda r: (r.threat_name or "", r.filepath))
        when = {(h, t): at for h, t, at in
                session.query(Allowance.file_hash, Allowance.threat_name, Allowance.allowed_at)}
    if not rows:
        return 0
    print(f"\n[bold]=== ALLOWED BY YOU ({len(rows)} file{'s' if len(rows) != 1 else ''}) ===[/bold]")
    print("Flagged by ClamAV, and marked by you as false positives. Not counted as infected. "
          "ensign-scan --list-allowed shows them all; --unallow PATH undoes one.")
    for filepath, threat, digest in rows[:top]:
        date = when.get((digest, threat))
        on = f", allowed {date:%Y-%m-%d}" if date else ""
        print_unwrapped(f"  [cyan]○[/cyan] {shown(filepath)}  [dim]({shown(threat)}{on})[/dim]")
    if len(rows) > top:
        print(f"  … and {len(rows) - top} more (ensign-scan --list-allowed)")
    return len(rows)


def list_allowed(engine: Engine) -> int:
    """Every allowance, with where its content is now."""
    with Session(engine) as session:
        allowances = session.query(Allowance).order_by(Allowance.allowed_at).all()
        where = {}
        for a in allowances:
            where[a.id] = [r.filepath for r in session.query(FileRecord.filepath).filter(
                FileRecord.file_hash == a.file_hash, FileRecord.threat_name == a.threat_name,
                FileRecord.scan_status == ScanStatus.ALLOWED.value)]
        rows = [(a.id, a.filepath, a.threat_name, a.file_hash, a.allowed_at) for a in allowances]
    if not rows:
        print("Nothing is allowed. (ensign-scan --allow PATH marks a flagged file as a false positive.)")
        return 0
    print(f"\n=== ALLOWED BY YOU ({len(rows)}) ===")
    for row_id, filepath, threat, digest, allowed_at in rows:
        print(f"\n  Signature: {shown(threat)}")
        print_unwrapped(f"  Allowed:   {allowed_at:%Y-%m-%d %H:%M} UTC, from {shown(filepath)}")
        print(f"  SHA-256:   {digest}")
        found = where[row_id]
        if found:
            for p in found:
                print_unwrapped(f"  [cyan]○[/cyan] {shown(p)}")
        else:
            print("  [dim](no file with this content is tracked right now)[/dim]")
    return len(rows)
