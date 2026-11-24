"""Findings: what each engine found in each file, and when.

files.scan_status stays the summary every report reads. A finding is the
history behind it: which engine found which signature in which content,
when it was first and last seen, and whether it is open, allowed or gone.
It's what lets two engines flag one file without one hiding the other,
and what evidence (evidence.py) is attached to.

The rules, kept by the scanner in the same transaction as the verdict:

* A ClamAV pass on a file speaks for the ClamAV engines (CLAMAV_ENGINES:
  clamd or clamscan, the sweep, and the sweep's YARA pass, which all use
  ClamAV's signatures). The hit it reports is open, or allowed if you
  allowed it; any other open ClamAV hit on that file is gone, since ClamAV
  no longer reports it. A clean result makes them all gone.
* A file whose content changed since its hits were found (a --no-scan run
  sees a new hash) has them all gone: they were about other content.
* An error, or a sweep that couldn't scan a file whole, changes nothing:
  no engine has given a new answer.

tidy() runs at the start of each run: it removes findings and evidence of
files that are no longer recorded, and brings each finding's state in line
with your allowances (which can change without a scan, and in protected
mode are root's).
"""
from __future__ import annotations

from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from .models import CLAMAV_ENGINES, Evidence, FileRecord, Finding, ScanStatus, utcnow

OPEN, ALLOWED, GONE = "open", "allowed", "gone"


def record_outcome(session: Session, record: FileRecord, outcome) -> None:
    """Bring `record`'s findings in line with a new scan `outcome` (a
    clamd.ScanOutcome). The caller has flushed the record and commits."""
    status = outcome.status
    if status in (ScanStatus.INFECTED, ScanStatus.ALLOWED):
        signature = outcome.threat_name or "Unknown"
        now = utcnow()
        state = ALLOWED if status == ScanStatus.ALLOWED else OPEN
        found = session.query(Finding).filter(
            Finding.file_id == record.id, Finding.engine == outcome.engine,
            Finding.signature == signature, Finding.content_hash == record.file_hash).first()
        if found is None:
            found = Finding(file_id=record.id, engine=outcome.engine, signature=signature,
                            content_hash=record.file_hash, detail=outcome.raw,
                            first_seen=now, last_seen=now, state=state)
            session.add(found)
            session.flush()
        else:
            found.last_seen, found.state, found.detail = now, state, outcome.raw
        if outcome.engine in CLAMAV_ENGINES:
            _gone(session, record.id, CLAMAV_ENGINES, keep=found.id)
    elif status == ScanStatus.CLEAN and outcome.engine in CLAMAV_ENGINES:
        _gone(session, record.id, CLAMAV_ENGINES)


def content_changed(session: Session, file_id: int) -> None:
    """The file's content changed without a scan: its findings were about
    other content."""
    _gone(session, file_id, None)


def clamav_found_nothing(session: Session, file_id: int) -> None:
    """The sweep found none of ClamAV's signatures in a file it can't scan
    whole: an earlier hit there (older signatures, say) is no longer found."""
    _gone(session, file_id, CLAMAV_ENGINES)


def _gone(session: Session, file_id: int, engines, keep: int | None = None) -> None:
    query = session.query(Finding).filter(Finding.file_id == file_id, Finding.state != GONE)
    if engines is not None:
        query = query.filter(Finding.engine.in_(engines))
    if keep is not None:
        query = query.filter(Finding.id != keep)
    query.update({Finding.state: GONE}, synchronize_session=False)


def tidy(engine: Engine) -> None:
    """At the start of a run: drop findings and evidence of files no longer
    recorded, and match each finding's state to your allowances."""
    from .allowlist import allowed_keys, key   # allowlist imports models only; no cycle
    keys = allowed_keys(engine)
    with Session(engine) as session:
        for table in (Finding, Evidence):
            session.query(table).filter(
                ~table.file_id.in_(session.query(FileRecord.id))).delete(synchronize_session=False)
        for found in session.query(Finding).filter(Finding.state != GONE):
            state = ALLOWED if key(found.content_hash, found.signature, found.engine) in keys else OPEN
            if found.state != state:
                found.state = state
        session.commit()


def current(session: Session, file_ids) -> dict[int, list[Finding]]:
    """The open and allowed findings of these files, newest first."""
    result: dict[int, list[Finding]] = {}
    ids = list(file_ids)
    for start in range(0, len(ids), 500):   # see allowlist.reconcile: SQLite's variable limit
        for found in session.query(Finding).filter(
                Finding.file_id.in_(ids[start:start + 500]), Finding.state != GONE).order_by(
                Finding.last_seen.desc()):
            result.setdefault(found.file_id, []).append(found)
    return result
