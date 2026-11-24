"""Findings, engines and evidence: the groundwork for more than one engine
and for second opinions on false positives (0.10.0).

Checked here:

  * a database from 0.9.x is upgraded: old allowances become ClamAV's, and
    its YARA sweep hits get their own engine;
  * an allowance covers only its own engine: the same content and signature
    found by the sweep's YARA pass is still flagged;
  * each hit is a finding, closed when a scan finds nothing or the content
    changes, and kept in line with allowances at the start of a run;
  * package evidence is shown with a flagged file, only for the content it
    was checked against, and an unchanged package file is labelled a
    likely false positive -- and is still flagged.

Runs anywhere: clamd is a stand-in, and so is the package manager.

    python3 tests/findings_test.py
"""
from __future__ import annotations

import sys as _sys_path
from pathlib import Path as _Path

# Run against THIS checkout, never an installed copy of Ensign.
ROOT = _Path(__file__).resolve().parent.parent
_sys_path.path.insert(0, str(ROOT))

import contextlib  # noqa: E402
import io  # noqa: E402
import os  # noqa: E402
import sqlite3  # noqa: E402
import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

from sqlalchemy.orm import Session  # noqa: E402

from ensign_scan import allowlist, evidence, findings, pkgdb, reports  # noqa: E402
from ensign_scan.clamd import ScanOutcome  # noqa: E402
from ensign_scan.config import Config  # noqa: E402
from ensign_scan.db import DATA_VERSION, make_engine  # noqa: E402
from ensign_scan.models import (  # noqa: E402
    ENGINE_CLAMAV_YARA,
    Allowance,
    AllowedFolder,
    Evidence,
    FileRecord,
    Finding,
    ScanStatus,
)
from ensign_scan.scanner import Scanner  # noqa: E402


class FakeClamd:
    """Flags EVIL as Test.Evil. Content containing YARA is reported as found
    by the sweep's YARA pass instead (the same signature name), which is
    how a second engine's hit reaches the scanner."""
    def __init__(self):
        self.version = 27000

    def daemon_uid(self):
        return 990   # not your uid: Ensign refuses a clamd running as you

    def supports_fildes(self):
        return True

    def signature_version(self):
        return self.version

    def max_threads(self):
        return 4

    def scan_fd(self, fd, label=""):
        data = os.pread(fd, 1 << 20, 0)
        if b"BROKEN" in data:
            return ScanOutcome(ScanStatus.ERROR, f"{label}: clamd stopped answering")
        if b"NONAME" in data:   # a hit ClamAV gave no signature name for
            return ScanOutcome(ScanStatus.INFECTED, f"{label}: FOUND", None)
        if b"EVIL" in data:
            engine = ENGINE_CLAMAV_YARA if b"YARA" in data else "clamav"
            return ScanOutcome(ScanStatus.INFECTED, f"{label}: Test.Evil FOUND", "Test.Evil", engine)
        return ScanOutcome(ScanStatus.CLEAN, f"{label}: OK")


def quiet(fn, *args, **kwargs):
    """Run fn with its output captured; line breaks folded into spaces."""
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        result = fn(*args, **kwargs)
    return result, " ".join(buf.getvalue().split())


def record(engine, name):
    with Session(engine) as session:
        row = session.query(FileRecord).filter(FileRecord.filepath.like(f"%/{name}")).one()
        session.expunge(row)
        return row


def finding_states(engine, name):
    row = record(engine, name)
    with Session(engine) as session:
        return sorted((f.engine, f.signature, f.state) for f in
                      session.query(Finding).filter(Finding.file_id == row.id))


yes = lambda prompt: True  # noqa: E731

# --- upgrading a 0.9.x database ---------------------------------------------------------------
with tempfile.TemporaryDirectory() as d:
    path = Path(d, "system.db")
    old = sqlite3.connect(path)
    # The tables as 0.9.1 made them (only what the upgrade touches).
    old.executescript("""
        CREATE TABLE files (id INTEGER NOT NULL, filepath VARCHAR NOT NULL, filename VARCHAR NOT NULL,
            file_hash VARCHAR NOT NULL, file_size INTEGER, mtime_ns INTEGER, ctime_ns INTEGER,
            sig_version INTEGER, scan_status VARCHAR, scan_result TEXT, threat_name TEXT,
            format_mismatch TEXT, last_scanned DATETIME, created_at DATETIME, updated_at DATETIME,
            PRIMARY KEY (id), UNIQUE (filepath));
        CREATE TABLE allowances (id INTEGER NOT NULL, file_hash VARCHAR NOT NULL,
            threat_name TEXT NOT NULL, filepath VARCHAR NOT NULL, allowed_at DATETIME NOT NULL,
            PRIMARY KEY (id), UNIQUE (file_hash, threat_name));
        CREATE INDEX ix_allowances_file_hash ON allowances (file_hash);
        CREATE TABLE allowed_folders (id INTEGER NOT NULL, folder VARCHAR NOT NULL,
            threat_name TEXT NOT NULL, allowed_at DATETIME NOT NULL, last_allowed_at DATETIME NOT NULL,
            PRIMARY KEY (id), UNIQUE (folder, threat_name));
        INSERT INTO files (id, filepath, filename, file_hash, scan_status, scan_result,
            threat_name) VALUES (1, '/data/a.bin', 'a.bin', 'aa', 'infected', '/data/a.bin: X FOUND', 'X');
        INSERT INTO files (id, filepath, filename, file_hash, scan_status, scan_result,
            threat_name) VALUES (2, '/data/huge.img', 'huge.img', 'bb', 'infected',
            'sweep: Y FOUND at 1 GiB by YARA, using Ensign''s translation', 'Y');
        INSERT INTO files (id, filepath, filename, file_hash, scan_status, scan_result)
            VALUES (3, '/data/ok.txt', 'ok.txt', 'cc', 'clean', 'OK');
        INSERT INTO allowances VALUES (1, 'bb', 'Y', '/data/huge.img', '2026-01-01 00:00:00');
        INSERT INTO allowed_folders VALUES (1, '/games', 'Z', '2026-01-01 00:00:00',
            '2026-01-01 00:00:00');
        PRAGMA user_version = 2;
    """)
    old.commit()
    old.close()

    engine = make_engine(f"sqlite:///{path}")
    with Session(engine) as session:
        allowance = session.query(Allowance).one()
        assert (allowance.file_hash, allowance.threat_name, allowance.engine) == ("bb", "Y", "clamav")
        assert session.query(AllowedFolder).one().engine == "clamav"
        engines = {r.filepath: r.threat_engine for r in session.query(FileRecord)}
        assert engines == {"/data/a.bin": None, "/data/huge.img": ENGINE_CLAMAV_YARA,
                           "/data/ok.txt": None}, engines
        made = sorted((f.file_id, f.engine, f.signature, f.state) for f in session.query(Finding))
        assert made == [(1, "clamav", "X", "open"), (2, ENGINE_CLAMAV_YARA, "Y", "open")], made
    raw = sqlite3.connect(path)
    assert raw.execute("PRAGMA user_version").fetchone()[0] == DATA_VERSION
    leftovers = [r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE name LIKE '%before%'")]
    assert not leftovers, leftovers
    raw.close()
    # The old allowance was ClamAV's; the YARA pass's hit on that content isn't covered by it.
    assert allowlist.orphaned(engine) == set()
    assert ("bb", "Y", ENGINE_CLAMAV_YARA) not in allowlist.allowed_keys(engine)
    engine.dispose()
    make_engine(f"sqlite:///{path}").dispose()   # a second start changes nothing, and doesn't fail
    print("upgrade from 0.9.x test passed ✓")

# --- engines, findings and evidence during runs ------------------------------------------------
with tempfile.TemporaryDirectory() as d:
    tree = Path(d, "tree")
    tree.mkdir()
    (tree / "asset.dat").write_bytes(b"game data EVIL bytes")
    (tree / "yara.dat").write_bytes(b"game data EVIL bytes, YARA")
    (tree / "pkg.so").write_bytes(b"library EVIL bytes")
    Path(d, "data").mkdir()
    config = Config(db_url=f"sqlite:///{d}/data/system.db", log_file=Path(d, "data", "e.txt"),
                    max_workers=2, rescan_after_signature_updates=1)
    clamd = FakeClamd()

    def scan():
        s = Scanner(config, clamd=clamd)  # a fresh Scanner per run, like the CLI
        allowlist.reconcile(s.engine)
        findings.tidy(s.engine)
        quiet(s.scan_tree, tree)
        quiet(s.rescan_infected)
        return s

    engine = scan().engine
    assert record(engine, "yara.dat").threat_engine == ENGINE_CLAMAV_YARA
    assert record(engine, "asset.dat").threat_engine is None, "NULL means ClamAV, as before"
    assert finding_states(engine, "asset.dat") == [("clamav", "Test.Evil", "open")]
    assert finding_states(engine, "yara.dat") == [(ENGINE_CLAMAV_YARA, "Test.Evil", "open")]

    # Allowing asset.dat covers ClamAV's hit. yara.dat has the same signature
    # name from another engine: allowing one never covers the other.
    ok, out = quiet(allowlist.allow, engine, str(tree / "asset.dat"), yes)
    assert ok, out
    ok, out = quiet(allowlist.allow, engine, str(tree / "yara.dat"), yes)
    assert ok and "Found by:" in out, out
    with Session(engine) as session:
        keys = {(a.threat_name, a.engine) for a in session.query(Allowance)}
    assert keys == {("Test.Evil", "clamav"), ("Test.Evil", ENGINE_CLAMAV_YARA)}, keys
    ok, _ = quiet(allowlist.unallow, engine, str(tree / "yara.dat"))
    assert ok
    scan()
    assert record(engine, "asset.dat").scan_status == "allowed"
    assert record(engine, "yara.dat").scan_status == "infected", "the other engine's hit stays flagged"
    assert finding_states(engine, "asset.dat") == [("clamav", "Test.Evil", "allowed")]
    print("an allowance covers only its own engine test passed ✓")

    # Content changes: the old finding is gone, a new one is about the new content.
    (tree / "asset.dat").write_bytes(b"game data, now harmless")
    scan()
    assert record(engine, "asset.dat").scan_status == "clean"
    assert finding_states(engine, "asset.dat") == [("clamav", "Test.Evil", "gone")]
    (tree / "asset.dat").write_bytes(b"game data EVIL again, other bytes")
    scan()
    assert finding_states(engine, "asset.dat") == [("clamav", "Test.Evil", "gone"),
                                                  ("clamav", "Test.Evil", "open")]
    # Changed content that couldn't be scanned: the old finding was about
    # other content, so it's closed, even though no new verdict replaces it.
    (tree / "asset.dat").write_bytes(b"BROKEN content now")
    scan()
    assert record(engine, "asset.dat").scan_status == "error"
    assert all(state == "gone" for *_, state in finding_states(engine, "asset.dat")), \
        finding_states(engine, "asset.dat")
    (tree / "asset.dat").write_bytes(b"game data EVIL again, other bytes")   # the earlier content
    scan()
    assert finding_states(engine, "asset.dat") == [("clamav", "Test.Evil", "gone"),
                                                  ("clamav", "Test.Evil", "open")], \
        "the same content flagged again reopens its finding"
    # A hit with no signature name is allowed as "Unknown", the file included.
    (tree / "noname.dat").write_bytes(b"NONAME hit")
    scan()
    ok, out = quiet(allowlist.allow, engine, str(tree / "noname.dat"), yes)
    assert ok and record(engine, "noname.dat").scan_status == "allowed", out
    (tree / "noname.dat").unlink()
    with Session(engine) as session:
        session.query(FileRecord).filter(FileRecord.filepath.like("%/noname.dat")).delete()
        session.query(Allowance).filter(Allowance.threat_name == "Unknown").delete()
        session.commit()
    # The engine shown comes from the database, so it's escaped like a name.
    with Session(engine) as session:
        session.query(FileRecord).filter(FileRecord.filepath.like("%/yara.dat")).update(
            {FileRecord.threat_engine: "x\x1b]0;pwned\x07"}, synchronize_session=False)
        session.commit()
    _, text = quiet(reports.list_infected, engine)
    assert "\x1b" not in text and "Found by:" in text, repr(text)
    # A deleted file's findings are tidied away with its record.
    # --purge-missing deletes them with the record, at once: SQLite can give
    # the deleted record's id to the next new file.
    (tree / "yara.dat").unlink()
    quiet(Scanner(config, clamd=clamd).purge_missing)
    with Session(engine) as session:
        assert session.query(Finding).filter(Finding.engine == ENGINE_CLAMAV_YARA).count() == 0
    # And a record deleted some other way: tidied at the start of the next run.
    (tree / "gone.dat").write_bytes(b"EVIL to be removed")
    scan()
    (tree / "gone.dat").unlink()
    with Session(engine) as session:
        session.query(FileRecord).filter(FileRecord.filepath.like("%/gone.dat")).delete()
        session.commit()
    scan()
    with Session(engine) as session:
        known = {r.id for r in session.query(FileRecord)}
        assert {f.file_id for f in session.query(Finding)} <= known
    print("finding lifecycle test passed ✓")

    # --- evidence: what the package manager says, never a verdict --------------------------------
    class FakeBackend:
        name, label = "pacman", "pacman"

        def owner(self, path):   # the report's Context line asks this when there's no evidence
            return ("unowned", None)
    answers = {str(tree / "pkg.so"): (pkgdb.FROM_PACKAGE, "libfoo"),
               str(tree / "asset.dat"): (pkgdb.MODIFIED, "game-data")}
    real_active, real_origins = pkgdb.active, pkgdb.origins
    pkgdb.active = lambda: FakeBackend()
    pkgdb.origins = lambda paths, backend=None: {p: answers.get(p, (pkgdb.UNOWNED, None)) for p in paths}
    try:
        assert evidence.refresh(engine) == 2
        _, text = quiet(reports.list_infected, engine)
        assert "Likely false positive: Installed by the package libfoo, and unchanged since" in text, text
        assert "differs from what it installed" in text, text
        assert record(engine, "pkg.so").scan_status == "infected", "evidence never changes a verdict"
        assert "not owned by any" not in text, "the Context line doesn't repeat the package"

        # The package manager checks the file on disk now. If that isn't the
        # flagged content any more, its answer isn't kept for that content.
        (tree / "pkg.so").write_bytes(b"library EVIL bytes, replaced")
        evidence.refresh(engine)
        with Session(engine) as session:
            assert {e.subject for e in session.query(Evidence)} == {"game-data"}, \
                "an answer about other content than what was flagged"
        answers[str(tree / "pkg.so")] = (pkgdb.FROM_PACKAGE, "libfoo")

        # Evidence is about the content it was checked against.
        assert evidence.refresh(engine) == 1   # pkg.so not scanned again yet: still not kept
        scan()
        _, text = quiet(reports.list_infected, engine)
        assert "libfoo" not in text, "an answer about other content isn't shown"
        assert "not owned by any pacman package" in text, "Context asks again instead"
        # Asked again: the package manager no longer vouches for it, so the old answer goes.
        answers[str(tree / "pkg.so")] = (pkgdb.UNOWNED, None)
        evidence.refresh(engine)
        with Session(engine) as session:
            sources = {(e.subject, e.verdict) for e in session.query(Evidence)}
        assert sources == {("game-data", pkgdb.MODIFIED)}, sources

        # An answer stored for older content is never shown for the new.
        with Session(engine) as session:
            session.add(Evidence(file_id=record(engine, "pkg.so").id, source="package",
                                 verdict=pkgdb.FROM_PACKAGE, subject="stale-pkg", content_hash="0" * 64))
            session.commit()
        _, text = quiet(reports.list_infected, engine)
        assert "stale-pkg" not in text, text

        # Verification off: nothing is asked, and nothing stored is touched.
        FakeBackend.name = "none"
        assert evidence.refresh(engine) == 0
    finally:
        pkgdb.active, pkgdb.origins = real_active, real_origins
    print("package evidence test passed ✓")

print("\nAll findings tests passed ✓")
