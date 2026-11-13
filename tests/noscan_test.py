"""--no-scan must never leave a changed file looking scanned.

A --no-scan run hashes files and records them without asking ClamAV. It
used to save a changed file's new hash, size and times and keep the old
verdict beside them. A file that was clean, then replaced with malware,
then seen by a --no-scan run, stayed "clean": every later scan found its
size and times matching the database and skipped it as unchanged.

Now a --no-scan run that finds different content clears the old verdict
("pending"), and the next real scan picks up every pending file -- also
one first recorded by --no-scan, which used to wait for the stale rescan.

Run: python3 tests/noscan_test.py
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
import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

from sqlalchemy.orm import Session  # noqa: E402

from ensign_scan.clamd import ScanOutcome  # noqa: E402
from ensign_scan.config import Config  # noqa: E402
from ensign_scan.models import FileRecord, ScanStatus  # noqa: E402
from ensign_scan.scanner import Scanner  # noqa: E402

MARKER = b"PRETEND-MALWARE"


class FakeClamd:
    """Flags any file whose contents hold MARKER; counts what it is sent."""

    def __init__(self):
        self.scanned = 0

    def daemon_uid(self):
        return 1000

    def supports_fildes(self):
        return True

    def signature_version(self):
        return 27455

    def max_threads(self):
        return 2

    def scan_fd(self, fd, label=""):
        self.scanned += 1
        if MARKER in os.pread(fd, 4096, 0):
            return ScanOutcome(ScanStatus.INFECTED, f"{label}: Test.Marker FOUND", "Test.Marker")
        return ScanOutcome(ScanStatus.CLEAN, f"{label}: OK")


def record(engine, path: Path):
    with Session(engine) as session:
        r = session.query(FileRecord).filter(FileRecord.filepath == str(path)).one()
        return r.scan_status, r.threat_name, r.sig_version, r.last_scanned


def run(config, tree, scan=True):
    """One scan of `tree` with a fresh Scanner, as a new run would be."""
    clamd = FakeClamd()
    scanner = Scanner(config, clamd=clamd)
    with contextlib.redirect_stdout(io.StringIO()):
        stats = scanner.scan_tree(tree, scan=scan)
    return scanner, clamd, stats


def rewrite(path: Path, data: bytes) -> None:
    """Replace a file's contents and make sure its recorded times differ."""
    before = os.stat(path).st_mtime_ns
    path.write_bytes(data)
    os.utime(path, ns=(before + 10**9, before + 10**9))


with tempfile.TemporaryDirectory() as d:
    tree = Path(d, "tree")
    tree.mkdir()
    data_dir = Path(d, "data")
    data_dir.mkdir()
    config = Config._from_dict({"data_dir": str(data_dir)}, source="test")

    # --- a clean file, replaced, then seen by --no-scan -------------------
    changed = tree / "changed.bin"
    changed.write_bytes(b"harmless")
    scanner, _, _ = run(config, tree)
    assert record(scanner.engine, changed)[0] == "clean"

    rewrite(changed, MARKER)
    scanner, clamd, _ = run(config, tree, scan=False)
    assert clamd.scanned == 0, "--no-scan sent a file to clamd"
    status, threat, sig, last = record(scanner.engine, changed)
    assert status == "pending", f"changed file kept its old verdict after --no-scan: {status}"
    assert (threat, sig, last) == (None, None, None), "old verdict details survived --no-scan"

    scanner, clamd, stats = run(config, tree)
    assert stats.never_scanned == 1 and stats.unchanged == 0, stats
    assert record(scanner.engine, changed)[:2] == ("infected", "Test.Marker"), \
        "the scan after --no-scan skipped the changed file"

    # --- an infected file, replaced with something harmless ----------------
    # The old detection was for other content: it goes too, and the next
    # scan gives the real answer.
    rewrite(changed, b"harmless again")
    scanner, _, _ = run(config, tree, scan=False)
    assert record(scanner.engine, changed)[0] == "pending"
    scanner, _, _ = run(config, tree)
    assert record(scanner.engine, changed)[:2] == ("clean", None)

    # --- unchanged content keeps its verdict -------------------------------
    # Same bytes, new times (a touch): the verdict was for exactly this
    # content, so --no-scan leaves it alone.
    stamp = os.stat(changed).st_mtime_ns + 10**9
    os.utime(changed, ns=(stamp, stamp))
    scanner, _, _ = run(config, tree, scan=False)
    status, _, sig, last = record(scanner.engine, changed)
    assert status == "clean" and sig == 27455 and last is not None, "a touch wiped a valid verdict"
    scanner, clamd, stats = run(config, tree)
    assert clamd.scanned == 0 and stats.unchanged == 1, "an unchanged, scanned file was scanned again"

    # --- a file first recorded by --no-scan --------------------------------
    fresh = tree / "fresh.bin"
    fresh.write_bytes(MARKER)
    scanner, _, _ = run(config, tree, scan=False)
    assert record(scanner.engine, fresh)[0] == "pending"
    # A second --no-scan run has nothing to add: pending files are left alone.
    scanner, _, stats = run(config, tree, scan=False)
    assert stats.never_scanned == 0 and stats.unchanged == 2, stats
    # The next real scan checks it, without waiting for the stale rescan.
    scanner, clamd, stats = run(config, tree)
    assert stats.never_scanned == 1 and clamd.scanned == 1, stats
    assert record(scanner.engine, fresh)[:2] == ("infected", "Test.Marker")

print("no-scan tests passed")
