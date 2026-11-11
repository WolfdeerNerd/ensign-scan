"""Files the user running Ensign can't open.

Since 0.3.0 Ensign opens every file itself and hands clamd the open
descriptor. When that open() failed -- a file owned by root or another
user, most often -- the file was logged and then dropped: no database
row, not counted as an error, in no report. A run over a folder full of
root-owned files said "Total files: 0, Errors: 0". And a file scanned
clean earlier that later became unreadable kept its old "clean" record.

Now it's recorded as an ERROR, kept apart from clamd's own refusals, and
retried every run.

Run: python3 tests/unreadable_test.py   (as your normal user, not root)
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
import sys  # noqa: E402
import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

from sqlalchemy.orm import Session  # noqa: E402

from ensign_scan import reports  # noqa: E402
from ensign_scan.clamd import ScanOutcome  # noqa: E402
from ensign_scan.config import Config  # noqa: E402
from ensign_scan.models import FileRecord, ScanStatus, is_open_failed  # noqa: E402
from ensign_scan.scanner import Scanner  # noqa: E402

if os.geteuid() == 0:
    print("unreadable-file tests skipped: root can open everything (run as your normal user)")
    sys.exit(0)


class FakeClamd:
    def daemon_uid(self):
        return 1000

    def supports_fildes(self):
        return True

    def signature_version(self):
        return 27455

    def max_threads(self):
        return 2

    def scan_fd(self, fd, label=""):
        return ScanOutcome(ScanStatus.CLEAN, f"{label}: OK")


def flat(text: str) -> str:
    return " ".join(text.split())


def record(engine, path: Path):
    with Session(engine) as session:
        r = session.query(FileRecord).filter(FileRecord.filepath == str(path)).one_or_none()
        return None if r is None else (r.scan_status, r.scan_result, r.file_hash)


with tempfile.TemporaryDirectory() as d:
    tree = Path(d, "tree")
    tree.mkdir()
    locked = tree / "locked.txt"
    locked.write_text("you can't read me")
    locked.chmod(0o000)  # unreadable even by its owner, without needing root
    (tree / "fine.txt").write_text("hello")
    Path(d, "data").mkdir()
    config = Config(db_url=f"sqlite:///{d}/data/system.db", log_file=Path(d, "data", "errors.txt"),
                    max_workers=2)

    # --- an unreadable file is recorded and counted, not dropped ----------------------
    scanner = Scanner(config, clamd=FakeClamd())
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        scanner.scan_tree(tree)
    assert "locked.txt" in buf.getvalue() and "Permission denied" in buf.getvalue(), buf.getvalue()
    status, result, digest = record(scanner.engine, locked)
    assert status == "error" and is_open_failed(result) and "Permission denied" in result, (status, result)
    assert digest == "", "never read, so no hash"
    with contextlib.redirect_stdout(io.StringIO()):
        counts = reports.scan_summary(scanner.engine)
    assert counts.get("error") == 1 and counts.get("total") == 2, counts
    print("unreadable-file record test passed ✓")

    # --- the reports say what happened, in Ensign's words, not clamd's ------------------
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        reports.error_summary(scanner.engine)
        reports.suggest_fixes(scanner.engine)
    out = flat(buf.getvalue())
    assert "Ensign could not open this file (Permission denied)" in out, out
    assert "FILES ENSIGN COULD NOT OPEN (1 directories)" in out
    assert "FILES CLAMD COULD NOT READ" not in out, "this was never clamd's refusal"
    assert "setfacl" not in out and "chmod" not in out, "still advisory: no permission commands"
    print("report tests passed ✓")

    # --- readable again: the next run scans it -------------------------------------------
    locked.chmod(0o600)
    with contextlib.redirect_stdout(io.StringIO()):
        scanner.rescan_errors()
    status, _, digest = record(scanner.engine, locked)
    assert status == "clean" and digest, (status, digest)
    print("recovery test passed ✓")

    # --- a file scanned clean that later becomes unreadable is no longer "clean" ---------
    clean_hash = digest
    locked.chmod(0o000)
    os.utime(locked, ns=(1, 1))  # look changed, so the walk picks it up
    with contextlib.redirect_stdout(io.StringIO()):
        scanner.scan_tree(tree)
    status, result, digest = record(scanner.engine, locked)
    assert status == "error", "an old 'clean' must not stand for a file nobody can check"
    assert digest == clean_hash, "the stored hash survives, as a baseline for when it's readable again"
    locked.chmod(0o600)
    print("stale-clean test passed ✓")

print("\nAll unreadable-file tests passed ✓")
