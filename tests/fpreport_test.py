"""--clamav-report: a false-positive report for ClamAV, ready to submit.

Checked here:

  * only a flagged file whose content still matches the scan gets a report;
  * it's scanned again first: if ClamAV no longer flags it, nothing is written;
  * .UNOFFICIAL signatures and sweep hits are sent elsewhere, not reported;
  * the report holds the signature, hashes and versions, and nothing that
    identifies you or the file: no name, path, username or hostname;
  * the file itself is never copied, only named on screen;
  * a file in a personal folder gets a warning.

Runs anywhere: clamd is a stand-in that flags content containing "EVIL".

    python3 tests/fpreport_test.py
"""
from __future__ import annotations

import sys as _sys_path
from pathlib import Path as _Path

# Run against THIS checkout, never an installed copy of Ensign.
ROOT = _Path(__file__).resolve().parent.parent
_sys_path.path.insert(0, str(ROOT))

import contextlib  # noqa: E402
import getpass  # noqa: E402
import hashlib  # noqa: E402
import io  # noqa: E402
import os  # noqa: E402
import socket  # noqa: E402
import stat  # noqa: E402
import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

from sqlalchemy.orm import Session  # noqa: E402

from ensign_scan import fpreport  # noqa: E402
from ensign_scan.clamd import ScanOutcome  # noqa: E402
from ensign_scan.config import Config  # noqa: E402
from ensign_scan.models import FileRecord, ScanStatus  # noqa: E402
from ensign_scan.scanner import Scanner  # noqa: E402


class FakeClamd:
    """Flags content containing EVIL as `name`; `fixed` stands in for a
    signature update that no longer flags it."""
    def __init__(self):
        self.name = "Test.Evil"
        self.fixed = False

    def daemon_uid(self):
        return 1000

    def supports_fildes(self):
        return True

    def signature_version(self):
        return 27000

    def version_string(self):
        return "ClamAV 1.5.4/27000/Thu Nov 12 08:00:00 2026"

    def max_threads(self):
        return 4

    def scan_fd(self, fd, label=""):
        data = os.pread(fd, 1 << 20, 0)
        if b"EVIL" in data and not self.fixed:
            return ScanOutcome(ScanStatus.INFECTED, f"{label}: {self.name} FOUND", self.name)
        return ScanOutcome(ScanStatus.CLEAN, f"{label}: OK")


def quiet(fn, *args, **kwargs):
    """Run fn with its output captured. Returns (result, output), with line
    breaks folded into spaces: the console wraps long lines."""
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        result = fn(*args, **kwargs)
    return result, " ".join(buf.getvalue().split())


def set_record(engine, path, **fields):
    with Session(engine) as session:
        record = session.query(FileRecord).filter(FileRecord.filepath == str(path)).one()
        for key, value in fields.items():
            setattr(record, key, value)
        session.commit()


with tempfile.TemporaryDirectory() as d:
    tree = Path(d, "tree")
    tree.mkdir()
    content = b"MZ harmless game plugin, EVIL-looking bytes"
    flagged = tree / "nep-plugin.dll"
    flagged.write_bytes(content)
    (tree / "fine.txt").write_bytes(b"nothing here")
    Path(d, "data").mkdir()
    config = Config(db_url=f"sqlite:///{d}/data/system.db", log_file=Path(d, "data", "e.txt"), max_workers=2)
    clamd = FakeClamd()

    def scanner():
        s = Scanner(config, clamd=clamd)
        quiet(s.scan_tree, tree)
        return s

    s = scanner()
    reports_dir = Path(d, "data", "clamav-reports")

    # --- refusals ------------------------------------------------------------------------------
    out, text = quiet(fpreport.make_report, s, config, str(tree / "never-scanned.dll"))
    assert out is None and "no record" in text, text
    out, text = quiet(fpreport.make_report, s, config, str(tree / "fine.txt"))
    assert out is None and "Only a file ClamAV flagged" in text, text
    flagged.write_bytes(content + b" edited")
    out, text = quiet(fpreport.make_report, s, config, str(flagged))
    assert out is None and "changed since it was scanned" in text, text
    flagged.write_bytes(content)
    assert not reports_dir.exists(), "nothing written when there's nothing to report"
    print("report refusals test passed ✓")

    # --- the report: what ClamAV needs, nothing personal ---------------------------------------
    out, text = quiet(fpreport.make_report, s, config, str(flagged))
    assert out is not None and out.parent == reports_dir, text
    report = out.read_text()
    sha256 = hashlib.sha256(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()
    for needed in ("Test.Evil", sha256, md5, f"{len(content):,} bytes", "ClamAV 1.5.4/27000",
                   "clamd, whole file", "Why I believe this is a false positive"):
        assert needed in report, (needed, report)
    for personal in ("nep-plugin", str(tree), d, socket.gethostname()):
        assert personal not in report, (personal, report)
    user = getpass.getuser()
    if user != "root" and len(user) > 2:
        assert user not in report, report
    assert stat.S_IMODE(out.stat().st_mode) == 0o600, "only you can read it"
    assert [p.name for p in reports_dir.iterdir()] == [out.name], "the file itself is never copied"
    # the file to attach is named on screen, with the form and the clamsubmit line
    assert str(flagged) in text and fpreport.FORM_URL in text and "clamsubmit -p" in text, text
    assert "sends the file's whole contents to Cisco" in text, text
    print("report contents test passed ✓")

    # --- allowed files can be reported too (that's what you believe they are) ------------------
    set_record(s.engine, flagged, scan_status=ScanStatus.ALLOWED.value)
    out, _ = quiet(fpreport.make_report, s, config, str(flagged))
    assert out is not None
    set_record(s.engine, flagged, scan_status=ScanStatus.INFECTED.value)
    print("allowed files test passed ✓")

    # --- renamed by newer signatures: the current name is reported, the old one noted ---------
    clamd.name = "Test.Evil.Renamed"
    out, text = quiet(fpreport.make_report, s, config, str(flagged))
    report = out.read_text()
    assert "Signature name:   Test.Evil.Renamed" in report and "Earlier name:     Test.Evil" in report
    assert "it was Test.Evil" in text, text
    clamd.name = "Test.Evil"
    print("renamed signature test passed ✓")

    # --- already fixed: rescanned clean, nothing to report -------------------------------------
    out.unlink()
    clamd.fixed = True
    out, text = quiet(fpreport.make_report, s, config, str(flagged))
    assert out is None and "Nothing to report" in text and "already been fixed" in text, text
    assert not any(reports_dir.iterdir())
    clamd.fixed = False
    print("already fixed test passed ✓")

    # --- .UNOFFICIAL: a third-party signature, sent to its provider ----------------------------
    clamd.name = "Sanesecurity.Foxhole.Test.UNOFFICIAL"
    out, text = quiet(fpreport.make_report, s, config, str(flagged))
    assert out is None and "Not a ClamAV signature" in text and "third-party" in text, text
    clamd.name = "Test.Evil"
    print("unofficial signature test passed ✓")

    # --- sweep hits: ClamAV can't reproduce them from the whole file ---------------------------
    set_record(s.engine, flagged, scan_result="sweep: Test.Evil in bytes 0-1048576")
    out, text = quiet(fpreport.make_report, s, config, str(flagged))
    assert out is None and "The sweep found this" in text, text
    set_record(s.engine, flagged, scan_result="whatever: Test.Evil FOUND")
    print("sweep hit test passed ✓")

    # --- a personal folder: warned, still reported ---------------------------------------------
    real_home = fpreport.HOME
    fpreport.HOME = Path(d)
    try:
        personal = Path(d, "Downloads")
        personal.mkdir()
        (personal / "setup.exe").write_bytes(b"installer with EVIL in it")
        tree_was = tree
        tree = personal
        s2 = scanner()
        tree = tree_was
        out, text = quiet(fpreport.make_report, s2, config, str(personal / "setup.exe"))
        assert out is not None and "in your Downloads folder: make sure" in text, text
        out, text = quiet(fpreport.make_report, s2, config, str(flagged))
        assert "folder: make sure" not in text, "no warning outside personal folders"
    finally:
        fpreport.HOME = real_home
    print("personal folder warning test passed ✓")

    # --- hostile names are shown escaped, like everywhere else ---------------------------------
    hostile = tree / "x\x1b]0;pwned\x07.dll"
    hostile.write_bytes(b"evil name, EVIL content")
    s = scanner()
    out, text = quiet(fpreport.make_report, s, config, str(hostile))
    assert out is not None and "\x1b" not in text and "\\x1b" in text, repr(text)
    assert "pwned" not in out.read_text()
    print("hostile names test passed ✓")

print("\nAll ClamAV report tests passed ✓")
