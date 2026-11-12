"""Allowed by you: false positives you tell Ensign to stop flagging.

An allowance covers one exact content (SHA-256) flagged by one exact
signature. Checked here:

  * --allow only works on a flagged file whose content still matches the
    scan, and only after you confirm;
  * identical copies are covered, a changed file or another signature is not;
  * allowed files leave the infected list and alerts, but get their own
    section, and are rescanned when the signatures update;
  * --unallow puts them back.

Runs anywhere: clamd is a stand-in that flags content containing "EVIL".

    python3 tests/allowlist_test.py
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

from ensign_scan import allowlist, reports  # noqa: E402
from ensign_scan.clamd import ScanOutcome  # noqa: E402
from ensign_scan.config import Config  # noqa: E402
from ensign_scan.models import Allowance, FileRecord, ScanStatus  # noqa: E402
from ensign_scan.scanner import Scanner  # noqa: E402


class FakeClamd:
    """Flags content containing EVIL as Test.Evil -- or, once `stricter` is
    set (a signature update), as Test.Worse."""
    def __init__(self):
        self.version = 27000
        self.stricter = False

    def daemon_uid(self):
        return 1000

    def supports_fildes(self):
        return True

    def signature_version(self):
        return self.version

    def max_threads(self):
        return 4

    def scan_fd(self, fd, label=""):
        data = os.pread(fd, 1 << 20, 0)
        if b"EVIL" in data:
            name = "Test.Worse" if self.stricter else "Test.Evil"
            return ScanOutcome(ScanStatus.INFECTED, f"{label}: {name} FOUND", name)
        return ScanOutcome(ScanStatus.CLEAN, f"{label}: OK")


def statuses(engine) -> dict[str, tuple[str, str | None]]:
    with Session(engine) as session:
        return {Path(r.filepath).name: (r.scan_status, r.threat_name) for r in session.query(FileRecord)}


def quiet(fn, *args, **kwargs):
    """Run fn with its output captured. Returns (result, output), with line
    breaks folded into spaces: the console wraps long lines."""
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        result = fn(*args, **kwargs)
    return result, " ".join(buf.getvalue().split())


yes = lambda prompt: True  # noqa: E731
no = lambda prompt: False  # noqa: E731

with tempfile.TemporaryDirectory() as d:
    tree = Path(d, "tree")
    (tree / "sub").mkdir(parents=True)
    (tree / "game-asset.dat").write_bytes(b"harmless game data EVIL-looking bytes")
    (tree / "sub" / "copy.dat").write_bytes(b"harmless game data EVIL-looking bytes")  # same content
    (tree / "other.bin").write_bytes(b"different content, also EVIL")
    (tree / "fine.txt").write_bytes(b"nothing here")
    Path(d, "data").mkdir()
    config = Config(db_url=f"sqlite:///{d}/data/system.db", log_file=Path(d, "data", "e.txt"),
                    max_workers=2, rescan_after_signature_updates=1)
    clamd = FakeClamd()

    def scan():
        s = Scanner(config, clamd=clamd)  # a fresh Scanner per run, like the CLI
        quiet(s.scan_tree, tree)
        quiet(s.rescan_infected)
        return s

    engine = scan().engine
    asset, copy, other = (str(tree / "game-asset.dat"), str(tree / "sub" / "copy.dat"),
                          str(tree / "other.bin"))
    assert statuses(engine)["game-asset.dat"][0] == "infected"

    # --- refusals: nothing is allowed without a match, a flag and a yes ------------------------
    assert not quiet(allowlist.allow, engine, asset, no)[0], "declining the prompt allows nothing"
    assert not quiet(allowlist.allow, engine, str(tree / "fine.txt"), yes)[0], "only flagged files"
    ok, out = quiet(allowlist.allow, engine, str(tree / "never-scanned.dat"), yes)
    assert not ok and "no record" in out
    with Session(engine) as session:
        assert session.query(Allowance).count() == 0
    # the file changed since it was flagged: that isn't the content ClamAV flagged
    Path(other).write_bytes(b"different content, also EVIL, edited")
    ok, out = quiet(allowlist.allow, engine, other, yes)
    assert not ok and "changed since it was scanned" in out, out
    print("allow refusals test passed ✓")

    # --- allowing: this content and this signature, wherever the content is -------------------
    ok, out = quiet(allowlist.allow, engine, asset, yes)
    assert ok and "1 identical copy" in out, out
    st = statuses(engine)
    assert st["game-asset.dat"] == ("allowed", "Test.Evil") and st["copy.dat"] == ("allowed", "Test.Evil")
    assert st["other.bin"][0] == "infected", "different content isn't covered"
    ok, out = quiet(allowlist.allow, engine, asset, yes)
    assert not ok and "already allowed" in out
    print("allow test passed ✓")

    # --- reports: out of the infected list and alerts, into their own section -------------------
    infected, _ = quiet(reports.list_infected, engine)
    assert {Path(i["filepath"]).name for i in infected} == {"other.bin"}, infected
    summary, text = quiet(reports.scan_summary, engine)
    assert summary["allowed"] == 2 and summary["infected"] == 1 and "Allowed by you: 2" in text
    count, text = quiet(allowlist.allowed_report, engine)
    assert count == 2 and "ALLOWED BY YOU (2 files)" in text and "Test.Evil" in text, text
    count, _ = quiet(allowlist.allowed_report, engine, paths=[str(tree / "sub")])
    assert count == 1, "scoped like the other reports"
    count, text = quiet(allowlist.list_allowed, engine)
    assert count == 1 and "game-asset.dat" in text and "copy.dat" in text, text
    print("allowed reports test passed ✓")

    # --- later runs: allowed stays allowed; not rechecked every run like infections -------------
    scan()
    assert statuses(engine)["game-asset.dat"][0] == "allowed"
    # a signature update: allowed files are rescanned -- same signature, still allowed
    clamd.version += 1
    scan()
    assert statuses(engine)["copy.dat"] == ("allowed", "Test.Evil")
    print("allowed across runs test passed ✓")

    # --- a changed file, or a different signature, is flagged again ----------------------------
    Path(copy).write_bytes(b"harmless game data EVIL-looking bytes, now different")
    scan()
    assert statuses(engine)["copy.dat"][0] == "infected", "changed content: not covered"
    clamd.version += 1
    clamd.stricter = True  # new signatures flag it as Test.Worse
    scan()
    assert statuses(engine)["game-asset.dat"] == ("infected", "Test.Worse"), \
        "another signature: not covered"
    clamd.stricter = False
    clamd.version += 1
    scan()
    assert statuses(engine)["game-asset.dat"] == ("allowed", "Test.Evil"), \
        "back to the allowed signature: allowed again"
    print("not covered when it changes test passed ✓")

    # --- unallow: flagged as infected again, allowance gone ------------------------------------
    ok, out = quiet(allowlist.unallow, engine, asset)
    assert ok and "flagged as infected again" in out, out
    assert statuses(engine)["game-asset.dat"] == ("infected", "Test.Evil")
    with Session(engine) as session:
        assert session.query(Allowance).count() == 0
    assert not quiet(allowlist.unallow, engine, asset)[0], "nothing left to undo"
    scan()
    assert statuses(engine)["game-asset.dat"][0] == "infected", "and it stays infected"
    print("unallow test passed ✓")

    # --- hostile names are shown escaped, like everywhere else ---------------------------------
    hostile = tree / "x\x1b]0;pwned\x07.dat"
    hostile.write_bytes(b"evil name, EVIL content")
    scan()
    ok, out = quiet(allowlist.allow, engine, str(hostile), yes)
    assert ok and "\x1b" not in out, repr(out)
    _, out = quiet(allowlist.allowed_report, engine)
    _, listed = quiet(allowlist.list_allowed, engine)
    assert "\x1b" not in out and "\x1b" not in listed and "\\x1b" in out, repr(out)
    print("hostile names test passed ✓")

print("\nAll allowlist tests passed ✓")
