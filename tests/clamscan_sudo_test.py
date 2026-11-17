"""clamscan under sudo: files the clamav user can't read still get scanned.

Under sudo, Ensign runs clamscan as the clamav user. clamscan reopens each
file by path, so a file clamav may not read (mode 600, owned by someone
else) comes back "Access denied". Ensign then gives that file to clamscan
on stdin, still as clamav. Checked here, with the real clamscan:

  * a mode-600 file with a test signature in it is found infected;
  * a mode-600 clean file comes back clean, not an error;
  * a readable file in the same batch is scanned normally;
  * every file is reported to on_result exactly once, with its final
    answer (never the interim "Access denied");
  * clamscan's temporary copy is readable by clamav only.

Needs root, a clamav user and clamscan; skipped (with a note) otherwise.
The signature database is a one-line test signature made here.

    sudo python3 tests/clamscan_sudo_test.py
"""
from __future__ import annotations

import sys as _sys_path
from pathlib import Path as _Path

# Run against THIS checkout, never an installed copy of Ensign.
ROOT = _Path(__file__).resolve().parent.parent
_sys_path.path.insert(0, str(ROOT))

import os  # noqa: E402
import pwd  # noqa: E402
import shutil  # noqa: E402
import stat  # noqa: E402
import tempfile  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

from ensign_scan import clamd  # noqa: E402
from ensign_scan.clamd import ClamdLimits  # noqa: E402
from ensign_scan.models import ScanStatus  # noqa: E402

if os.geteuid() != 0 or not shutil.which("clamscan"):
    print("clamscan under sudo test skipped: needs root and clamscan")
    raise SystemExit(0)
try:
    clamav = pwd.getpwnam("clamav")
except KeyError:
    print("clamscan under sudo test skipped: no clamav user")
    raise SystemExit(0) from None

# Built from two halves so this file itself never holds the whole pattern.
MARK = b"ENSIGN-SUDO" + b"-TEST-MARKER"

with tempfile.TemporaryDirectory() as d:
    work = Path(d)
    work.chmod(0o755)
    db = work / "db"
    db.mkdir()
    (db / "test.ndb").write_text(f"Ensign.Test.Sudo:0:*:{MARK.hex()}\n")
    for p in (db, db / "test.ndb"):
        p.chmod(0o755 if p.is_dir() else 0o644)

    # Owned by "nobody" (neither root nor clamav), mode 600: clamav can't read them.
    nobody = pwd.getpwnam("nobody")
    files = {
        "private-infected.bin": (b"x" * 5000 + MARK + b"x" * 5000, 0o600),
        "private-clean.bin": (b"y" * 10000, 0o600),
        "readable-infected.bin": (b"z" * 100 + MARK, 0o644),
    }
    fds = {}
    for name, (data, mode) in files.items():
        path = work / name
        path.write_bytes(data)
        os.chown(path, nobody.pw_uid, nobody.pw_gid)
        path.chmod(mode)
        fds[name] = os.open(path, os.O_RDONLY)

    # Watch clamscan's temporary copies of stdin while it runs.
    tmp = work / "tmp"
    tmp.mkdir()
    tmp.chmod(0o1777)
    seen_modes: set[int] = set()
    stop = threading.Event()

    def watch() -> None:
        while not stop.is_set():
            for entry in tmp.iterdir():
                try:
                    seen_modes.add(stat.S_IMODE(entry.lstat().st_mode))
                except OSError:
                    pass
            time.sleep(0.005)

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    saved = clamd.clamscan_temp_dir
    clamd.clamscan_temp_dir = lambda: str(tmp)
    reported: list[tuple[int, object]] = []
    try:
        limits = ClamdLimits(100, 100, str(db), False, "test")
        outcomes = clamd.scan_fds_with_clamscan(
            list(fds.values()), limits, timeout=300, run_as=(clamav.pw_uid, clamav.pw_gid),
            on_result=lambda fd, outcome: reported.append((fd, outcome)))
    finally:
        clamd.clamscan_temp_dir = saved
        stop.set()
        watcher.join(5)
        for fd in fds.values():
            os.close(fd)

    by_name = {name: outcomes[fd] for name, fd in fds.items()}
    assert by_name["private-infected.bin"].status is ScanStatus.INFECTED, by_name
    assert by_name["private-infected.bin"].threat_name == "Ensign.Test.Sudo.UNOFFICIAL", by_name
    assert by_name["private-clean.bin"].status is ScanStatus.CLEAN, by_name
    assert by_name["readable-infected.bin"].status is ScanStatus.INFECTED, by_name
    assert sorted(fd for fd, _ in reported) == sorted(fds.values()), "each file reported exactly once"
    assert not any("Access denied" in o.raw for _, o in reported), reported
    assert seen_modes, "clamscan made no temporary copy (the stdin path didn't run?)"
    assert all(mode & 0o077 == 0 for mode in seen_modes), f"temp copy readable by others: {seen_modes}"
    assert not list(tmp.iterdir()), "clamscan left a temporary copy behind"

print("clamscan under sudo test passed ✓")
