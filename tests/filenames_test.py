"""Filenames that aren't valid UTF-8.

Linux allows any bytes in a filename except "/" and NUL, and old archives,
Wine/Proton folders and files from Windows often contain names in other
encodings (b"caf\\xe9" is Latin-1 for "café"). Python hands such a name to
Ensign with "surrogate" characters standing in for the undecodable bytes.

Before this was fixed, a file like that was scanned, then silently lost:
the database refused it, logging crashed writing the error, and a run
that had found an infection ended with "No infected files found", exit 0.

Now such names are stored as their original bytes (models.FsPath) and
tracked like any other file. And if the database refuses a result for
any reason, the result is still reported and alerted on, and the run
exits non-zero (scanner.UnsavedResult).

Run: python3 tests/filenames_test.py   (as your normal user)
"""
from __future__ import annotations

import sys as _sys_path
from pathlib import Path as _Path

# Run against THIS checkout, never an installed copy of Ensign.
ROOT = _Path(__file__).resolve().parent.parent
_sys_path.path.insert(0, str(ROOT))

import contextlib  # noqa: E402
import io  # noqa: E402
import logging  # noqa: E402
import os  # noqa: E402
import socket  # noqa: E402
import tempfile  # noqa: E402
import threading  # noqa: E402
from pathlib import Path  # noqa: E402

from sqlalchemy.orm import Session  # noqa: E402

from ensign_scan import logsetup, notify, reports  # noqa: E402
from ensign_scan.clamd import ClamdClient, ScanOutcome  # noqa: E402
from ensign_scan.config import Config  # noqa: E402
from ensign_scan.fsutil import shown  # noqa: E402
from ensign_scan.models import FileRecord, ScanStatus  # noqa: E402
from ensign_scan.scanner import Scanner  # noqa: E402

BAD = b"caf\xe9"  # Latin-1 "café": not valid UTF-8


def flat(text: str) -> str:
    return " ".join(text.split())  # undo rich's line wrapping


class FakeClamd:
    """Just enough of ClamdClient for Scanner: unprivileged, FILDES, and a
    verdict from the file's name ("evil" in it = infected)."""
    def daemon_uid(self):
        return 1000

    def supports_fildes(self):
        return True

    def signature_version(self):
        return 27455

    def max_threads(self):
        return 2

    def scan_fd(self, fd, label=""):
        if "evil" in label:
            return ScanOutcome(ScanStatus.INFECTED, f"{label}: Eicar-Test-Signature FOUND",
                               "Eicar-Test-Signature")
        return ScanOutcome(ScanStatus.CLEAN, f"{label}: OK")


# --- shown(): undecodable bytes are displayed as \xNN, so the file can be found -----
assert shown(os.fsdecode(b"/tmp/" + BAD + b".txt")) == "/tmp/caf\\xe9.txt"
assert shown("/tmp/café.txt") == "/tmp/café.txt", "valid UTF-8 is untouched"
assert shown("x\ud800y") == "x\ud800y", "a stray surrogate that isn't from a filename doesn't crash"
print("shown() test passed ✓")

with tempfile.TemporaryDirectory() as d:
    tree = Path(d, "tree")
    tree.mkdir()
    (tree / "ok.txt").write_text("fine")
    open(os.path.join(os.fsencode(tree), BAD + b".txt"), "wb").write(b"fine too")
    open(os.path.join(os.fsencode(tree), b"evil-" + BAD + b".com"), "wb").write(b"pretend malware")

    Path(d, "data").mkdir()
    config = Config(db_url=f"sqlite:///{d}/data/system.db", log_file=Path(d, "data", "error_logs.txt"),
                    max_workers=2)

    # --- the scan: such names are saved and tracked like any other ------------------
    evil = os.fsdecode(os.path.join(os.fsencode(tree), b"evil-" + BAD + b".com"))
    plain = os.fsdecode(os.path.join(os.fsencode(tree), BAD + b".txt"))
    scanner = Scanner(config, clamd=FakeClamd())
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        scanner.scan_tree(tree)
    assert scanner.unsaved == [], [u.error for u in scanner.unsaved]
    with Session(scanner.engine) as session:
        saved = {r.filepath: (r.scan_status, r.filename, r.last_scanned) for r in session.query(FileRecord)}
    assert set(saved) == {str(tree / "ok.txt"), evil, plain}, saved
    assert saved[evil][0] == "infected" and saved[plain][0] == "clean"
    assert saved[evil][1] == os.fsdecode(b"evil-" + BAD + b".com"), "the name column round-trips too"

    # stored byte-exact: as a BLOB of the original bytes, not as a lossy text
    with scanner.engine.connect() as conn:
        kinds = dict(conn.exec_driver_sql("SELECT filepath, typeof(filepath) FROM files").all())
    assert kinds[os.fsencode(evil)] == "blob" and kinds[str(tree / "ok.txt")] == "text", kinds
    print("scan test passed ✓")

    # --- tracked: unchanged next run, rescanned when it changes -----------------------
    with contextlib.redirect_stdout(io.StringIO()):
        scanner.scan_tree(tree)
    with Session(scanner.engine) as session:
        again = {r.filepath: r.last_scanned for r in session.query(FileRecord)}
    assert again[plain] == saved[plain][2], "an unchanged byte-named file isn't rescanned"
    with open(os.fsencode(plain), "ab") as fh:
        fh.write(b" changed")
    with contextlib.redirect_stdout(io.StringIO()):
        scanner.scan_tree(tree)
    with Session(scanner.engine) as session:
        assert session.query(FileRecord.last_scanned).filter(FileRecord.filepath == plain).scalar() \
            != saved[plain][2], "a changed one is"
    print("change-detection test passed ✓")

    # --- reports: listed, scoped to folders, shown findable ----------------------------
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        listed = reports.list_infected(scanner.engine)
    out = flat(buf.getvalue())
    assert [i["filepath"] for i in listed] == [evil] and "evil-caf\\xe9.com" in out, out
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        scoped = reports.list_infected(scanner.engine, paths=[str(tree)])
    assert [i["filepath"] for i in scoped] == [evil], \
        "folder scoping must reach byte-named rows (SQLite sorts BLOBs after all text)"
    with contextlib.redirect_stdout(io.StringIO()):
        outside = reports.list_infected(scanner.engine, paths=[str(tree) + "-other"])
    assert outside == [], "and must not leak them into a sibling folder's report"
    with contextlib.redirect_stdout(io.StringIO()):
        counts = reports.scan_summary(scanner.engine, paths=[str(tree)])
    assert counts.get("infected") == 1 and counts.get("total") == 3, counts
    print("report and scoping tests passed ✓")

    # --- a byte-named FOLDER: the walk, scoping and purge all reach inside it -------------
    odd_dir = os.path.join(os.fsencode(tree), b"dir-" + BAD)
    os.mkdir(odd_dir)
    inner = os.fsdecode(os.path.join(odd_dir, b"inner.txt"))
    open(os.fsencode(inner), "wb").write(b"x")
    with contextlib.redirect_stdout(io.StringIO()):
        scanner.scan_tree(tree)
        assert reports.scan_summary(scanner.engine, paths=[os.fsdecode(odd_dir)]).get("total") == 1
    os.remove(os.fsencode(inner))
    os.remove(os.fsencode(evil))
    with contextlib.redirect_stdout(io.StringIO()):
        scanner.purge_missing()
    with Session(scanner.engine) as session:
        left = {r.filepath for r in session.query(FileRecord)}
    assert evil not in left and inner not in left and plain in left, left
    print("folder and purge tests passed ✓")

    # --- if the database refuses a result anyway, it is still reported -----------------------
    # (a full disk or a damaged database). Simulated by making the write fail.
    sick = Scanner(config, clamd=FakeClamd())
    def refuse(*args, **kwargs):
        raise OSError("database or disk is full")
    sick._upsert_file = refuse
    open(os.path.join(os.fsencode(tree), b"evil-new-" + BAD + b".com"), "wb").write(b"more")
    open(os.path.join(os.fsencode(tree), b"zz-new.txt"), "wb").write(b"clean")  # sorts after evil-*
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        sick.scan_tree(tree)
    live = flat(buf.getvalue())
    assert "FOUND -- but the result couldn't be saved" in live, live
    unsaved_infected = [u for u in sick.unsaved if u.status == "infected"]
    assert len(unsaved_infected) == 1 and unsaved_infected[0].threat_name == "Eicar-Test-Signature"
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        reports.list_infected(sick.engine, paths=[str(tree) + "-none"], more_elsewhere=True)
        extra = reports.unsaved_report(sick.unsaved)
    out = flat(buf.getvalue())
    assert "No infected files found" not in out, "'none found' is not printed over an unsaved infection"
    assert "SCANNED BUT NOT SAVED" in out and "is INFECTED" in out and "disk is full" in out, out
    assert out.index("evil-new-caf") < out.index("clean: "), "infections are listed first"
    assert [e["threat"] for e in extra] == ["Eicar-Test-Signature"]
    assert reports.unsaved_report([]) == []
    print("unsaved-result tests passed ✓")

    # --- the alert counts and names it ------------------------------------------------------
    title, body, urgency = notify.build_message({"total": 1, "clean": 1, "infected": 1}, extra)
    assert urgency == "critical" and "1 infected" in title and "evil-new-caf" in body, (title, body)
    print("alert test passed ✓")

    # --- logging: the error line is written, not lost to a "Logging error" -------------------
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        log_path = logsetup.setup(config)
        logging.getLogger("ensign_scan.test").error("result not saved for %s", evil)
        logsetup.shutdown()
    assert "Logging error" not in stderr.getvalue(), stderr.getvalue()
    written = Path(log_path).read_text()
    assert "evil-caf" in written and "\\udce9" in written, written
    print("logging test passed ✓")

# --- the clamd connection: such a path goes out as its bytes, and comes back -------------
with tempfile.TemporaryDirectory() as d:
    sock_path = os.path.join(d, "fake.ctl")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(1)
    received: list[bytes] = []

    def answer():
        conn, _ = server.accept()
        with conn:
            data = b""
            while not data.endswith(b"\n"):
                data += conn.recv(4096)
            received.append(data)
            path = data[len(b"nSCAN "):-1]
            conn.sendall(path + b": OK\n")

    t = threading.Thread(target=answer)
    t.start()
    bad_path = os.fsdecode(b"/tmp/" + BAD + b".txt")
    reply = ClamdClient(sock_path, timeout=10)._command(f"SCAN {bad_path}")
    t.join(5)
    server.close()
    assert received == [b"nSCAN /tmp/" + BAD + b".txt\n"], "the original bytes are sent"
    assert reply == f"{bad_path}: OK", "and the reply decodes back to the same name"
print("clamd connection test passed ✓")

# --- package-manager lookups decode such names instead of crashing ------------------------
from ensign_scan.pkgdb import dpkg as dpkg_mod, pacman as pacman_mod, rpm as rpm_mod  # noqa: E402

calls = []


def recording_run(argv, **kwargs):
    calls.append(kwargs)
    return type("R", (), {"stdout": "", "stderr": "", "returncode": 1})()


real_run = dpkg_mod.subprocess.run
real_available = (pacman_mod.available, dpkg_mod.available, rpm_mod.available)
pacman_mod.available = dpkg_mod.available = rpm_mod.available = lambda: True
dpkg_mod.subprocess.run = recording_run  # one subprocess module, shared by all three
try:
    for mod in (pacman_mod, dpkg_mod, rpm_mod):
        mod.owner(bad_path)
        mod.verify_all()
finally:
    dpkg_mod.subprocess.run = real_run
    pacman_mod.available, dpkg_mod.available, rpm_mod.available = real_available
assert calls and all(kw.get("errors") == "surrogateescape" for kw in calls), \
    [kw.get("errors") for kw in calls]
print("package-manager decoding test passed ✓")

print("\nAll filename tests passed ✓")
