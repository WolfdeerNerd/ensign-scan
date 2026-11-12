"""Files larger than clamd scans.

clamd skips a file past its MaxFileSize or MaxScanSize and still answers
"OK" for it. Ensign 0.4.0 and older stored that as clean, so a large enough
file -- malware padded with junk, a well-known trick (MITRE ATT&CK T1027.001)
-- was never scanned and never reported. Now:

  * files from clamd's limit up are not sent to clamd; they are hashed, then
    scanned by clamscan with the limits off, in batches, through the
    descriptors Ensign opened (/proc/self/fd/N), never reopened by name;
  * a file clamd flags as over a limit (AlertExceedsMax) goes the same way,
    and is not counted as infected;
  * a file ClamAV can't scan at all (over ~2 GiB) is "incomplete": tracked,
    reported, never clean;
  * large files an older Ensign called clean are rescanned once.

Also here: clamd's reply is read for its verdict only, never for the
filename in it ("x: PUA.Harmless FOUND y.exe" can't rename a detection).

Most of this runs anywhere, with a stand-in clamd and clamscan. With
ENSIGN_TEST_CLAMD_SOCKET set (CI), the end runs real ClamAV too:

    ENSIGN_TEST_CLAMD_SOCKET=/run/clamav/clamd.ctl python3 tests/largefiles_test.py

Run as your normal user.
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
import shutil  # noqa: E402
import sqlite3  # noqa: E402
import stat  # noqa: E402
import tempfile  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

from sqlalchemy.orm import Session  # noqa: E402

from ensign_scan import reports, scanner as scanner_mod  # noqa: E402
from ensign_scan.clamd import (  # noqa: E402
    DEFAULT_LIMITS,
    ClamdClient,
    ClamdLimits,
    ScanOutcome,
    _outcome,
    parse_clamd_config,
    scan_fds_with_clamscan,
)
from ensign_scan.config import Config  # noqa: E402
from ensign_scan.models import FileRecord, ScanStatus  # noqa: E402
from ensign_scan.scanner import Scanner  # noqa: E402

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR" + b"-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def fds_open_under(folder: Path) -> list[str]:
    """Descriptors this process holds on files under `folder`. (Not a plain
    count: SQLite's connection pool opens and keeps its own.)"""
    held = []
    for fd in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            continue
        if target.startswith(f"{folder}/"):
            held.append(target)
    return held


# --- clamd.conf: the limits are read the way clamd reads them ------------------------------
conf = parse_clamd_config(
    "# Example\n"
    "MaxFileSize 25M\n"
    "MaxScanSize   1G   # trailing comment\n"
    "MaxFileSize 300M\n"             # the last one wins, as in clamd
    "PCREMaxFileSize 2000M\n"
    "DatabaseDirectory /var/lib/clamav\n"
    "AlertExceedsMax yes\n",
    "test",
)
assert conf.max_file_size == 300 * 2**20 and conf.max_scan_size == 2**30, conf
assert conf.database_dir == "/var/lib/clamav" and conf.alert_exceeds_max
assert conf.scan_limit == 300 * 2**20, "the smaller of the two limits"
assert parse_clamd_config("MaxFileSize 512\nMaxScanSize 4k", "t").scan_limit == 512, "bytes and K"
assert parse_clamd_config("MaxFileSize 2000M\nMaxScanSize 4000M", "t").scan_limit == 100 * 2**20, \
    "PCREMaxFileSize (default 100M) counts too: regex signatures skip files past it"
unlimited = parse_clamd_config("MaxFileSize 0\nMaxScanSize 0\nPCREMaxFileSize 0", "t")
assert unlimited.scan_limit == 2000 * 2**20, "0 = no setting, but ClamAV's own ceiling still applies"
assert parse_clamd_config("", "t").scan_limit == 100 * 2**20, "missing settings: ClamAV's defaults"
assert parse_clamd_config("MaxFileSize lots", "t").max_file_size == 100 * 2**20, "unparsable: the default"
print("clamd.conf limits test passed ✓")

# --- clamd's reply: the verdict is read from clamd's words, not from the filename --------------
spoof = _outcome("/h/x: PUA.Harmless FOUND y.exe: Win.Trojan.Agent-1 FOUND", "Win.Trojan.Agent-1 FOUND")
assert spoof.status == ScanStatus.INFECTED and spoof.threat_name == "Win.Trojan.Agent-1", spoof
assert _outcome("/h/FOUND.txt: Access denied. ERROR", "Access denied. ERROR").status == ScanStatus.ERROR
assert _outcome("/h/a: Eicar FOUND.txt: OK", "OK").status == ScanStatus.CLEAN
print("clamd reply parsing test passed ✓")

# --- clamscan's output, through a stand-in clamscan --------------------------------------------
# It prints what real clamscan prints, for whichever descriptors it is given.
with tempfile.TemporaryDirectory() as d:
    fake = Path(d, "clamscan")
    fake.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$@" > "$(dirname "$0")/argv"\n'
        'for a in "$@"; do\n'
        '  case "$a" in /proc/self/fd/*)\n'
        '    n=${a#/proc/self/fd/}\n'
        '    [ -e "$a" ] || { echo "$a: No such file or directory ERROR"; continue; }\n'
        '    case "$(head -c 4 "$a")" in\n'
        '      EVIL) echo "$a: Test.Evil FOUND" ;;\n'
        '      HUGE) echo "$a: Heuristics.Limits.Exceeded.MaxFileSize FOUND"; '
        'echo "$a: Virus(es) detected ERROR" ;;\n'
        '      GONE) ;;\n'
        '      *) echo "$a: OK" ;;\n'
        "    esac ;;\n"
        "  esac\n"
        "done\n"
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    files = {}
    for name in ("EVIL", "HUGE", "GONE", "fine"):
        p = Path(d, f"{name}.bin")
        p.write_bytes(name.encode() + b" data")
        files[name] = os.open(p, os.O_RDONLY)
    real_path = os.environ["PATH"]
    os.environ["PATH"] = f"{d}:{real_path}"
    try:
        got = scan_fds_with_clamscan(list(files.values()), DEFAULT_LIMITS, timeout=30)
    finally:
        os.environ["PATH"] = real_path
        for fd in files.values():
            os.close(fd)
    by_name = {name: got[fd] for name, fd in files.items()}
    argv = Path(d, "argv").read_text().splitlines()
    assert "--tempdir=/var/tmp" in argv, f"archives unpack on disk, not in a RAM-backed /tmp: {argv}"
    assert "--pcre-max-filesize=0" in argv and "--max-filesize=0" in argv, argv
    assert by_name["EVIL"].status == ScanStatus.INFECTED and by_name["EVIL"].threat_name == "Test.Evil"
    assert by_name["HUGE"].status == ScanStatus.INCOMPLETE, "a limits alert is 'not scanned', not infected"
    assert by_name["HUGE"].threat_name == "Heuristics.Limits.Exceeded.MaxFileSize"
    assert by_name["GONE"].status == ScanStatus.ERROR, "no answer is an error, never clean"
    assert by_name["fine"].status == ScanStatus.CLEAN and by_name["fine"].raw == "clamscan: OK"
print("clamscan output parsing test passed ✓")

# --- results are read as clamscan reports them, not when the run ends -------------------------
def stand_in_clamscan(d: Path, body: str) -> None:
    script = Path(d, "clamscan")
    script.write_text("#!/bin/sh\n" + body)
    script.chmod(0o755)


with tempfile.TemporaryDirectory() as d:
    # reports each file, then pauses 0.3 s: like clamscan working through big files
    stand_in_clamscan(d, 'for a in "$@"; do case "$a" in /proc/self/fd/*) '
                         'echo "$a: OK"; sleep 0.3 ;; esac; done\n')
    fds = []
    for i in range(4):
        p = Path(d, f"f{i}.bin")
        p.write_bytes(b"x")
        fds.append(os.open(p, os.O_RDONLY))
    seen: list[tuple[int, float]] = []
    real_path = os.environ["PATH"]
    os.environ["PATH"] = f"{d}:{real_path}"
    try:
        t0 = time.monotonic()
        got = scan_fds_with_clamscan(fds, DEFAULT_LIMITS, timeout=30,
                                     on_result=lambda fd, o: seen.append((fd, time.monotonic() - t0)))
        total = time.monotonic() - t0

        # a run that hangs after its first file: that one is kept, the rest time out.
        # (exec: one process, like real clamscan, so killing it closes its output.)
        stand_in_clamscan(d, 'for a in "$@"; do case "$a" in /proc/self/fd/*) '
                             'echo "$a: OK"; exec sleep 30 ;; esac; done\n')
        partial: list[int] = []
        t1 = time.monotonic()
        hung = scan_fds_with_clamscan(fds, DEFAULT_LIMITS, timeout=1,
                                      on_result=lambda fd, o: partial.append(fd))
        hung_took = time.monotonic() - t1
    finally:
        os.environ["PATH"] = real_path
        for fd in fds:
            os.close(fd)
assert [fd for fd, _ in seen] == fds, f"each file reported once, in order: {seen}"
assert seen[0][1] < total - 0.5, f"the first result arrives while clamscan is still running: {seen}"
# and not one file late: "OK" is final, so it's passed on before clamscan's 0.3 s
# pause and the next file's line
assert seen[0][1] < 0.25, f"an OK is reported at once, not when the next file starts: {seen}"
assert all(o.status == ScanStatus.CLEAN for o in got.values())
assert hung_took < 10, f"the time limit stops a hung clamscan: took {hung_took:.1f}s"
assert hung[fds[0]].status == ScanStatus.CLEAN, "a file reported before the hang keeps its result"
assert all(hung[fd].status == ScanStatus.ERROR and "ran out of time" in hung[fd].raw for fd in fds[1:]), hung
assert sorted(partial) == sorted(fds), "every file is still reported exactly once"
print("streamed clamscan results test passed ✓")


# --- the scanner: large files go to clamscan, in batches, and are never "clean" by default -------
class FakeClamd:
    """clamd with a 1 KiB limit. Like the real one, it says OK for anything
    it is sent -- so if a large file reached it, the test would see "clean"."""
    def __init__(self):
        self.sent: list[str] = []

    def daemon_uid(self):
        return 1000

    def supports_fildes(self):
        return True

    def signature_version(self):
        return 27455

    def max_threads(self):
        return 2

    def limits(self):
        return ClamdLimits(1024, 0, None, False, "test")

    def scan_fd(self, fd, label=""):
        self.sent.append(os.path.basename(label))
        if "archive" in label:  # AlertExceedsMax: an archive that unpacks past MaxScanSize
            return ScanOutcome(ScanStatus.INFECTED, f"{label}: Heuristics.Limits.Exceeded.MaxScanSize FOUND",
                               "Heuristics.Limits.Exceeded.MaxScanSize")
        return ScanOutcome(ScanStatus.CLEAN, f"{label}: OK")


batches: list[list[int]] = []


def fake_clamscan(fds, limits, timeout, run_as=None, on_result=None):
    """Reads each file through the descriptor it was given -- the one Ensign
    opened -- the way the real clamscan does through /proc/self/fd/N."""
    batches.append(list(fds))
    out = {}
    for fd in fds:
        os.fstat(fd)  # still open: raises if Ensign closed it too early
        data = os.pread(fd, 1 << 20, 0)
        if b"EVIL" in data:
            out[fd] = ScanOutcome(ScanStatus.INFECTED, "clamscan: Test.Evil FOUND", "Test.Evil")
        elif len(data) > 10_000:
            out[fd] = ScanOutcome(ScanStatus.INCOMPLETE, "clamscan: Heuristics.Limits.Exceeded.MaxFileSize FOUND",
                                  "Heuristics.Limits.Exceeded.MaxFileSize")
        else:
            out[fd] = ScanOutcome(ScanStatus.CLEAN, "clamscan: OK")
    return out


real = (scanner_mod.scan_fds_with_clamscan, scanner_mod.clamscan_cli_available,
        scanner_mod.clamscan_user, scanner_mod._CLAMSCAN_BATCH)
scanner_mod.scan_fds_with_clamscan = fake_clamscan
scanner_mod.clamscan_cli_available = lambda: True
scanner_mod.clamscan_user = lambda: None
scanner_mod._CLAMSCAN_BATCH = 2
try:
    with tempfile.TemporaryDirectory() as d:
        tree = Path(d, "tree")
        tree.mkdir()
        (tree / "small.txt").write_bytes(b"small and clean")
        (tree / "big-evil.bin").write_bytes(b"\0" * 2000 + b"EVIL" + b"\0" * 2000)  # padded past the limit
        (tree / "big-clean.bin").write_bytes(b"A" * 4096)
        (tree / "huge.img").write_bytes(b"B" * 20_000)
        (tree / "archive.zip").write_bytes(b"PK small, but unpacks past the limit")
        Path(d, "data").mkdir()
        config = Config(db_url=f"sqlite:///{d}/data/system.db", log_file=Path(d, "data", "e.txt"),
                        max_workers=2)
        clamd = FakeClamd()
        scanner = Scanner(config, clamd=clamd)
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            scanner.scan_tree(tree)
        out = buf.getvalue()

        with Session(scanner.engine) as session:
            rows = {Path(r.filepath).name: (r.scan_status, r.scan_result, r.threat_name)
                    for r in session.query(FileRecord)}
        assert set(clamd.sent) == {"small.txt", "archive.zip"}, \
            f"files past clamd's limit must not be sent to it: {clamd.sent}"
        assert rows["small.txt"][0] == "clean"
        assert rows["big-evil.bin"][:2] == ("infected", "clamscan: Test.Evil FOUND"), rows["big-evil.bin"]
        assert rows["big-clean.bin"][:2] == ("clean", "clamscan: OK"), rows["big-clean.bin"]
        assert rows["huge.img"][0] == "incomplete", rows["huge.img"]
        assert rows["archive.zip"][0] == "clean" and rows["archive.zip"][1].startswith("clamscan:"), \
            f"clamd's limits alert is rescanned by clamscan, not counted as infected: {rows['archive.zip']}"
        assert sum(len(b) for b in batches) == 4 and all(len(b) <= 2 for b in batches), batches
        assert fds_open_under(tree) == [], f"queued descriptors left open: {fds_open_under(tree)}"
        assert "queued for clamscan" in out and "Scanning 2 large file(s)" in out, out
        print("large-file routing test passed ✓")

        # --- reported as not fully scanned, with the disclaimer --------------------------------
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            summary = reports.scan_summary(scanner.engine)
            reports.incomplete_report(scanner.engine)
        text = " ".join(buf.getvalue().split())
        assert summary["incomplete"] == 1 and "Not fully scanned: 1" in text, text
        assert "NOT FULLY SCANNED (1 files)" in text and "huge.img" in text, text
        assert "does not call them clean" in text and "no ClamAV tool can scan" in text, text
        print("not-fully-scanned report test passed ✓")

        # --- unchanged next run: nothing rehashed, nothing rescanned ---------------------------
        batches.clear()
        with contextlib.redirect_stdout(io.StringIO()):
            stats = scanner.scan_tree(tree)
        assert stats.unchanged == 5 and not batches, (stats, batches)
        print("unchanged large files test passed ✓")

        # --- upgrading from 0.4.0: a large file clamd "passed" is rescanned once --------------------
        db = sqlite3.connect(f"{d}/data/system.db")
        db.execute("UPDATE files SET scan_result = ? WHERE filename = 'big-clean.bin'",
                   (f"{tree}/big-clean.bin: OK",))
        db.commit()
        db.close()
        with contextlib.redirect_stdout(io.StringIO()):
            stats = scanner.scan_tree(tree)
        assert stats.big_recheck == 1 and sum(len(b) for b in batches) == 1, (stats, batches)
        with contextlib.redirect_stdout(io.StringIO()):
            stats = scanner.scan_tree(tree)
        assert stats.big_recheck == 0, "rescanned once, not every run"
        print("0.4.0 upgrade recheck test passed ✓")

        # --- no clamscan: not fully scanned (never clean), retried once clamscan is there -----------
        (tree / "big-new.bin").write_bytes(b"C" * 4096)
        scanner_mod.clamscan_cli_available = lambda: False
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            scanner.scan_tree(tree)
        with Session(scanner.engine) as session:
            row = session.query(FileRecord).filter(FileRecord.filename == "big-new.bin").one()
            assert row.scan_status == "incomplete" and row.scan_result.startswith("not scanned:"), \
                (row.scan_status, row.scan_result)
        assert "isn't installed" in buf.getvalue()
        with contextlib.redirect_stdout(io.StringIO()):
            stats = scanner.scan_tree(tree)
        assert stats.big_recheck == 0, "not retried while clamscan is still missing"
        scanner_mod.clamscan_cli_available = lambda: True
        with contextlib.redirect_stdout(io.StringIO()):
            stats = scanner.scan_tree(tree)
        with Session(scanner.engine) as session:
            row = session.query(FileRecord).filter(FileRecord.filename == "big-new.bin").one()
            assert stats.big_recheck == 1 and row.scan_status == "clean", (stats, row.scan_status)
        print("missing-clamscan test passed ✓")

        # --- the progress line: a queued file counts when clamscan finishes it, and the
        #     line only closes after the last clamscan -- not when the files are queued.
        events: list[tuple[str, float, str | None]] = []

        class RecordingProgress:
            def __init__(self, label, total, workers, **kw):
                self.total = total

            def __enter__(self):
                return self

            def advance(self, status):
                events.append(("advance", time.monotonic(), status))

            def __exit__(self, *exc):
                events.append(("closed", time.monotonic(), None))

        batch_ends: list[float] = []

        def slow_clamscan(fds, limits, timeout, run_as=None, on_result=None):
            time.sleep(0.4)
            out = fake_clamscan(fds, limits, timeout, run_as)
            batch_ends.append(time.monotonic())
            return out

        real_progress = scanner_mod.RunProgress
        scanner_mod.RunProgress = RecordingProgress
        scanner_mod.scan_fds_with_clamscan = slow_clamscan
        try:
            tree2 = Path(d, "tree2")
            tree2.mkdir()
            for i in range(3):
                (tree2 / f"small{i}.txt").write_bytes(b"small")
                (tree2 / f"big{i}.bin").write_bytes(b"B" * 4096)
            with contextlib.redirect_stdout(io.StringIO()):
                scanner.scan_tree(tree2)
        finally:
            scanner_mod.RunProgress = real_progress
            scanner_mod.scan_fds_with_clamscan = fake_clamscan
        advances = [e for e in events if e[0] == "advance"]
        closed = [e[1] for e in events if e[0] == "closed"]
        assert len(advances) == 6, f"every file counted exactly once: {advances}"
        assert "queued" not in {e[2] for e in advances}, "queued is not finished"
        assert closed and batch_ends and closed[-1] >= max(batch_ends), \
            "the progress line closes only after the last clamscan"
        assert sum(1 for e in advances if e[1] >= min(batch_ends)) >= 3, \
            "the big files are counted as their clamscan results come in"
        print("progress waits for clamscan test passed ✓")

        # --- with a clamscan that reports as it goes, each big file is printed and counted
        #     straight away, not when its whole batch ends
        def streaming_clamscan(fds, limits, timeout, run_as=None, on_result=None):
            out = {}
            for fd in fds:
                time.sleep(0.3)
                out[fd] = ScanOutcome(ScanStatus.CLEAN, "clamscan: OK")
                on_result(fd, out[fd])
            batch_ends.append(time.monotonic())
            return out

        events.clear()
        batch_ends.clear()
        scanner_mod.RunProgress = RecordingProgress
        scanner_mod.scan_fds_with_clamscan = streaming_clamscan
        real_batch = scanner_mod._CLAMSCAN_BATCH
        scanner_mod._CLAMSCAN_BATCH = 3
        try:
            tree3 = Path(d, "tree3")
            tree3.mkdir()
            for i in range(3):
                (tree3 / f"big{i}.bin").write_bytes(b"C" * 4096)
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                scanner.scan_tree(tree3)
        finally:
            scanner_mod.RunProgress = real_progress
            scanner_mod.scan_fds_with_clamscan = fake_clamscan
            scanner_mod._CLAMSCAN_BATCH = real_batch
        times = [e[1] for e in events if e[0] == "advance"]
        assert len(times) == 3, events
        assert times[0] < batch_ends[-1] - 0.4, \
            f"the first big file is counted before its batch ends: {times} vs {batch_ends}"
        printed = buf.getvalue()
        assert all(f"big{i}.bin" in printed for i in range(3)), printed
        print("big files reported one by one test passed ✓")
finally:
    (scanner_mod.scan_fds_with_clamscan, scanner_mod.clamscan_cli_available,
     scanner_mod.clamscan_user, scanner_mod._CLAMSCAN_BATCH) = real

# --- clamscans side by side, as many as free memory allows ------------------------------------
GiB = 2**30


def run_pool(limit: int, per_copy: int, memory, batches: int = 6, work: float = 0.3,
             fail: bool = False, percent: int = 25, cpu_allows=None):
    """Run `batches` fake batches through a pool with free memory reported as
    `memory` (a (MemAvailable, MemTotal) pair, or None). Returns the pool and
    the most batches seen waiting or running at any submit."""
    real_memory = scanner_mod.memory_available
    scanner_mod.memory_available = lambda: memory

    def run_batch(batch, running):
        time.sleep(work)
        if fail:
            raise RuntimeError("clamscan exploded")

    pool = scanner_mod._ClamscanPool(limit, per_copy, run_batch, percent, cpu_allows)
    most_pending = 0
    try:
        for _ in range(batches):
            pool.submit([])
            most_pending = max(most_pending, pool._pending)
        pool.wait()
    finally:
        scanner_mod.memory_available = real_memory
    return pool, most_pending


pool, _ = run_pool(3, 1 * GiB, (20 * GiB, 32 * GiB))
assert pool.peak == 3, f"plenty of memory: up to the limit at once, got {pool.peak}"
pool, _ = run_pool(3, 1 * GiB, (int(2.5 * GiB), 8 * GiB))
assert pool.peak == 1, "2.5 GiB free minus the 2 GiB reserve can't fit another 1 GiB copy: one at a time"
pool, _ = run_pool(3, 1 * GiB, None)
assert pool.peak == 1, "free memory unknown: one at a time"
# A clamscan still loading its signatures hasn't used its memory yet, so
# free memory doesn't show it: each counts as using its share already.
# 5 GiB free, 2 GiB reserve, 1 GiB each: the 1st always starts, then 2nd
# (5-1-2 = 2 left) and 3rd (5-2-2 = 1 left), but not a 4th (5-3-2 = 0).
pool, _ = run_pool(4, 1 * GiB, (5 * GiB, 16 * GiB))
assert pool.peak == 3, f"starting clamscans count against free memory, got {pool.peak}"
print("clamscan memory gating test passed ✓")

# The fixed budget: however much is free, all clamscans together stay within
# clamscan_memory_percent of total RAM. 32 GiB machine, nearly all free,
# 1.5 GiB each: 25% = 8 GiB = 5 copies (a 6th would be 9 GiB).
copy = 3 * GiB // 2
pool, _ = run_pool(8, copy, (30 * GiB, 32 * GiB), batches=10)
assert pool.peak == 5, f"25% of 32 GiB fits 5 copies of 1.5 GiB, got {pool.peak}"
pool, _ = run_pool(8, copy, (30 * GiB, 32 * GiB), batches=10, percent=50)
assert pool.peak == 8, f"50% (16 GiB) fits 10, so the count limit of 8 decides, got {pool.peak}"
pool, _ = run_pool(4, 3 * GiB, (7 * GiB, 8 * GiB))
assert pool.peak == 1, "one copy is bigger than the whole 2 GiB budget: still one runs, never more"
with contextlib.redirect_stdout(io.StringIO()) as buf:
    assert Config._from_dict({"clamscan_memory_percent": 95}, "t").clamscan_memory_percent == 75
    assert Config._from_dict({"clamscan_memory_percent": 1}, "t").clamscan_memory_percent == 5
assert "outside 5-75" in buf.getvalue(), buf.getvalue()
assert Config._from_dict({"clamscan_memory_percent": 40}, "t").clamscan_memory_percent == 40
print("clamscan memory budget test passed ✓")

# The CPU budget is shared: a clamscan starts only if it, those running and
# the scan workers busy right now fit within cpu_share. With 6 workers busy
# and a budget of 8, at most 2 at once; with no workers busy, all 8.
busy = {"workers": 6}
pool, _ = run_pool(8, GiB, (60 * GiB, 64 * GiB), batches=10, work=0.2,
                   cpu_allows=lambda running: running + busy["workers"] + 1 <= 8)
assert pool.peak == 2, f"6 busy workers leave room for 2 in a budget of 8, got {pool.peak}"
busy["workers"] = 0
pool, _ = run_pool(8, GiB, (60 * GiB, 64 * GiB), batches=10, work=0.2,
                   cpu_allows=lambda running: running + busy["workers"] + 1 <= 8)
assert pool.peak == 8, pool.peak
busy["workers"] = 8
pool, _ = run_pool(8, GiB, (60 * GiB, 64 * GiB), batches=4, work=0.05,
                   cpu_allows=lambda running: running + busy["workers"] + 1 <= 8)
assert pool.peak == 1, "budget full of workers: still one clamscan, so large files get scanned"
with contextlib.redirect_stdout(io.StringIO()) as buf:
    assert Config._from_dict({"cpu_share": 150}, "t").cpu_share == 100
    assert Config._from_dict({"cpu_share": 0}, "t").cpu_share == 10
assert "outside 10-100" in buf.getvalue()
print("CPU budget test passed ✓")

# The workers never wait for clamscan itself -- only when batches pile up:
# at most limit + 1 waiting or running, so queued open files stay bounded.
pool, most_pending = run_pool(1, 1 * GiB, None, batches=6, work=0.2)
assert most_pending <= 2, f"batches waiting or running must stay at limit + 1, saw {most_pending}"
pool, most_pending = run_pool(3, 1 * GiB, (20 * GiB, 32 * GiB), batches=10, work=0.2)
assert most_pending <= 4, most_pending
print("clamscan queue bound test passed ✓")

# A batch that fails doesn't stop the others or hang the wait.
with contextlib.redirect_stderr(io.StringIO()):  # the failure is logged; expected here
    pool, _ = run_pool(2, 1 * GiB, (20 * GiB, 32 * GiB), batches=4, work=0.05, fail=True)
assert pool._pending == 0 and not pool._started
print("failing clamscan batch test passed ✓")

# Descriptors are closed exactly once. If recording a result fails, a second
# close would hit whatever the kernel handed that number to next -- here a
# stand-in for the database file -- so it must still be open afterwards.
with tempfile.TemporaryDirectory() as d:
    held = {}

    class Recorder:
        _advance = None  # no progress line here

        def _clamscan_outcomes(self, batch, total, on_result=None):
            return {i.fd: ScanOutcome(ScanStatus.CLEAN, "clamscan: OK") for i in batch}

        def _finish(self, path, st, digest, outcome):
            held.setdefault("db", os.open(Path(d, "database.db"), os.O_RDWR | os.O_CREAT))
            held.setdefault("recorded", []).append(path.name)
            if path.name == "a.bin":
                raise RuntimeError("unexpected failure while recording")

    items = []
    for name in ("a.bin", "b.bin"):
        p = Path(d, name)
        p.write_bytes(b"x")
        items.append(scanner_mod._Oversized(p, p.stat(), os.open(p, os.O_RDONLY), "digest"))
    rec = Recorder()
    pool = scanner_mod._ClamscanPool(1, GiB, lambda b, r: Scanner._clamscan_batch(rec, b, r))
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        pool.submit(items)
        pool.wait()
    os.fstat(held["db"])  # raises if the reused descriptor number was closed again
    os.close(held["db"])
    assert held["recorded"] == ["a.bin", "b.bin"], "one failure must not drop the rest of the batch"
    assert all(item.fd == -1 for item in items)
print("descriptors closed once test passed ✓")

# A scan worker isn't held up by a running clamscan: with one slow batch
# running, a second submit returns at once.
release = threading.Event()
pool = scanner_mod._ClamscanPool(1, GiB, lambda batch, running: release.wait(5))
pool.submit([])
t0 = time.monotonic()
pool.submit([])  # waits behind the first, but the caller doesn't
assert time.monotonic() - t0 < 0.5, "submit must not wait for clamscan to finish"
release.set()
pool.wait()
print("non-blocking workers test passed ✓")


# --- the setting itself ---------------------------------------------------------------------
assert Config._from_dict({"max_clamscans": 3}, "t").max_clamscans == 3
print("max_clamscans setting test passed ✓")


# --- advice to raise clamd's MaxThreads, only when the CPU could take more ------------------------
class ThreadsClamd(FakeClamd):
    def __init__(self, max_threads):
        super().__init__()
        self._max = max_threads

    def max_threads(self):
        return self._max


real_cpu_count = os.cpu_count
try:
    with tempfile.TemporaryDirectory() as d:
        def hint(clamd_threads, cpus, **cfg):
            os.cpu_count = lambda: cpus
            config = Config(db_url=f"sqlite:///{d}/w.db", log_file=Path(d, "e.txt"), **cfg)
            s = Scanner(config, clamd=ThreadsClamd(clamd_threads))
            return s.workers, s.thread_hint()
        # cpu_share 50 (the default): the workers may fill half the CPU threads.
        workers, tip = hint(7, 12)
        assert workers == 5 and "MaxThreads 7 limits Ensign to 5" in tip and "MaxThreads 8" in tip \
            and "would allow 6" in tip and "50% of 12 CPU threads" in tip, tip
        workers, tip = hint(7, 16)
        assert "MaxThreads 10" in tip and "would allow 8" in tip, tip
        workers, tip = hint(7, 32)
        assert "MaxThreads 14" in tip and "would allow 12" in tip, f"capped at 12 workers: {tip}"
        assert hint(7, 8)[1] is None, "half of 8 is 4, below the current 5 workers: nothing to suggest"
        assert hint(7, 6)[1] is None
        assert hint(10, 16)[1] is None, "already at half of 16"
        # cpu_share 100: the whole machine
        workers, tip = hint(7, 12, cpu_share=100)
        assert "MaxThreads 14" in tip and "would allow 12" in tip, tip
        # and the worker count itself follows cpu_share, not just the tip
        assert hint(12, 16)[0] == 8, "MaxThreads 12 allows 10, but half of 16 threads is 8"
        assert hint(12, 16, cpu_share=100)[0] == 10
        assert hint(12, 2)[0] == 1, "never below 1"
        # the scanner's own check: 16 threads at 50% = 8; 6 workers busy
        os.cpu_count = lambda: 16
        s = Scanner(Config(db_url=f"sqlite:///{d}/w.db", log_file=Path(d, "e.txt")),
                    clamd=ThreadsClamd(12))
        s._busy_workers = 6
        assert s.cpu_budget() == 8
        assert s._cpu_allows_clamscan(1) and not s._cpu_allows_clamscan(2), \
            "1 running + 6 busy workers + 1 more = 8 fits; a 3rd would not"
        assert hint(14, 32)[1] is None, "already at Ensign's maximum"
        assert hint(None, 32)[1] is None, "clamd didn't say: no advice"
        assert hint(7, 32, max_workers=3)[1] is None, "workers set by hand: no advice"
finally:
    os.cpu_count = real_cpu_count
print("MaxThreads advice test passed ✓")

# --- real ClamAV (CI) --------------------------------------------------------------------------
socket_path = os.environ.get("ENSIGN_TEST_CLAMD_SOCKET")
if not socket_path or not shutil.which("clamscan"):
    print("\nAll large-file tests passed ✓ (real-ClamAV tests skipped: set ENSIGN_TEST_CLAMD_SOCKET, "
          "and install clamscan)")
    raise SystemExit(0)

limits = ClamdClient(socket_path).limits()
assert limits.source != "test" and limits.scan_limit > 0, limits
with tempfile.TemporaryDirectory() as d:
    padded = Path(d, "padded.bin")
    padded.write_bytes(EICAR + b"\0" * 8192)        # the hash signature can't match; the body one does
    huge = Path(d, "huge.img")
    with open(huge, "wb") as fh:                      # sparse: no disk used, but past ClamAV's ceiling
        fh.write(EICAR)
        fh.truncate(2049 * 2**20)
    clean = Path(d, "clean.bin")
    clean.write_bytes(b"nothing here " * 1000)
    regex = Path(d, "regex-past-100m.bin")      # only a regex (PCRE) signature matches this
    with open(regex, "wb") as fh:
        fh.write(b"ENSIGN-PCRE" + b"-TEST-MARKER")
        fh.truncate(150 * 2**20)
    fds = [os.open(p, os.O_RDONLY) for p in (padded, huge, clean, regex)]
    try:
        got = scan_fds_with_clamscan(fds, limits, timeout=600)
    finally:
        for fd in fds:
            os.close(fd)
    padded_r, huge_r, clean_r, regex_r = (got[fd] for fd in fds)
    assert regex_r.status == ScanStatus.INFECTED and "PCRE" in regex_r.threat_name, \
        f"regex signatures must apply past PCREMaxFileSize too: {regex_r}"
    assert padded_r.status == ScanStatus.INFECTED and "EICAR" in padded_r.threat_name.upper(), padded_r
    assert huge_r.status == ScanStatus.INCOMPLETE, f"ClamAV can't scan past ~2 GiB: {huge_r}"
    assert huge_r.threat_name == "Heuristics.Limits.Exceeded.MaxFileSize", huge_r
    assert clean_r.status == ScanStatus.CLEAN, clean_r
    print("real clamscan test passed ✓")

    # End to end with the real clamd: EICAR padded past clamd's own limit.
    tree = Path(d, "tree")
    tree.mkdir()
    with open(tree / "padded-past-clamd.bin", "wb") as fh:
        fh.write(EICAR)
        fh.truncate(limits.scan_limit + 4096)
    Path(d, "data").mkdir()
    config = Config(db_url=f"sqlite:///{d}/data/system.db", log_file=Path(d, "data", "e.txt"),
                    clamd_socket=socket_path, max_workers=2)
    live = Scanner(config)
    with contextlib.redirect_stdout(io.StringIO()):
        live.scan_tree(tree)
    with Session(live.engine) as session:
        row = session.query(FileRecord).one()
    assert row.scan_status == "infected" and row.scan_result.startswith("clamscan:"), \
        (row.scan_status, row.scan_result)
    print("real clamd + clamscan end-to-end test passed ✓")

print("\nAll large-file tests passed ✓")
