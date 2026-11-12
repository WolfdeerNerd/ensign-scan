"""The sweep: files too large for ClamAV, read in overlapping slices.

ClamAV can't scan a file over about 2 GiB. With sweep_huge_files (or
--sweep), Ensign reads such files in slices, each passed to clamd through
an in-memory file, and flags the whole file if a slice matches a signature.
Checked here:

  * slices overlap, so a signature cut by a slice boundary is still found,
    and no slice is larger than clamd will scan;
  * a hit flags the file infected; a heuristic hit is only noted; nothing
    found leaves it "not fully scanned", never clean;
  * the normal rescan passes don't undo a sweep verdict; signature updates
    re-sweep it (a fixed false positive goes back to "not fully scanned");
  * an allowed sweep hit stays allowed; no in-memory files are left open.

Runs anywhere with a stand-in clamd (64 KiB limit) that flags "EVIL" and,
as a heuristic, "HEUR". With ENSIGN_TEST_CLAMD_SOCKET set (CI), the end
sweeps a real 2049 MiB sparse file through real clamd.

    python3 tests/sweep_test.py
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
import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

from sqlalchemy.orm import Session  # noqa: E402

from ensign_scan import allowlist, scanner as scanner_mod  # noqa: E402
from ensign_scan.clamd import ClamdLimits, ScanOutcome  # noqa: E402
from ensign_scan.config import Config  # noqa: E402
from ensign_scan.models import FileRecord, ScanStatus  # noqa: E402
from ensign_scan.scanner import Scanner, _sweep_slices  # noqa: E402

LIMIT = 64 * 1024
TOO_BIG = "Heuristics.Limits.Exceeded.MaxFileSize"


# --- slices: cover the file, overlap, never exceed the slice size ------------------------------
for size, length, overlap in ((1_000_000, 65_535, 16_383), (65_535, 65_535, 16_383), (10, 4, 1)):
    spans = _sweep_slices(size, length, overlap)
    assert spans[0][0] == 0 and spans[-1][1] == size, spans
    assert all(e - s <= length for s, e in spans)
    assert all(b[0] == a[1] - overlap for a, b in zip(spans, spans[1:], strict=False)), "each overlaps the next"
assert _sweep_slices(0, 10, 2) == []
print("slice layout test passed ✓")


class FakeClamd:
    """A 64 KiB limit; flags EVIL (unless `fixed`, i.e. newer signatures
    dropped that one) and, as a heuristic, HEUR. Records each slice."""
    def __init__(self):
        self.version = 27000
        self.fixed = False
        self.slices: list[int] = []

    def daemon_uid(self):
        return 1000

    def supports_fildes(self):
        return True

    def signature_version(self):
        return self.version

    def max_threads(self):
        return 6

    def limits(self):
        return ClamdLimits(LIMIT, 0, None, False, "test", pcre_max_file_size=0)

    def memory_in_use(self):
        return 2**20

    def scan_fd(self, fd, label=""):
        data = os.pread(fd, 1 << 22, 0)
        if "[bytes " in label:
            self.slices.append(len(data))
        if b"EVIL" in data and not self.fixed:
            return ScanOutcome(ScanStatus.INFECTED, f"{label}: Test.Evil FOUND", "Test.Evil")
        if b"HEUR" in data:
            return ScanOutcome(ScanStatus.INFECTED, f"{label}: Heuristics.Test FOUND", "Heuristics.Test")
        return ScanOutcome(ScanStatus.CLEAN, f"{label}: OK")


def refuses_everything(fds, limits, timeout, run_as=None, on_result=None):
    """clamscan, for files this test treats as over ClamAV's ceiling."""
    return {fd: ScanOutcome(ScanStatus.INCOMPLETE, f"clamscan: {TOO_BIG} FOUND", TOO_BIG) for fd in fds}


def statuses(engine) -> dict[str, tuple[str, str | None, str | None]]:
    with Session(engine) as session:
        return {Path(r.filepath).name: (r.scan_status, r.threat_name, r.scan_result)
                for r in session.query(FileRecord)}


def memfds_open() -> int:
    n = 0
    for fd in os.listdir("/proc/self/fd"):
        with contextlib.suppress(OSError):
            n += os.readlink(f"/proc/self/fd/{fd}").startswith("/memfd:")
    return n


real = (scanner_mod.scan_fds_with_clamscan, scanner_mod.clamscan_cli_available, scanner_mod.clamscan_user)
scanner_mod.scan_fds_with_clamscan = refuses_everything
scanner_mod.clamscan_cli_available = lambda: True
scanner_mod.clamscan_user = lambda: None
try:
    with tempfile.TemporaryDirectory() as d:
        tree = Path(d, "tree")
        tree.mkdir()
        size = 300 * 1024
        (tree / "deep.img").write_bytes(b"\0" * 200_000 + b"EVIL" + b"\0" * (size - 200_004))
        # slices are 65535 bytes, stepping 49152: put EVIL across the end of the first slice
        (tree / "straddle.img").write_bytes(b"\0" * 65_533 + b"EVIL" + b"\0" * (size - 65_537))
        (tree / "heur.img").write_bytes(b"\0" * 100_000 + b"HEUR" + b"\0" * (size - 100_004))
        (tree / "empty.img").write_bytes(b"\0" * size)
        Path(d, "data").mkdir()
        config = Config(db_url=f"sqlite:///{d}/data/system.db", log_file=Path(d, "data", "e.txt"),
                        max_workers=3, rescan_after_signature_updates=1)
        clamd = FakeClamd()

        def scanner():
            return Scanner(config, clamd=clamd)

        def scan(sweep: bool):
            s = scanner()
            with contextlib.redirect_stdout(io.StringIO()):
                s.scan_tree(tree)
                s.rescan_infected()
                s.rescan_stale(days=0)  # everything counts as stale: the hardest case
                if sweep:
                    s.sweep_huge([str(tree)])
            return s

        engine = scan(sweep=False).engine
        assert all(v[0] == "incomplete" for v in statuses(engine).values()), statuses(engine)

        # --- the sweep -------------------------------------------------------------------------
        scan(sweep=True)
        st = statuses(engine)
        assert st["deep.img"][:2] == ("infected", "Test.Evil"), st["deep.img"]
        assert st["deep.img"][2].startswith("sweep: Test.Evil FOUND in bytes "), st["deep.img"]
        assert st["straddle.img"][:2] == ("infected", "Test.Evil"), \
            f"a signature cut by a slice boundary is found in the overlap: {st['straddle.img']}"
        assert st["heur.img"][0] == "incomplete" and "Heuristics.Test" in st["heur.img"][2] \
            and "not counted" in st["heur.img"][2], f"a heuristic hit is only noted: {st['heur.img']}"
        assert st["empty.img"][0] == "incomplete" and st["empty.img"][2].startswith("swept: "), \
            "nothing found is still not fully scanned, never clean"
        assert clamd.slices and max(clamd.slices) < LIMIT, "no slice is larger than clamd scans"
        assert memfds_open() == 0, "every in-memory slice is closed"
        print("sweep verdicts test passed ✓")

        # --- once swept, not swept again; the rescans don't undo it ----------------------------
        clamd.slices.clear()
        scan(sweep=True)
        assert not clamd.slices, "unchanged and swept: not swept again"
        assert statuses(engine)["deep.img"][0] == "infected", \
            "the infected and stale rescans must not turn a sweep hit back into 'not fully scanned'"
        print("sweep verdicts kept test passed ✓")

        # --- allowing a sweep hit: stays allowed when re-swept --------------------------------
        with contextlib.redirect_stdout(io.StringIO()):
            assert allowlist.allow(engine, str(tree / "straddle.img"), lambda p: True)
        clamd.version += 1  # signatures moved on: sweep verdicts are re-swept
        scan(sweep=True)
        st = statuses(engine)
        assert st["straddle.img"][0] == "allowed", st["straddle.img"]
        assert st["deep.img"][0] == "infected"
        print("allowed sweep hit test passed ✓")

        # --- newer signatures no longer match: back to "not fully scanned" -------------------
        clamd.version += 1
        clamd.fixed = True
        scan(sweep=True)
        st = statuses(engine)
        assert st["deep.img"][0] == "incomplete" and st["deep.img"][1] == TOO_BIG \
            and st["deep.img"][2].startswith("swept: "), st["deep.img"]
        clamd.fixed = False
        print("re-sweep after signature update test passed ✓")

        # --- a changed file is swept again from scratch -------------------------------------
        clamd.version += 1
        scan(sweep=True)   # EVIL matches again
        (tree / "deep.img").write_bytes(b"\0" * size)  # now clean bytes
        scan(sweep=True)
        assert statuses(engine)["deep.img"][0] == "incomplete"
        print("changed file test passed ✓")

        # --- clamd limits too small to sweep: skipped with a warning, nothing changed --------
        class TinyClamd(FakeClamd):
            def limits(self):
                return ClamdLimits(1024, 0, None, False, "test", pcre_max_file_size=0)
        before = statuses(engine)
        clamd2 = TinyClamd()
        clamd2.version = clamd.version + 5
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            Scanner(config, clamd=clamd2).sweep_huge([str(tree)])
        assert "too small to sweep" in " ".join(buf.getvalue().split())
        assert statuses(engine) == before
        print("tiny clamd limits test passed ✓")
finally:
    scanner_mod.scan_fds_with_clamscan, scanner_mod.clamscan_cli_available, scanner_mod.clamscan_user = real

assert Config().sweep_huge_files is False, "off by default"

# --- real clamd (CI) --------------------------------------------------------------------------
socket_path = os.environ.get("ENSIGN_TEST_CLAMD_SOCKET")
if not socket_path or not shutil.which("clamscan"):
    print("\nAll sweep tests passed ✓ (real-clamd test skipped: set ENSIGN_TEST_CLAMD_SOCKET, "
          "and install clamscan)")
    raise SystemExit(0)

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR" + b"-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
with tempfile.TemporaryDirectory(dir="/var/tmp") as d:
    tree = Path(d, "tree")
    tree.mkdir()
    with open(tree / "huge.img", "wb") as fh:   # sparse: no disk used
        fh.truncate(2049 * 2**20)
        fh.seek(1536 * 2**20)
        fh.write(EICAR)
    Path(d, "data").mkdir()
    config = Config(db_url=f"sqlite:///{d}/data/system.db", log_file=Path(d, "data", "e.txt"),
                    clamd_socket=socket_path, max_workers=2, sweep_huge_files=True)
    live = Scanner(config)
    with contextlib.redirect_stdout(io.StringIO()):
        live.scan_tree(tree)
        assert statuses(live.engine)["huge.img"][0] == "incomplete", "ClamAV refuses it whole"
        live.sweep_huge([str(tree)])
    status, threat, result = statuses(live.engine)["huge.img"]
    assert status == "infected" and "EICAR" in threat.upper() and result.startswith("sweep: "), \
        (status, threat, result)
    print("real clamd sweep test passed ✓")

print("\nAll sweep tests passed ✓")
