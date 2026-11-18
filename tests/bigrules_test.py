"""YARA rules for what the sweep misses, made from ClamAV's own signatures.

Checked here, with a small made-up signature database:

  * only signatures the sweep can miss become rules: those tied to a
    position (an offset, the end of the file, an executable's layout) and
    patterns that can stretch past the slices' overlap; floating short
    ones are left to the sweep, and untranslatable ones are counted;
  * the rules match exactly what clamscan matches (when clamscan is
    installed);
  * the rules are rebuilt when the databases change, and only then;
  * a failed rebuild keeps the old rules, says so, and is retried on the
    next run; a sudden drop in the rule count is refused unless by hand;
  * rules that fail their self-test aren't used;
  * in the sweep, a signature the slices miss is found by YARA and flags
    the file; nothing found says the YARA pass ran; a file swept before
    the rules existed is swept again once;
  * the YARA pass runs in a child process: if it is killed mid-file (the
    SIGBUS a file shrinking under yara-x causes), the run goes on and the
    next file gets a new child; the child leaves no core dump (it holds
    pieces of scanned files); a timeout is reported and marked, so the
    file isn't swept again every run;
  * a different yara-x version rebuilds the rules;
  * a run checks the rules before scanning but compiles them only when
    the sweep has a file for them.

Needs yara-x for most of it (skipped, with a note, without).

    python3 tests/bigrules_test.py
"""
from __future__ import annotations

import sys as _sys_path
from pathlib import Path as _Path

# Run against THIS checkout, never an installed copy of Ensign.
ROOT = _Path(__file__).resolve().parent.parent
_sys_path.path.insert(0, str(ROOT))

import contextlib  # noqa: E402
import io  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import tarfile  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

from sqlalchemy.orm import Session  # noqa: E402

from ensign_scan import bigrules, scanner as scanner_mod, yaraengine  # noqa: E402
from ensign_scan.clamd import ClamdLimits, ScanOutcome  # noqa: E402
from ensign_scan.config import Config  # noqa: E402
from ensign_scan.models import FileRecord, ScanStatus  # noqa: E402
from ensign_scan.scanner import Scanner  # noqa: E402


def hexs(text: str) -> str:
    return text.encode().hex()


# name, target, offset, hex -- and whether it should become a rule
SIGNATURES = [
    ("Test.Abs", "0", "5000", hexs("ENSIGN-ABS"), True),           # absolute offset
    ("Test.AbsShift", "0", "6000,64", hexs("ENSIGN-SHIFT"), True),  # offset with a range
    ("Test.Eof", "0", "EOF-20", hexs("ENSIGN-EOF"), True),          # from the end
    ("Test.Span", "0", "*", hexs("START") + "*" + hexs("FINISH"), True),   # unbounded gap
    ("Test.Long", "0", "*", hexs("LONGA") + "{1500000}" + hexs("LONGB"), True),  # > 1 MiB
    ("Test.Alt", "0", "100", hexs("PATR") + "(" + hexs("ON") + "|" + hexs("OO") + ")", True),
    ("Test.Short", "0", "*", hexs("FLOATING-SHORT"), False),        # the sweep finds it
    ("Test.Ignored", "0", "200", hexs("IGNORED-SIG"), False),       # on the ignore list
    ("Test.Negated", "0", "300", hexs("NEGA") + "!(" + hexs("XX") + "|" + hexs("YY") + ")", False),
    ("Test.Html", "3", "400", hexs("HTMLTEXT"), False),             # normalised text: skipped
    ("Test.Weak", "0", "500", "41??42??43??44", False),             # no 4 known bytes in a row
    ("Test.PeEp", "1", "EP+0", hexs("PE-ENTRY"), True),             # executable layout
]


def write_db(folder: Path, signatures=SIGNATURES, version: int = 27000) -> None:
    """A daily.cvd as freshclam writes it: a 512-byte header, then a
    gzip'd tar holding the .ndb; plus a loose ignore list."""
    folder.mkdir(parents=True, exist_ok=True)
    ndb = "".join(f"{n}:{t}:{o}:{h}\n" for n, t, o, h, _ in signatures).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("daily.ndb")
        info.size = len(ndb)
        tar.addfile(info, io.BytesIO(ndb))
    header = f"ClamAV-VDB:17 Nov 2026 04-00 +0000:{version}:{len(signatures)}:90:x:x:x:0".encode()
    (folder / "daily.cvd").write_bytes(header.ljust(512, b" ") + buf.getvalue())
    (folder / "local.ign2").write_text("Test.Ignored\n")


def _try(fn, *args):
    """fn(*args), or the exception it raised."""
    try:
        return fn(*args)
    except Exception as exc:
        return exc


def quiet(fn, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()) as out:
        result = fn(*args, **kwargs)
    return result, " ".join(out.getvalue().split())


# --- translation: no engine needed ---------------------------------------------------------------
ignored = {"Test.Ignored"}
for name, target, offset, hexsig, wanted in SIGNATURES:
    line = f"{name}:{target}:{offset}:{hexsig}"
    try:
        conv = bigrules.convert_line("daily.cvd/daily.ndb", line, ignored)
        assert wanted, f"{name} should not have become a rule: {conv}"
    except (bigrules.Skip, bigrules.Unneeded) as why:
        assert not wanted, f"{name} should have become a rule ({type(why).__name__}: {why})"
loose = bigrules.convert_line("thirdparty.ndb", "Test.Abs:0:5000:" + hexs("ENSIGN-ABS"), set())
assert loose.name == "Test.Abs.UNOFFICIAL", "ClamAV names signatures from unsigned databases this way"
assert bigrules.render_condition("EOF-20", "any") == "$a at filesize - 20"
assert bigrules.render_condition("6000,64", "any") == "$a in (6000..6000 + 64)"
assert bigrules.render_condition("EP+0", "pe") == "$a at pe.entry_point + 0"
assert bigrules.max_span(bigrules.parse_hex("4141{10}42(4343|444444)")) == 1 + 1 + 10 + 1 + 3
assert bigrules.max_span(bigrules.parse_hex("41414141*42")) == float("inf")
assert bigrules.SWEEP_OVERLAP == scanner_mod._SWEEP_OVERLAP_MAX, "the gap threshold is the sweep's overlap"
print("big-file rule translation test passed ✓")

found = yaraengine.find()
if found is None:
    print("big-file rule tests skipped: yara-x isn't installed for this Python")
    raise SystemExit(0)
engines = [found]


# Test files: each made to match one signature, and a near miss for each.
def sample_files(folder: Path) -> dict[str, set[str]]:
    """{file name: signatures clamscan should report}."""
    folder.mkdir()
    pad = b"\0" * 8000
    cases = {
        "abs.bin": (pad[:5000] + b"ENSIGN-ABS" + pad, {"Test.Abs"}),
        "abs-miss.bin": (pad[:5001] + b"ENSIGN-ABS" + pad, set()),
        "shift.bin": (pad[:6030] + b"ENSIGN-SHIFT" + pad, {"Test.AbsShift"}),
        "shift-miss.bin": (pad[:6070] + b"ENSIGN-SHIFT" + pad, set()),
        "eof.bin": (pad + b"ENSIGN-EOF" + b"\0" * 10, {"Test.Eof"}),
        "eof-miss.bin": (pad + b"ENSIGN-EOF" + b"\0" * 11, set()),
        "span.bin": (b"START" + b"\0" * 3_000_000 + b"FINISH", {"Test.Span"}),
        "long.bin": (b"LONGA" + b"\1" * 1_500_000 + b"LONGB", {"Test.Long"}),
        "long-miss.bin": (b"LONGA" + b"\1" * 1_400_000 + b"LONGB", set()),
        "alt.bin": (pad[:100] + b"PATROO" + pad, {"Test.Alt"}),
        "alt-miss.bin": (pad[:100] + b"PATRXX" + pad, set()),
    }
    for fname, (data, _) in cases.items():
        (folder / fname).write_bytes(data)
    return {fname: want for fname, (_, want) in cases.items()}


def clamscan_hits(db: Path, folder: Path) -> dict[str, set[str]] | None:
    clamscan = shutil.which("clamscan")
    if not clamscan:
        return None
    ndb = folder.parent / "plain-db"
    ndb.mkdir(exist_ok=True)
    # Without the ignored one, and without Test.Weak, which ClamAV itself
    # refuses to load ("can't find a static subpattern").
    (ndb / "test.ndb").write_text("".join(f"{n}:{t}:{o}:{h}\n" for n, t, o, h, _ in SIGNATURES
                                          if n not in ("Test.Ignored", "Test.Weak")))
    run = subprocess.run([clamscan, "--no-summary", "-d", str(ndb), str(folder)],
                         capture_output=True, text=True)
    assert run.returncode in (0, 1), f"clamscan failed: {run.stderr}"
    found: dict[str, set[str]] = {}
    for line in run.stdout.splitlines():
        if line.endswith(" FOUND"):
            path, _, rest = line.partition(": ")
            # A loose .ndb is unsigned, so ClamAV adds .UNOFFICIAL
            name = rest[:-len(" FOUND")].removesuffix(".UNOFFICIAL")
            found.setdefault(Path(path).name, set()).add(name)
    return found


LIMIT = 64 * 1024
TOO_BIG = "Heuristics.Limits.Exceeded.MaxFileSize"


def check(engine: yaraengine.Engine) -> None:
    with tempfile.TemporaryDirectory() as d:
        db, data = Path(d, "clamav"), Path(d, "data")
        data.mkdir()
        write_db(db)

        # --- first build, then "up to date" ----------------------------------------------------
        status = bigrules.update(data, db, engine)
        assert status.ok and status.rebuilt and status.loaded, status.message
        assert status.loaded.count == sum(w for *_, w in SIGNATURES), status.loaded.count
        state = bigrules.read_state(data)
        assert state["versions"] == {"daily": 27000} and state["covered_by_sweep"] == 1, state
        assert "Test.Short" not in (data / "yara/clamav-gaps-any.yar").read_text()
        again = bigrules.update(data, db, engine)
        assert again.ok and not again.rebuilt and "up to date" in again.message, again.message

        # --- the rules match what clamscan matches -------------------------------------------
        samples = data.parent / "samples"
        want = sample_files(samples)
        got = {}
        for f in sorted(samples.iterdir()):
            hits = engine.scan_file(status.loaded.compiled["any"], str(f), 60)
            got[f.name] = {h.meta["clamav_name"] for h in hits}
        expected = {k: v for k, v in want.items()}
        assert got == expected, (engine.name, got)
        real = clamscan_hits(db, samples)
        if real is not None:
            real = {f: real.get(f, set()) for f in want}
            assert real == got, f"{engine.name} differs from clamscan: clamscan {real}, YARA {got}"
            note = "agrees with clamscan"
        else:
            note = "clamscan not installed, checked against the expected hits"
        print(f"[{engine.name}] big-file rules match test passed ✓ ({note})")

        # --- freshclam updated the databases: rebuilt ----------------------------------------
        time.sleep(0.01)
        write_db(db, version=27001)
        rebuilt = bigrules.update(data, db, engine)
        assert rebuilt.ok and rebuilt.rebuilt and "rebuilt" in rebuilt.message, rebuilt.message
        assert bigrules.read_state(data)["versions"] == {"daily": 27001}

        # --- a failed rebuild keeps the old rules, says so, and is retried --------------------
        good = (db / "daily.cvd").read_bytes()
        (db / "daily.cvd").write_bytes(good[:600])   # cut short, as a broken download would be
        broken = bigrules.update(data, db, engine)
        assert not broken.ok and broken.failed and broken.loaded is not None, broken.message
        assert "couldn't be updated" in broken.message and "--update-rules" in broken.message
        assert bigrules.read_state(data).get("last_error")
        still = bigrules.update(data, db, engine)            # same broken file: tried again
        assert not still.ok and "couldn't be updated" in still.message, still.message
        (db / "daily.cvd").write_bytes(good)
        fixed = bigrules.update(data, db, engine)
        assert fixed.ok and fixed.rebuilt and not bigrules.read_state(data).get("last_error"), fixed.message

        # --- half the rules gone at once: refused unless by hand ------------------------------
        few = [s for s in SIGNATURES if s[0] in ("Test.Abs", "Test.Short")]
        write_db(db, few, version=27002)
        refused = bigrules.update(data, db, engine)
        assert not refused.ok and "less than half" in refused.message, refused.message
        assert refused.loaded.count == status.loaded.count, "the previous rules are still used"
        by_hand = bigrules.update(data, db, engine, by_hand=True)
        assert by_hand.loaded.count == 1 and "less than half" in by_hand.message, by_hand.message
        write_db(db, version=27003)
        assert bigrules.update(data, db, engine, by_hand=True).ok

        # --- rules that fail the self-test aren't used ---------------------------------------
        anyrules = data / "yara/clamav-gaps-any.yar"
        text = anyrules.read_text()
        anyrules.write_text(text.replace("ensign_selftest", "x_selftest").replace(
            'clamav_name = "Ensign.SelfTest"', 'clamav_name = "Other"'))
        tampered = bigrules.update(data, db, engine)
        assert tampered.loaded is None and not tampered.ok and "self-test" in tampered.message, tampered.message
        assert bigrules.update(data, db, engine, by_hand=True).ok, "--update-rules repairs it"

        # --- no databases at all ----------------------------------------------------------------
        missing = bigrules.update(Path(d, "data2"), Path(d, "nowhere"), engine)
        assert missing.loaded is None and missing.failed and "couldn't read" in missing.message, missing.message
        assert not bigrules.update(data, db, None).failed, "no engine is a choice, not a failure"
        print(f"[{engine.name}] big-file rule updates test passed ✓")

        # --- in the sweep ------------------------------------------------------------------------
        class FakeClamd:
            """64 KiB limit; finds nothing in any slice."""
            def daemon_uid(self):
                return 1000

            def supports_fildes(self):
                return True

            def signature_version(self):
                return 27003

            def max_threads(self):
                return 4

            def limits(self):
                return ClamdLimits(LIMIT, 0, str(db), False, "test", pcre_max_file_size=0)

            def memory_in_use(self):
                return 2**20

            def scan_fd(self, fd, label=""):
                return ScanOutcome(ScanStatus.CLEAN, f"{label}: OK")

        def refuses(fds, limits, timeout, run_as=None, on_result=None, max_scantime_ms=None):
            return {fd: ScanOutcome(ScanStatus.INCOMPLETE, f"clamscan: {TOO_BIG} FOUND", TOO_BIG) for fd in fds}

        saved = (scanner_mod.scan_fds_with_clamscan, scanner_mod.clamscan_cli_available,
                 scanner_mod.clamscan_user, yaraengine.find)
        yaraengine.find = lambda: engine   # this engine, not the first one installed
        scanner_mod.scan_fds_with_clamscan = refuses
        scanner_mod.clamscan_cli_available = lambda: True
        scanner_mod.clamscan_user = lambda: None
        try:
            tree = Path(d, "tree")
            tree.mkdir()
            size = 300 * 1024
            # At 20 bytes from the end: slices have their own ends, so only YARA sees it.
            (tree / "tail.img").write_bytes(b"\0" * (size - 20) + b"ENSIGN-EOF" + b"\0" * 10)
            (tree / "plain.img").write_bytes(b"\0" * size)
            config = Config(db_url=f"sqlite:///{data}/system.db", log_file=data / "e.txt",
                            max_workers=2, rescan_after_signature_updates=7)
            clamd = FakeClamd()

            def run(with_rules: bool):
                s = Scanner(config, clamd=clamd)
                with contextlib.redirect_stdout(io.StringIO()):
                    if with_rules:
                        assert s.prepare_big_rules().ok
                        # Checked, but not compiled until a file needs them.
                        assert s.big_rules is None and s._big_rules_available
                    s.scan_tree(tree)
                    s.sweep_huge([str(tree)])
                with Session(s.engine) as session:
                    return {Path(r.filepath).name: (r.scan_status, r.threat_name, r.scan_result)
                            for r in session.query(FileRecord)}

            before = run(with_rules=False)
            assert before["tail.img"][0] == "incomplete" and "YARA" not in before["tail.img"][2], before
            after = run(with_rules=True)          # swept before without YARA: swept again with it
            assert after["tail.img"][:2] == ("infected", "Test.Eof"), after["tail.img"]
            assert after["tail.img"][2].startswith("sweep: Test.Eof FOUND at byte ") \
                and "by YARA" in after["tail.img"][2], after["tail.img"]
            assert after["plain.img"][0] == "incomplete" and \
                scanner_mod.SWEPT_YARA_MARK in after["plain.img"][2], after["plain.img"]
            assert run(with_rules=True)["plain.img"] == after["plain.img"], "not swept a third time"
            # Nothing to sweep: the rules are never compiled.
            idle = Scanner(config, clamd=clamd)
            with contextlib.redirect_stdout(io.StringIO()):
                assert idle.prepare_big_rules().ok
                idle.sweep_huge([str(tree)])
            assert idle.big_rules is None, "compiled with nothing to sweep"
        finally:
            (scanner_mod.scan_fds_with_clamscan, scanner_mod.clamscan_cli_available,
             scanner_mod.clamscan_user, yaraengine.find) = saved
        print(f"[{engine.name}] YARA in the sweep test passed ✓")

        # --- the YARA child: a crash ends only the child -------------------------------------------
        import signal
        import threading
        from ensign_scan import yarachild
        huge = Path(d, "huge.bin")
        with open(huge, "wb") as f:      # sparse: 20 GiB that take no disk space
            f.truncate(20 * 2**30)
        worker = yarachild.Worker(status.loaded.compiled, timeout=600)
        fd = os.open(huge, os.O_RDONLY)
        try:
            box = []
            t = threading.Thread(target=lambda: box.append(_try(worker.scan, fd, ["any"])))
            t.start()
            for _ in range(200):          # wait for the child to start scanning
                if worker._proc is not None and worker._proc.poll() is None:
                    break
                time.sleep(0.05)
            time.sleep(1.0)
            pid = worker._proc.pid
            limits = Path(f"/proc/{pid}/limits").read_text()
            assert any(line.startswith("Max core file size") and line.split()[4:6] == ["0", "0"]
                       for line in limits.splitlines()), limits
            # The core-size limit of 0 shows _no_core_dumps() ran in the child;
            # what it does to the dumpable flag is checked on its own below.
            os.kill(pid, signal.SIGBUS)   # what a shrinking file does to it
            t.join(60)
            assert box and isinstance(box[0], yarachild.ChildFailed), box
            assert "changed while YARA was reading it" in str(box[0]), box[0]
            small = Path(d, "tail2.bin")
            small.write_bytes(b"\0" * 5000 + b"ENSIGN-EOF" + b"\0" * 10)
            fd2 = os.open(small, os.O_RDONLY)
            try:
                assert worker.scan(fd2, ["any"]) == [("Test.Eof", 5000)], "a new child takes over"
            finally:
                os.close(fd2)
            # --- a timeout is a timeout -------------------------------------------------------
            slow = yarachild.Worker(status.loaded.compiled, timeout=1)
            try:
                failed = _try(slow.scan, fd, ["any"])
                assert isinstance(failed, yarachild.ChildFailed) and "timed out" in str(failed), failed
            finally:
                slow.close(kill=True)
        finally:
            os.close(fd)
            worker.close(kill=True)
            huge.unlink()
        # Started from a folder that has since been deleted: still works.
        gone = Path(d, "gone")
        gone.mkdir()
        here = os.getcwd()
        os.chdir(gone)
        gone.rmdir()
        lost = yarachild.Worker(status.loaded.compiled, timeout=60)
        try:
            small = Path(d, "tail3.bin")
            small.write_bytes(b"\0" * 5000 + b"ENSIGN-EOF" + b"\0" * 10)
            fd3 = os.open(small, os.O_RDONLY)
            try:
                assert lost.scan(fd3, ["any"]) == [("Test.Eof", 5000)]
            finally:
                os.close(fd3)
        finally:
            lost.close(kill=True)
            os.chdir(here)
        # _no_core_dumps() makes the process non-dumpable (PR_GET_DUMPABLE == 0).
        probe = subprocess.run(
            [sys.executable, "-c",
             f"import sys; sys.path.insert(0, {str(ROOT)!r}); import ctypes; "
             "from ensign_scan.yarachild import _no_core_dumps; _no_core_dumps(); "
             "print(ctypes.CDLL(None).prctl(3, 0, 0, 0, 0))"],
            capture_output=True, text=True, timeout=60)
        assert probe.stdout.strip() == "0", (probe.stdout, probe.stderr)
        print(f"[{engine.name}] YARA child process test passed ✓")

        # --- a new yara-x version rebuilds the rules ---------------------------------------------
        state = bigrules.read_state(data)
        state["engine_version"] = "0.0.1"
        bigrules._write_state(data, state)
        upgraded = bigrules.update(data, db, engine)
        assert upgraded.ok and upgraded.rebuilt, upgraded.message
        assert bigrules.read_state(data)["engine_version"] == engine.version

        # The state file carries no paths or names that could leak into a bug report.
        assert str(d) not in json.dumps(bigrules.read_state(data))

for engine in engines:
    check(engine)
print("All big-file rule tests passed ✓")
