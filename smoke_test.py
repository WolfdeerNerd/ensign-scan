"""Smoke test: fake clamd server + temp tree, verifies the full pipeline.

Run: python3 smoke_test.py
"""
from __future__ import annotations

import os
import socket
import socketserver
import tempfile
import threading
import time
from pathlib import Path

from ensign_scan.clamd import ClamdClient
from ensign_scan.config import Config
from ensign_scan.models import ScanStatus
from ensign_scan.reports import scan_summary
from ensign_scan.scanner import Scanner

import re

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


# Mutable so tests can simulate freshclam delivering a new database.
FAKE_SIG_VERSION = [27455]


class FakeClamdHandler(socketserver.StreamRequestHandler):
    def handle(self):
        data = self.rfile.readline().decode().strip()
        if data.startswith("n"):
            data = data[1:]
        if data == "PING":
            self.wfile.write(b"PONG\n")
        elif data == "STATS":
            self.wfile.write(b"POOLS: 1\nTHREADS: live 1 idle 0 max 12 idle-timeout 30\nEND\n")
        elif data == "VERSION":
            from datetime import datetime, timedelta
            build_date = (datetime.now() - timedelta(days=5)).strftime("%a %b %d %H:%M:%S %Y")
            self.wfile.write(f"ClamAV 1.2.0/{FAKE_SIG_VERSION[0]}/{build_date}\n".encode())
        elif data.startswith("SCAN "):
            path = data[5:]
            if "toolarge" in path:
                self.wfile.write(f"{path}: size limit exceeded. ERROR\n".encode())
            elif "evil" in path:
                self.wfile.write(f"{path}: Eicar-Test-Signature FOUND\n".encode())
            else:
                self.wfile.write(f"{path}: OK\n".encode())


def main():
    tmp = Path(tempfile.mkdtemp(prefix="ensign_test_"))
    sock_path = str(tmp / "clamd.sock")

    server = socketserver.ThreadingUnixStreamServer(sock_path, FakeClamdHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    # Build a small tree, including a snapshot subtree and a fifo.
    tree = tmp / "tree"
    (tree / "docs").mkdir(parents=True)
    (tree / "snapshots" / "snap1").mkdir(parents=True)
    (tree / "docs" / "a.txt").write_text("hello")
    (tree / "docs" / "evil.bin").write_text("pretend malware")
    (tree / "snapshots" / "snap1" / "frozen.txt").write_text("immutable")
    os.mkfifo(tree / "docs" / "pipe.fifo")  # must be skipped, not hang

    # Symlink to a regular file must be followed and scanned -- this is
    # the whole point of switching is_scannable/process_file from
    # safe_lstat to safe_stat.
    real_target = tmp / "outside_tree" / "real_secret.txt"
    real_target.parent.mkdir(parents=True)
    real_target.write_text("actual content")
    (tree / "docs" / "link_to_real.txt").symlink_to(real_target)

    # A symlink whose target doesn't exist must be skipped cleanly, not
    # raise or hang.
    (tree / "docs" / "broken_link.txt").symlink_to(tmp / "does_not_exist")

    config = Config(
        db_url=f"sqlite:///{tmp / 'test.db'}",
        log_file=tmp / "errors.log",
        clamd_socket=sock_path,
        max_workers=3,
        snapshot_roots=(str(tree / "snapshots"),),
        scan_targets=(tree,),
        rescan_after_signature_updates=1,   # these tests step the version by 1; the default is 7
    )
    scanner = Scanner(config)

    assert scanner.clamd.ping(), "fake clamd should answer PING"
    assert scanner.clamd.max_threads() == 12, "STATS parsing"
    assert scanner.workers == 3, "explicit max_workers should win"

    auto_scanner = Scanner(Config(
        db_url=f"sqlite:///{tmp / 'auto.db'}",
        log_file=tmp / "errors2.log",
        clamd_socket=sock_path,
        max_workers=0,
    ), clamd=scanner.clamd)
    expected = max(1, min(10, os.cpu_count() or 4, 12))
    assert auto_scanner.workers == expected, f"auto sizing: {auto_scanner.workers} != {expected}"

    print("--- First run (everything new) ---")
    import logging as _lg
    _captured = []

    class _Grab(_lg.Handler):
        def emit(self, record):
            _captured.append(record.getMessage())

    _grab = _Grab(level=_lg.ERROR)
    _lg.getLogger().addHandler(_grab)
    try:
        stats1 = scanner.scan_tree(tree)
    finally:
        _lg.getLogger().removeHandler(_grab)
    _broken = str(tree / "docs" / "broken_link.txt")
    assert _broken in stats1.missing, "a broken symlink must be counted as missing"
    assert not any(_broken in m for m in _captured), \
        "a broken symlink is counted quietly, not logged as an error every run"
    print("broken symlink counted quietly test passed ✓")
    assert stats1.processed == 4, f"expected 4 processed (3 originals + symlink), got {stats1}"
    assert stats1.unchanged == 0

    from sqlalchemy.orm import Session as _SymSession
    from ensign_scan.models import FileRecord as _FRSym
    with _SymSession(scanner.engine) as session:
        link_record = session.query(_FRSym).filter(
            _FRSym.filepath == str(tree / "docs" / "link_to_real.txt")
        ).first()
        assert link_record is not None, "symlink to a regular file should be recorded, not skipped"
        assert link_record.scan_status == ScanStatus.CLEAN.value, \
            "symlink target should actually be scanned (fake clamd returns OK for non-evil paths)"

        broken_record = session.query(_FRSym).filter(
            _FRSym.filepath == str(tree / "docs" / "broken_link.txt")
        ).first()
        assert broken_record is None, "a broken symlink must be skipped cleanly, not recorded or errored"

    print("\n--- Second run (nothing changed) ---")
    stats2 = scanner.scan_tree(tree)
    assert stats2.processed == 0, f"expected 0 processed, got {stats2}"
    assert stats2.unchanged >= 2, f"expected unchanged files, got {stats2}"
    assert stats2.pruned_dirs >= 1, f"expected snapshot pruning, got {stats2}"

    print("\n--- Third run (one file modified) ---")
    time.sleep(0.01)
    (tree / "docs" / "a.txt").write_text("hello, changed")
    stats3 = scanner.scan_tree(tree)
    assert stats3.processed == 1, f"expected 1 processed, got {stats3}"

    summary = scan_summary(scanner.engine)
    assert summary["infected"] == 1, f"expected 1 infected, got {summary}"
    assert summary["clean"] == 3, f"expected 3 clean (a.txt, link_to_real.txt, and... wait, evil.bin is infected), got {summary}"

    print("\n--- ctime catches an mtime-restored edit ---")
    _a = tree / "docs" / "a.txt"
    _before = _a.stat()
    time.sleep(0.01)
    _a.write_text("HELLO, CHANGED")                      # same size, new content
    assert _a.stat().st_size == _before.st_size
    os.utime(_a, ns=(_before.st_atime_ns, _before.st_mtime_ns))  # put mtime back
    _after = _a.stat()
    assert (_after.st_size, _after.st_mtime_ns) == (_before.st_size, _before.st_mtime_ns)
    assert _after.st_ctime_ns != _before.st_ctime_ns, "ctime can't be reset by utime"
    stats_ct = scanner.scan_tree(tree)
    assert stats_ct.processed == 1, f"ctime change must trigger a rescan, got {stats_ct}"
    stats_ct2 = scanner.scan_tree(tree)
    assert stats_ct2.processed == 0, "and settle again afterwards"
    print("ctime catches mtime-restored edit test passed ✓")

    print("\n--- legacy rows (ctime_ns NULL) are rescanned once ---")
    from sqlalchemy import text as _sqltext
    with scanner.engine.begin() as _conn:
        _conn.execute(_sqltext("UPDATE files SET ctime_ns = NULL"))
    stats_leg = scanner.scan_tree(tree)
    assert stats_leg.processed == 3, f"every row without a ctime must be rescanned, got {stats_leg}"
    stats_leg2 = scanner.scan_tree(tree)
    assert stats_leg2.processed == 0, "and settle again once ctime is recorded"
    print("legacy ctime rescan test passed ✓")

    print("\n--- new signatures trigger rescans of clean files ---")
    import dataclasses
    assert scanner.clamd.signature_version() == 27455, scanner.clamd.signature_version()
    assert scanner.scan_tree(tree).processed == 0, "same database: nothing to redo"

    FAKE_SIG_VERSION[0] = 27456
    stats_sig = scanner.scan_tree(tree)
    # a.txt and link_to_real.txt are clean; evil.bin is infected, which the
    # rescan_infected pass already covers, so the walk leaves it alone.
    assert stats_sig.sig_rescan == 2 and stats_sig.processed == 2, stats_sig
    assert scanner.scan_tree(tree).processed == 0, "stamped with the new version, settles again"

    relaxed = Scanner(dataclasses.replace(config, rescan_after_signature_updates=3), clamd=scanner.clamd)
    FAKE_SIG_VERSION[0] = 27458   # 2 updates behind: under the threshold of 3
    assert relaxed.scan_tree(tree).processed == 0, "threshold 3 ignores a 2-update gap"
    FAKE_SIG_VERSION[0] = 27459   # exactly 3 behind
    assert relaxed.scan_tree(tree).processed == 2, "threshold 3 triggers at a 3-update gap"

    off = Scanner(dataclasses.replace(config, rescan_after_signature_updates=0), clamd=scanner.clamd)
    FAKE_SIG_VERSION[0] = 27999
    assert off.scan_tree(tree).processed == 0, "0 disables signature-triggered rescans"

    FAKE_SIG_VERSION[0] = 27000   # database went backwards (restored backup, other machine)
    assert scanner.scan_tree(tree).processed == 2, "an older database than the stamp counts as stale"
    FAKE_SIG_VERSION[0] = 27455
    scanner.scan_tree(tree)       # leave the stamps as later tests expect
    print("signature-triggered rescan test passed ✓")

    print("\n--- Rescan infected ---")
    scanner.rescan_infected()

    print("\n--- suggest_fixes: secrets-path guard ---")
    from ensign_scan.models import FileRecord, ScanStatus as SS, utcnow
    from ensign_scan.reports import suggest_fixes
    from sqlalchemy.orm import Session as _Session
    import io, contextlib

    # suggest_fixes() checks lexists() before suggesting a command, so
    # these need to be real files on disk -- not just DB rows -- or
    # they'll be (correctly) routed to the stale-record/--purge-missing
    # branch instead of the command-suggestion branch this test checks.
    cache_file = tmp / "home_u" / ".cache" / "app" / "reg.bin"
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text("cached data")

    wallet_file = tmp / "home_u" / ".local" / "share" / "kwalletd" / "kdewallet.kwl"
    wallet_file.parent.mkdir(parents=True, exist_ok=True)
    wallet_file.write_text("encrypted wallet data")

    with _Session(scanner.engine) as session:
        session.add(FileRecord(filepath=str(cache_file), filename="reg.bin",
                                file_hash="x", scan_status=SS.ERROR.value,
                                scan_result=f"{cache_file}: Access denied. ERROR",
                                last_scanned=utcnow()))
        session.add(FileRecord(filepath=str(wallet_file),
                                filename="kdewallet.kwl", file_hash="x",
                                scan_status=SS.ERROR.value,
                                scan_result=f"{wallet_file}: Access denied. ERROR",
                                last_scanned=utcnow()))
        session.commit()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        suggest_fixes(scanner.engine)
    output = " ".join(_strip_ansi(buf.getvalue()).split())  # normalize whitespace: rich wraps lines to console width
    assert "setfacl" in output and str(cache_file.parent) in output, "should suggest a command for a normal cache dir"
    assert "kwalletd" in output and "review manually" in output.lower(), "should flag, not suggest, a wallet-like path"
    assert "setfacl" not in output.split("kwalletd")[1].split("!")[0], "must not print a command for the wallet path"

    print("\n--- suggest_fixes: secrets guard covers the whole subtree ---")
    # setfacl -R recurses, and -d is inherited by new files, so the guard
    # has to look beneath a hotspot, not just at the files that errored
    # in it. Each case runs suggest_fixes scoped to its own directory so
    # the rows other tests left in this DB don't leak into the output.
    g = tmp / "g"

    def _guard_row(path, status):
        return FileRecord(filepath=str(path), filename=Path(path).name, file_hash="x",
                          scan_status=status.value, scan_result=f"{path}: Access denied. ERROR",
                          last_scanned=utcnow())

    def _real(path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x")
        return path

    def _run(scope):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            suggest_fixes(scanner.engine, paths=[str(scope)])
        return " ".join(_strip_ansi(buf.getvalue()).split())

    def _cmd(d):
        return f"setfacl -R -m g:clamav:rX '{d}'"

    # A: a CLASSIFIED wallet deeper in the tree, only an ordinary file
    # directly in the hotspot.
    pa_err = _real(g / "pa" / "notes.txt")
    _real(g / "pa" / "vault" / ".ssh" / "id_rsa")
    # B: the same wallet name next to the hotspot and in an unrelated
    # dir -- one shares a prefix ("pb2" vs "pb") but is not beneath it.
    pb_err = _real(g / "pb" / "data.txt")
    # C: a deep ERROR (not CLASSIFIED) file that matches at MEDIUM.
    pc_err = _real(g / "pc" / "a.txt")
    pc_pem = _real(g / "pc" / "sub" / "server.pem")
    # D: a hotspot scoped down to one exact file, with a wallet beneath
    # it that is outside that scope.
    pd_err = _real(g / "pd" / "x.txt")
    # E: a CLASSIFIED record whose file is gone.
    pe_err = _real(g / "pe" / "y.txt")

    with _Session(scanner.engine) as session:
        for p in (pa_err, pb_err, pc_err, pc_pem, pd_err, pe_err):
            session.add(_guard_row(p, SS.ERROR))
        session.add(_guard_row(g / "pa" / "vault" / ".ssh" / "id_rsa", SS.CLASSIFIED))
        session.add(_guard_row(g / "pb2" / ".ssh" / "id_rsa", SS.CLASSIFIED))
        session.add(_guard_row(g / "elsewhere" / ".ssh" / "id_rsa", SS.CLASSIFIED))
        session.add(_guard_row(g / "pd" / "vault" / ".ssh" / "id_rsa", SS.CLASSIFIED))
        session.add(_guard_row(g / "pe" / "gone" / ".ssh" / "id_rsa", SS.CLASSIFIED))
        session.commit()

    out_a = _run(g / "pa")
    assert "review manually" in out_a and "vault/.ssh/id_rsa" in out_a, \
        "a CLASSIFIED wallet deeper in the subtree must stop the command"
    assert "setfacl" not in out_a, "no command may be printed over a subtree holding a wallet"

    out_b = _run(g / "pb")
    assert _cmd(g / "pb") in out_b, \
        "an unrelated wallet, or one in a sibling that merely shares the name prefix, must not block the command"
    assert "review manually" not in out_b

    out_c = _run(g / "pc")
    assert "sub/server.pem" in out_c and "setfacl" not in out_c, \
        "a deep ERROR file matching at MEDIUM must stop the command too"

    out_d = _run(g / "pd" / "x.txt")
    assert "review manually" in out_d and "setfacl" not in out_d, \
        "narrowing the report's scope must not narrow the guard"

    out_e = _run(g / "pe")
    assert "review manually" in out_e and "setfacl" not in out_e, \
        "a stale CLASSIFIED record still blocks: -d would grant it if the file came back"

    print("\n--- unreadable directories: reported, not silently skipped ---")
    from ensign_scan.reports import unreadable_report
    from ensign_scan.scanner import TreeStats

    # Part 1 -- classification and reporting need no real permissions, so
    # these run everywhere, including as root.
    ts = TreeStats()
    scanner._on_walk_error(ts, FileNotFoundError(2, "No such file or directory", "/x/vanished"))
    scanner._on_walk_error(ts, NotADirectoryError(20, "Not a directory", "/x/replaced"))
    assert ts.unreadable_dirs == {}, "a directory that vanished mid-walk is noise, not a blind spot"
    scanner._on_walk_error(ts, PermissionError(13, "Permission denied", "/x/locked"))
    assert ts.unreadable_dirs == {"/x/locked": "cannot list: Permission denied"}

    def _report(d, **kw):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            unreadable_report(d, **kw)
        return " ".join(_strip_ansi(buf.getvalue()).split())

    assert _report({}) == "", "nothing unreadable -> nothing printed"
    out_u = _report({"/a": "r1", "/a/b": "r2", "/c": "r3"})
    assert "(2)" in out_u and "/a r1" in out_u and "/c r3" in out_u
    assert "/a/b" not in out_u, "a path under an already-listed ancestor is redundant"
    out_u = _report({"/a": "r1", "/a-b": "r2"})
    assert "/a-b r2" in out_u, "a sibling that merely shares a name prefix is not 'under' it"
    out_u = _report({f"/d{i}": "r" for i in range(4)}, top=2)
    assert "(4)" in out_u and "and 2 more" in out_u, "past `top`, say how many were left out"

    # Part 2 -- the real walk. Needs permissions that are actually
    # enforced; a root process ignores chmod, so probe rather than assume.
    ud = tmp / "ud"
    (ud / "ok").mkdir(parents=True)
    (ud / "ok" / "file.txt").write_text("fine")
    (ud / "locked").mkdir()                          # no permissions at all
    (ud / "locked" / "secret.txt").write_text("hidden")
    (ud / "noexec" / "sub").mkdir(parents=True)      # readable, but can't be entered
    (ud / "noexec" / "inside.txt").write_text("hidden")
    (ud / "noexec" / "sub" / "deep.txt").write_text("hidden")
    (ud / "locked").chmod(0o000)
    (ud / "noexec").chmod(0o444)
    try:
        try:
            os.listdir(ud / "locked")
            enforced = False
        except PermissionError:
            enforced = True
        if not enforced:
            print("  (real-walk check skipped: this process ignores file permissions -- running as root?)")
        else:
            st_u = scanner.scan_tree(ud, scan=False)
            assert st_u.processed == 1, f"only ok/file.txt is readable, got {st_u}"
            assert set(st_u.unreadable_dirs) == {
                str(ud / "locked"), str(ud / "noexec"), str(ud / "noexec" / "sub"),
            }, st_u.unreadable_dirs
            assert "cannot list" in st_u.unreadable_dirs[str(ud / "locked")]
            assert "cannot enter" in st_u.unreadable_dirs[str(ud / "noexec")], \
                "a listable-but-not-enterable directory must be named itself, not just its child"
            out_ud = _report(st_u.unreadable_dirs)
            assert "(2)" in out_ud and str(ud / "locked") in out_ud and str(ud / "noexec") in out_ud
            assert str(ud / "noexec" / "sub") not in out_ud, "the child is explained by its parent"
            assert scanner.scan_tree(ud, scan=False).unreadable_dirs == st_u.unreadable_dirs, \
                "the same blind spots must be found again on the next run"
    finally:
        (ud / "locked").chmod(0o755)   # leave nothing behind that can't be deleted
        (ud / "noexec").chmod(0o755)

    print("\n--- signature_age_days ---")
    assert scanner.clamd.signature_age_days() == 5, scanner.clamd.signature_age_days()

    print("\n--- clamscan CLI fallback for size-limit rejections ---")
    fakebin = tmp / "fakebin"
    fakebin.mkdir()
    fake_clamscan = fakebin / "clamscan"
    fake_clamscan.write_text(
        "#!/bin/bash\n"
        'path="${@: -1}"\n'
        'if [[ "$path" == *evil* ]]; then\n'
        '  echo "$path: Eicar-Test-Signature FOUND"\n'
        "  exit 1\n"
        "else\n"
        '  echo "$path: OK"\n'
        "  exit 0\n"
        "fi\n"
    )
    fake_clamscan.chmod(0o755)
    old_path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{fakebin}{os.pathsep}{old_path}"
    try:
        sock_path2 = str(tmp / "clamd2.sock")
        server2 = socketserver.ThreadingUnixStreamServer(sock_path2, FakeClamdHandler)
        threading.Thread(target=server2.serve_forever, daemon=True).start()
        config2 = Config(
            db_url=f"sqlite:///{tmp / 'sizelimit.db'}",
            log_file=tmp / "errors3.log",
            clamd_socket=sock_path2,
            max_workers=2,
        )
        scanner2 = Scanner(config2)

        big_clean = tmp / "toolarge_clean.bin"
        big_clean.write_bytes(b"x" * 100)
        big_evil = tmp / "toolarge_evil.bin"
        big_evil.write_bytes(b"x" * 100)

        scanner2.process_file(big_clean, scan=True)
        scanner2.process_file(big_evil, scan=True)

        from ensign_scan.models import FileRecord
        from sqlalchemy.orm import Session as _S
        with _S(scanner2.engine) as session:
            clean_rec = session.query(FileRecord).filter(FileRecord.filepath == str(big_clean)).first()
            evil_rec = session.query(FileRecord).filter(FileRecord.filepath == str(big_evil)).first()
            assert clean_rec.scan_status == ScanStatus.CLEAN.value, \
                "daemon's size-limit error should be overridden by the CLI fallback's clean verdict"
            assert evil_rec.scan_status == ScanStatus.INFECTED.value, \
                "CLI fallback should still catch a real infection"
            assert evil_rec.threat_name == "Eicar-Test-Signature"
        server2.shutdown()
    finally:
        os.environ["PATH"] = old_path

    print("\n--- secrets-pattern reclassification (CLASSIFIED, not ERROR) ---")

    class DenyHandler(socketserver.StreamRequestHandler):
        def handle(self):
            data = self.rfile.readline().decode().strip()
            if data.startswith("n"):
                data = data[1:]
            if data == "PING":
                self.wfile.write(b"PONG\n")
            elif data.startswith("SCAN "):
                self.wfile.write(f"{data[5:]}: Access denied. ERROR\n".encode())

    sock_path3 = str(tmp / "clamd3.sock")
    server3 = socketserver.ThreadingUnixStreamServer(sock_path3, DenyHandler)
    threading.Thread(target=server3.serve_forever, daemon=True).start()

    config3 = Config(
        db_url=f"sqlite:///{tmp / 'classify.db'}",
        log_file=tmp / "errors4.log",
        clamd_socket=sock_path3,
        max_workers=2,
    )
    scanner3 = Scanner(config3)

    wallet_dir = tmp / ".local" / "share" / "kwalletd"
    wallet_dir.mkdir(parents=True)
    wallet_file = wallet_dir / "kdewallet.kwl"
    wallet_file.write_text("encrypted stuff")

    normal_dir = tmp / "documents"
    normal_dir.mkdir()
    normal_file = normal_dir / "regular_document.txt"
    normal_file.write_text("nothing special")

    scanner3.process_file(wallet_file, scan=True)
    scanner3.process_file(normal_file, scan=True)

    from ensign_scan.models import FileRecord as _FR
    from ensign_scan.reports import error_summary as _es, suggest_fixes as _sf, scan_summary as _ss
    from sqlalchemy.orm import Session as _S2
    with _S2(scanner3.engine) as session:
        wrec = session.query(_FR).filter(_FR.filepath == str(wallet_file)).first()
        nrec = session.query(_FR).filter(_FR.filepath == str(normal_file)).first()
        assert wrec.scan_status == ScanStatus.CLASSIFIED.value, \
            "permission-denied on a secrets-pattern path should be reclassified"
        assert nrec.scan_status == ScanStatus.ERROR.value, \
            "permission-denied on an ordinary path must stay a real error"

    buf2 = io.StringIO()
    with contextlib.redirect_stdout(buf2):
        _es(scanner3.engine)
        _sf(scanner3.engine)
        _ss(scanner3.engine)
    combined = " ".join(_strip_ansi(buf2.getvalue()).split())
    assert "kwalletd" not in combined, "classified path must not appear in error_summary or suggest_fixes"
    assert str(normal_dir) in combined, "the real error must still be reported"
    assert "Classified: 1" in combined

    server3.shutdown()


    # --- explanations: structural decoder + curated precedence ----------
    from ensign_scan import explanations as _ex
    d = _ex.explain_threat("Win.Malware.Example-1234567-0")
    assert d and d.decoded and "signature 1234567, revision 0" in d.description
    assert "can't run natively" in d.false_positive_note
    d = _ex.explain_threat("Win.Exploit.CVE_2020_1234-1")
    assert d and d.decoded and "CVE-2020-1234" in d.description
    for n in ("Win.Exploit.CVE_2015_2503-1", "Win.Malware.Aotera-10060486-0"):
        assert not _ex.explain_threat(n).decoded, "built-in entries take precedence"
    d = _ex.explain_threat("Unix.Trojan.Agent-123-0")
    assert d and d.false_positive_note is None, "no Windows hint on a Unix signature"
    assert _ex.explain_threat("Win.Test.EICAR_HDB-1").false_positive_note is None
    assert _ex.explain_threat("Heuristics.Phishing.Email.X").decoded
    assert _ex.explain_threat("NotARealThreatName") is None
    assert _ex.explain_threat("Foo.Bar.Baz-1-0") is None, "unrecognized shape stays silent"
    assert not _ex.explain_threat("Heuristics.Limits.Exceeded").decoded, "curated beats decoded"
    print("explanations decoder test passed ✓")

    # --- list_infected: grouping, one explanation per threat, per-file context ---
    import contextlib, io
    import tempfile as _tf
    from sqlalchemy.orm import Session
    from ensign_scan.db import make_engine as _me
    from ensign_scan.models import FileRecord as _FR, ScanStatus as _SS, utcnow as _un
    from ensign_scan.reports import list_infected as _li
    _d = _tf.mkdtemp()
    _eng = _me(f"sqlite:///{_d}/g.db")
    _real = os.path.join(_d, "real[1].bin")   # brackets: must not be eaten as rich markup
    open(_real, "wb").write(b"x" * 2048)
    with Session(_eng) as _s:
        for _p, _t in [(_real, "Win.Malware.Example-1-0"),
                       ("/gone/a.bin", "Win.Malware.Example-1-0"),
                       ("/gone/b.bin", "Heuristics.Limits.Exceeded")]:
            _s.add(_FR(filepath=_p, filename=os.path.basename(_p), file_hash="h",
                       scan_status=_SS.INFECTED.value, threat_name=_t,
                       scan_result=f"{_p}: {_t} FOUND", last_scanned=_un()))
        _s.commit()
    _buf = io.StringIO()
    with contextlib.redirect_stdout(_buf):
        _res = _li(_eng)
    _out = _strip_ansi(_buf.getvalue())
    assert len(_res) == 3, "one result dict per file, grouping must not drop any"
    assert "3 files, 2 threats" in _out
    assert _out.count("Threat: Win.Malware.Example-1-0") == 1 and "(2 files)" in _out
    assert _out.count("A Windows malware signature") == 1, "explained once per threat, not per file"
    assert "real[1].bin" in _out, "paths containing [ ] must print literally"
    assert "2.0 KiB" in _out and "no longer on disk" in _out
    print("list_infected grouping test passed ✓")

    # --- pacman_report: unverified files kept apart from real mismatches ---
    from ensign_scan import reports as _rp
    from ensign_scan.pacman import PacmanMismatch as _PM, PacmanVerifyResult as _PR
    _ms = [_PM("libutempter", "/usr/lib/utempter/utempter", "GID mismatch"),
           _PM("filesystem", "/etc/shadow", "failed to calculate SHA256 checksum")]
    _ms += [_PM("rkhunter", f"/var/lib/rkhunter/db/f{i}", "Permission denied") for i in range(5)]
    _ms += [_PM("filesystem", "/etc/fstab", "Size mismatch", is_backup=True)]
    assert [m.unverified for m in _ms[:3]] == [False, True, True]
    _eng_pm = _me(f"sqlite:///{_tf.mkdtemp()}/pm.db")

    def _render(euid):
        _orig = os.geteuid
        os.geteuid = lambda: euid
        try:
            _b = io.StringIO()
            with contextlib.redirect_stdout(_b):
                _rp.pacman_report(_eng_pm, _PR(mismatches=_ms, candidate_line_count=len(_ms)))
            return " ".join(_strip_ansi(_b.getvalue()).split())
        finally:
            os.geteuid = _orig

    _user = _render(1000)
    assert "1 file differ from pacman's records" in _user, "only the GID mismatch is a real difference"
    assert "6 files pacman could not verify (not mismatches)" in _user
    assert "wasn't run as root" in _user and "sudo pacman -Qkk" in _user
    assert "rkhunter: 5 files (Permission denied)" in _user and "and 2 more" in _user
    assert "1 backup/config file" in _user
    assert "even as root" in _render(0), "a root run must not blame missing root"
    print("pacman_report unverified-split test passed ✓")

    server.shutdown()
    print("\nAll smoke tests passed ✓")


if __name__ == "__main__":
    main()
