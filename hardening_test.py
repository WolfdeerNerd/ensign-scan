"""Regression tests for bugs found in the Nov 2026 review sweep.
Run: python3 hardening_test.py   (as your normal user)

Each test reproduces the original failure; each fails without its fix.
"""
from __future__ import annotations

import contextlib
import io
import os
import socket
import socketserver
import sqlite3
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from sqlalchemy.orm import Session

from ensign_scan.clamd import ClamdClient
from ensign_scan.db import make_engine
from ensign_scan.fsutil import open_for_scan, shown
from ensign_scan.models import FileRecord, utcnow
from ensign_scan.notify import build_message
from ensign_scan.reports import error_summary, list_infected, scan_summary
from ensign_scan.runlock import RunLock

REPO = Path(__file__).resolve().parent
tmp = Path(tempfile.mkdtemp(prefix="ensign_hardening_"))


def quietly(fn, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        result = fn(*args, **kwargs)
    return result, buf.getvalue()


# ----------------------------------------------------------------------
# 1. Scoped reports: exact directory, not LIKE wildcards or case-folding
# ----------------------------------------------------------------------
engine = make_engine(f"sqlite:///{tmp / 'scope.db'}")
inside = ["/home/w/my_docs/a.exe", "/home/w/my_docs/sub/b.exe"]
outside = ["/home/w/myXdocs/c.exe", "/home/w/My_Docs/d.exe", "/home/w/my_docs2/e.exe",
           "/home/w/my_docs"]   # a FILE named like the dir is only included when asked for exactly
with Session(engine) as s:
    for p in inside + outside:
        s.add(FileRecord(filepath=p, filename=p.rsplit("/", 1)[1], file_hash="x",
                         scan_status="infected", threat_name="Eicar", last_scanned=utcnow()))
    s.commit()
hits, _ = quietly(list_infected, engine, paths=["/home/w/my_docs/"])
got = sorted(h["filepath"] for h in hits)
assert got == sorted(inside + ["/home/w/my_docs"]), got
summary, _ = quietly(scan_summary, engine, paths=["/home/w/my_docs"])
assert summary["total"] == 3, summary
hits, _ = quietly(list_infected, engine, paths=["/"])
assert len(hits) == len(inside + outside), "'/' covers everything"
print("scope test passed ✓")

# ----------------------------------------------------------------------
# 2. Markup in names: no crash, nothing hidden
# ----------------------------------------------------------------------
assert shown("a[/b]") == "a\\[/b]"
assert shown("x[black on black]") == "x\\[black on black]"
assert shown("two\nlines") == "two\\nlines"
with Session(engine) as s:
    p = "/home/w/a[/b]/x.txt"
    s.add(FileRecord(filepath=p, filename="x.txt", file_hash="x", scan_status="error",
                     scan_result=f"{p}: odd [/red] ERROR", last_scanned=utcnow()))
    s.commit()
_, out = quietly(error_summary, engine)   # raised rich.errors.MarkupError before
assert "a[/b]" in out, out
print("markup test passed ✓")

# ----------------------------------------------------------------------
# 3. Desktop alert body: names are plain text, one line each
# ----------------------------------------------------------------------
_, body, _ = build_message({"infected": 2}, [{"filepath": "/x/<a href=evil>Clean.exe"},
                                              {"filepath": "/x/b\nInfected: 0"}])
assert "<a" not in body and "&lt;a href=evil&gt;" in body, body
assert body.count("\n") == 1, f"a name must not add lines: {body!r}"
print("notification test passed ✓")

# ----------------------------------------------------------------------
# 4 + 5. The CLI: lock respected by writing flag combos; relative targets
# ----------------------------------------------------------------------
data = tmp / "data"
data.mkdir()
cfg = tmp / "cfg.toml"
cfg.write_text(f'data_dir = "{data}"\nclamd_socket = "{tmp / "none.sock"}"\n')
make_engine(f"sqlite:///{data / 'system.db'}")
with sqlite3.connect(data / "system.db") as c:
    c.execute("INSERT INTO files (filepath, filename, file_hash, scan_status) "
              "VALUES ('/gone/file', 'file', 'x', 'error')")


def cli(*argv, cwd=REPO):
    return subprocess.run([sys.executable, str(REPO / "main.py"), "--config", str(cfg), *argv],
                          capture_output=True, text=True, cwd=cwd)


lock = RunLock(data / "ensign.lock")
lock.acquire()  # a scan is running
out = cli("--suggest-fixes", "--purge-missing")
lock.release()
assert out.returncode == 75 and "already running" in out.stdout, out.stdout[-300:]
with sqlite3.connect(data / "system.db") as c:
    assert c.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 1, "nothing purged under the lock"

home = tmp / "home"
(home / "Downloads").mkdir(parents=True)
(home / "Downloads" / "a.txt").write_text("hi")
cli("--no-scan", "--skip-rescans", "Downloads", cwd=home)
with sqlite3.connect(data / "system.db") as c:
    stored = [r[0] for r in c.execute("SELECT filepath FROM files WHERE filename = 'a.txt'")]
assert stored == [str(home / "Downloads" / "a.txt")], stored
print("cli test passed ✓")

# ----------------------------------------------------------------------
# 6. A backslash in a file name must not break the clamd reply handling
# ----------------------------------------------------------------------


class FildesFake(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        buf = b""
        while (b := sock.recv(1)) not in (b"", b"\0", b"\n"):
            buf += b
        _, fds, _, _ = socket.recv_fds(sock, 1, 1)
        os.close(fds[0])
        sock.sendall(b"fd[7]: OK\0")


sock_path = str(tmp / "fake.sock")
server = socketserver.ThreadingUnixStreamServer(sock_path, FildesFake)
threading.Thread(target=server.serve_forever, daemon=True).start()
weird = tmp / "report\\1final \\g<0>.txt"
weird.write_text("data")
fd, _ = open_for_scan(weird)
try:
    outcome = ClamdClient(sock_path).scan_fd(fd, label=str(weird))  # raised re.error before
finally:
    os.close(fd)
assert outcome.raw == f"{weird}: OK", outcome.raw
server.shutdown()
print("backslash name test passed ✓")

# ----------------------------------------------------------------------
# 7. Credential paths match whole components, never fragments
#    (a HIGH match means the file is never scanned)
# ----------------------------------------------------------------------
from ensign_scan.secrets import Confidence, classify  # noqa: E402

not_secrets = [
    "/h/notes/.bitcoin-notes/todo.md",
    "/h/Downloads/.dogecoin-memes/meme.png",
    "/h/mnt/.sshfs-cache/proj/config",
    "/h/old/.kube-backup/config",
    "/h/.config/gcloud-sdk-docs/readme.txt",
    "/h/app/.gnupg-tools/private-keys-v1.d-notes.txt",
    "/h/eth/keystore-backup/UTC--notes.txt",
]
for path in not_secrets:
    assert classify(path) != Confidence.HIGH, f"fragment match would hide {path}"
still_secrets = [
    "/h/.bitcoin/wallet.dat", "/h/.ssh/config", "/h/.kube/config",
    "/h/.gnupg/private-keys-v1.d/A.key", "/h/.config/gcloud/credentials.db",
    "/h/.ethereum/keystore/UTC--2020-01-01T00-00-00.0Z--abc",
    "/h/.kde/share/apps/kwallet/x", "/h/.local/share/kwalletd/kdewallet.kwl",
]
for path in still_secrets:
    assert classify(path) == Confidence.HIGH, f"real credential path missed: {path}"
print("whole-component secrets test passed ✓")

# ----------------------------------------------------------------------
# 8. Snapshot roots: "/snaps" is not "/snaps2"
# ----------------------------------------------------------------------
from ensign_scan.config import Config  # noqa: E402
from ensign_scan.scanner import Scanner  # noqa: E402

snap = Scanner(Config(db_url=f"sqlite:///{tmp / 'snap.db'}", log_file=tmp / "snap.log",
                      snapshot_roots=("/x/snaps/",)))
assert snap._is_snapshot_dir(Path("/x/snaps")) and snap._is_snapshot_dir(Path("/x/snaps/1/a"))
assert not snap._is_snapshot_dir(Path("/x/snaps2/a")), "a sibling sharing the prefix is not a snapshot root"
print("snapshot root test passed ✓")

print("\nAll hardening tests passed ✓")
