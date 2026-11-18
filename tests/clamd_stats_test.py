"""Reading clamd's MaxThreads (the STATS reply), which sizes the workers.

STATS is several lines, closed by "END". A busy clamd writes it a few
lines at a time. Ensign used to stop reading at the first piece that ended
in a newline, so it never saw the THREADS line, decided MaxThreads was
unknown, and quietly fell back to 5 workers. Checked here, with a fake
clamd on a Unix socket:

  * STATS written in pieces is read whole, and MaxThreads comes through;
  * a reply that ends without "END" (the connection just closes) still works;
  * the worker count follows MaxThreads, and the fallback is used only when
    clamd really doesn't say.

    python3 tests/clamd_stats_test.py
"""
from __future__ import annotations

import sys as _sys_path
from pathlib import Path as _Path

# Run against THIS checkout, never an installed copy of Ensign.
ROOT = _Path(__file__).resolve().parent.parent
_sys_path.path.insert(0, str(ROOT))

import os  # noqa: E402
import socket  # noqa: E402
import tempfile  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

from ensign_scan import scanner as scanner_mod  # noqa: E402
from ensign_scan.clamd import ClamdClient  # noqa: E402
from ensign_scan.config import Config  # noqa: E402
from ensign_scan.scanner import Scanner  # noqa: E402

STATS = [b"POOLS: 1\n\n", b"STATE: VALID PRIMARY\n",
         b"THREADS: live 9  idle 3 max 12 idle-timeout 30\n",
         b"QUEUE: 0 items\n\tSTATS 0.000004 \n\n", b"MEMSTATS: heap 1.2M mmap 0.0M\n", b"END\n"]


def fake_clamd(path: str, parts: list[bytes], pause: float = 0.02) -> None:
    """Answer one connection with `parts`, one write each, with a pause between."""
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    srv.listen(1)

    def serve() -> None:
        conn, _ = srv.accept()
        conn.recv(100)
        for part in parts:
            conn.sendall(part)
            time.sleep(pause)
        conn.close()
        srv.close()

    threading.Thread(target=serve, daemon=True).start()


with tempfile.TemporaryDirectory() as d:
    # --- written in pieces, the way a busy clamd does ----------------------------------------------
    sock = os.path.join(d, "a.ctl")
    fake_clamd(sock, STATS)
    assert ClamdClient(sock).max_threads() == 12, "STATS cut short at the first newline"

    # --- no END: the connection just closes -------------------------------------------------------
    sock = os.path.join(d, "b.ctl")
    fake_clamd(sock, STATS[:-1])
    assert ClamdClient(sock).max_threads() == 12

    # --- the workers follow it ------------------------------------------------------------------------
    class Fake:
        def __init__(self, max_threads):
            self._max = max_threads

        def max_threads(self):
            return self._max

    cfg = Config(db_url=f"sqlite:///{d}/s.db", log_file=Path(d, "l.txt"), max_workers=0, cpu_share=100)
    saved = scanner_mod.os.cpu_count
    scanner_mod.os.cpu_count = lambda: 32
    try:
        assert Scanner(cfg, clamd=Fake(12)).workers == 10, "MaxThreads 12, minus 2 headroom"
        unknown = Scanner(cfg, clamd=Fake(None))
        assert unknown.workers == 5 and unknown.clamd_max_threads is None, "the fallback, only when unknown"
    finally:
        scanner_mod.os.cpu_count = saved

print("clamd STATS test passed ✓")
