"""Diagnostics test: --diagnostics must leak nothing personal and write nothing.

Seeds a config and a database full of identifiable values (paths under your
real home, a fake file name, hash and threat name, a host section for this
machine), runs the diagnostics report against them, and fails if any of it
shows up in the output -- or if the database was modified.

Run: python3 tests/diagnostics_test.py
"""
from __future__ import annotations

import sys as _sys_path
from pathlib import Path as _Path

# Run against THIS checkout, never an installed copy of Ensign: the tests
# live in tests/, so without this "import ensign_scan" would find whatever
# is installed (or nothing) instead of the code next to them.
ROOT = _Path(__file__).resolve().parent.parent
_sys_path.path.insert(0, str(ROOT))

import hashlib
import re
import socketserver
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from sqlalchemy.orm import Session

from ensign_scan import diagnostics
from ensign_scan.config import HOME, HOSTNAME, Config
from ensign_scan.db import make_engine
from ensign_scan.models import FileRecord, ScanStatus, utcnow

# Every seeded value contains this, so one search finds any of them.
MARK = "ENSIGNMARK"


class FakeClamd(socketserver.StreamRequestHandler):
    def handle(self):
        cmd = self.rfile.readline().decode().strip().lstrip("n")
        if cmd == "PING":
            self.wfile.write(b"PONG\n")
        elif cmd == "VERSION":
            self.wfile.write(b"ClamAV 1.5.0/27800/Wed Nov  4 08:00:00 2026\n")


def _word(needle: str) -> re.Pattern:
    """Same boundaries diagnostics._scrub() uses."""
    return re.compile(rf"(?<![\w.-]){re.escape(needle)}(?![\w.-])")


def _fingerprint(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    tmp = Path(tempfile.mkdtemp(prefix="ensign_diag_"))
    sock = tmp / "clamd.sock"
    server = socketserver.ThreadingUnixStreamServer(str(sock), FakeClamd)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    data_dir = tmp / f"{MARK}_data"
    data_dir.mkdir()  # a normal run creates this before the database
    cfg = tmp / "config.toml"
    cfg.write_text(f"""
max_workers = 4
data_dir = "{data_dir}"
clamd_socket = "{sock}"
scan_targets = ["{HOME / (MARK + '_target')}"]
excludes = ["~/.cache/{MARK}_excluded"]

[custom_secrets]
high_dirs = ["{MARK}_vault"]

[hosts."{HOSTNAME}"]
max_workers = 2
""")

    # A real database, built by the real engine, holding identifiable rows.
    config = Config.load(cfg)
    engine = make_engine(config.db_url)
    with Session(engine) as session:
        for i, status in enumerate((ScanStatus.CLEAN, ScanStatus.INFECTED, ScanStatus.ERROR)):
            path = HOME / f"{MARK}_dir" / f"{MARK}_file{i}.txt"
            session.add(FileRecord(
                filepath=str(path), filename=path.name, file_hash=f"{MARK}HASH{i}",
                scan_status=status.value, last_scanned=utcnow(),
                threat_name=f"{MARK}.Threat-1" if status is ScanStatus.INFECTED else None,
                scan_result=f"{path}: result",
            ))
        session.commit()
    engine.dispose()  # close it like a finished scan would

    db_file = data_dir / "system.db"
    before = _fingerprint(db_file)

    print("--- diagnostics report ---")
    out = diagnostics.report(str(cfg))
    print(out)

    # 1. Nothing seeded may appear: paths, file names, hashes, threat names,
    #    the data_dir, the excludes, the custom secrets entry.
    assert MARK not in out, f"a seeded value leaked: {[l for l in out.splitlines() if MARK in l]}"
    assert str(HOME) not in out, "the home path leaked"
    assert str(tmp) not in out, "a config path leaked"
    assert not _word(HOSTNAME).search(out), "the hostname leaked"
    if HOME.name != "root":
        assert not _word(HOME.name).search(out), "the username leaked"
    print("no personal values in the output ✓")

    # 2. ...while the useful, non-identifying facts are still there.
    flat = " ".join(out.split())
    assert "files tracked: 3" in flat, "database counts missing"
    assert "infected: 1" in flat and "clean: 1" in flat and "error: 1" in flat
    assert "one matches this machine: yes" in flat, "host section match missing"
    assert "max_workers: 2" in flat, "the host override should be applied"
    assert "clamd_socket: custom" in flat and "data_dir: custom" in flat
    assert "scan_targets: 1 entries" in flat and "custom_secrets: 1 entries" in flat
    assert "ClamAV 1.5.0/27800/" in flat, "clamd version missing"
    print("useful facts still reported ✓")

    # 3. Read-only: the database file itself is byte-for-byte unchanged.
    assert _fingerprint(db_file) == before, "diagnostics modified the database"
    print("database unchanged ✓")

    # 4. The safety net catches values that slip past layer 1.
    leaked = f"failed at {HOME}/x on {HOSTNAME} for {HOME.name}; ClamAV ok"
    scrubbed = diagnostics._scrub(leaked)
    assert str(HOME) not in scrubbed and not _word(HOSTNAME).search(scrubbed)
    if HOME.name != "root":
        assert not _word(HOME.name).search(scrubbed)
    assert "ClamAV ok" in scrubbed, "ordinary words must survive the scrub"
    assert "running as root" in diagnostics._scrub("running as root"), \
        "'root' identifies no one and must not be replaced"
    print("scrub safety net ✓")

    # 5. Through the real CLI: no greeting (it prints your username),
    #    clean exit, and no starter config written.
    result = subprocess.run(
        [sys.executable, "-m", "ensign_scan.cli", "--diagnostics", "--config", str(cfg)],
        capture_output=True, text=True, timeout=60, cwd=ROOT,
    )
    assert result.returncode == 0, result.stderr
    assert "Greetings" not in result.stdout, "the greeting must not run"
    assert "Ensign diagnostics" in result.stdout
    assert MARK not in result.stdout
    print("CLI --diagnostics ✓")

    server.shutdown()
    print("\nAll diagnostics tests passed ✓")


if __name__ == "__main__":
    main()
