"""--list-infected and --list-allowed, read straight from the database.

A database is filled by hand (no clamd needed), with HOME pointed at a
temporary folder. Checked:

  * --list-infected lists every infected file (no "and N more" cut-off),
    each with the SHA-256 of the content that was flagged; a file in a
    personal folder gets "look up the hash, don't upload the file"; each
    threat ends by pointing to --clamav-report; and it scans nothing.
  * --list-allowed shows a folder once, with each signature allowed there
    and how many files it allowed, plus the files in it that are infected
    now and not allowed. The files a folder covers aren't listed again.
  * A file allowed for two signatures is one entry with both, even though
    the database keeps only the latest signature on the file itself.
  * Allowed content that isn't on disk now is listed apart, where it was.

    python3 tests/listviews_test.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FILL = r"""
import os, sys, datetime as dt
sys.path.insert(0, sys.argv[1])
from sqlalchemy.orm import Session
from ensign_scan.config import Config, HOME
from ensign_scan.db import make_engine
from ensign_scan.models import Allowance, AllowedFolder, FileRecord
c = Config.load()
c.data_dir.mkdir(parents=True, exist_ok=True)
H, t = str(HOME), dt.datetime(2026, 11, 1, 12)

def rec(path, status, threat, digest):
    return FileRecord(filepath=path, filename=os.path.basename(path), file_hash=digest,
                      scan_status=status, threat_name=threat, last_scanned=t, scan_result=f"{threat} FOUND")

with Session(make_engine(c.db_url)) as s:
    game = f"{H}/Games/foo"
    for i in range(3):
        s.add(rec(f"{game}/a{i}.js", "allowed", "Js.Downloader.X", f"{i}" * 64))
        s.add(Allowance(file_hash=f"{i}" * 64, threat_name="Js.Downloader.X", filepath=f"{game}/a{i}.js", allowed_at=t))
    s.add(AllowedFolder(folder=game, threat_name="Js.Downloader.X", allowed_at=t, last_allowed_at=t))
    s.add(rec(f"{game}/new.js", "infected", "Js.Downloader.Y", "n" * 64))
    # one content, two signatures allowed on it; the record keeps the latest
    s.add(rec(f"{H}/Downloads/tool.exe", "allowed", "Win.Packed.Generic-1", "t" * 64))
    for sig in ("Win.Packed.Generic-1", "PUA.Win.Tool.Foo"):
        s.add(Allowance(file_hash="t" * 64, threat_name=sig, filepath=f"{H}/Downloads/tool.exe", allowed_at=t))
    s.add(Allowance(file_hash="g" * 64, threat_name="Win.Old.Thing", filepath=f"{H}/old/x.bin", allowed_at=t))
    s.add(rec(f"{H}/Downloads/evil.exe", "infected", "Win.Trojan.Evil", "e" * 64))
    for i in range(30):   # more than the end-of-scan list shows per threat
        s.add(rec(f"/opt/lib/many{i:02}.so", "infected", "Win.Trojan.Evil", f"{i + 100:064}"))
    s.commit()
"""

with tempfile.TemporaryDirectory() as d:
    env = {k: v for k, v in os.environ.items() if k not in ("SUDO_USER", "ENSIGN_CONFIG")}
    env.update(HOME=d, COLUMNS="200")
    subprocess.run([sys.executable, "-c", FILL, str(ROOT)], env=env, check=True, stdin=subprocess.DEVNULL)

    def ensign(*args: str) -> str:
        out = subprocess.run([sys.executable, str(ROOT / "main.py"), *args], env=env, capture_output=True,
                             text=True, stdin=subprocess.DEVNULL, timeout=120)
        assert out.returncode == 0, out.stdout + out.stderr
        return out.stdout

    # --- --list-infected --------------------------------------------------------------------------
    out = ensign("--list-infected")
    flat = " ".join(out.split())
    assert "INFECTED FILES (32 files, 2 threats)" in flat, flat
    assert "more files with this threat" not in flat and "many29.so" in flat, "cut short"
    assert f"SHA-256: {'e' * 64}" in flat and f"SHA-256: {129:064}" in flat, flat
    evil = out[out.index("Downloads/evil.exe"):].split("File:")[0]
    assert "don't upload the file" in evil, evil
    many = out[out.index("many00.so"):].split("File:")[0]
    assert "don't upload" not in many, "only personal folders get the upload warning"
    assert flat.count("--clamav-report PATH") == 2, "one pointer per threat"
    assert "Scanning" not in out and "scanned so far" not in flat, "it must not scan"

    scoped = " ".join(ensign("--list-infected", f"{d}/Games").split())
    assert "INFECTED FILES (1 files, 1 threat)" in scoped and "evil.exe" not in scoped, scoped

    # --- --list-allowed -----------------------------------------------------------------------------
    flat = " ".join(ensign("--list-allowed").split())
    assert "FOLDERS YOU ALLOWED (1)" in flat and "Js.Downloader.X 3 files allowed" in flat, flat
    assert "a0.js" not in flat, "a folder's files are counted under it, not listed again"
    assert "1 file here is infected now and not allowed" in flat, flat
    assert "FILES YOU ALLOWED (1)" in flat, flat
    tool = flat[flat.index("Downloads/tool.exe"):]
    assert "PUA.Win.Tool.Foo allowed 2026-11-01 Win.Packed.Generic-1 allowed 2026-11-01" in tool, tool
    assert f"SHA-256: {'t' * 64}" in tool, tool
    assert "ALLOWED, BUT NOT ON DISK NOW (1)" in flat and "old/x.bin" in flat, flat

print("list views test passed ✓")
