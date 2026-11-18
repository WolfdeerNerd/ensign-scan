"""The folder rename in 0.8.1: ~/.config/ensign -> ~/.config/ensign-scan,
~/.local/share/ensign -> ~/.local/share/ensign-scan.

Each case runs in a fresh Python with HOME pointed at a temporary folder, so
the real home is never touched. Checked:

  * nothing old on disk: the new folders are used, the starter config goes
    to the new place, and there's no notice;
  * only the old folders: they're still used (the settings and the
    database aren't lost), no starter config is written over them, and the
    notice gives the mv commands;
  * old and new both there: the new ones win and there's no notice;
  * data_dir set to the old folder in the config: the notice also says to
    change that line;
  * a real run prints the notice twice: at the start and at the end.

Then the automatic move (migrate.py): both folders move, database intact,
when every check passes; and nothing moves when the old folder holds a file
Ensign doesn't make, the config has a setting Ensign doesn't have, the
database lacks Ensign's tables, another run holds the lock, data_dir names
the old folder, --config or $ENSIGN_CONFIG names the old file, or the new
folder already exists.

    python3 tests/legacy_paths_test.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PROBE = """
import sys
sys.path.insert(0, sys.argv[1])
from ensign_scan.config import Config, ensure_default_config, legacy_notice
ensure_default_config()
c = Config.load()
print("CONFIG", c.source)
print("DATA", c.data_dir)
print("NOTICE", repr(legacy_notice(c)))
"""


def probe(home: Path) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in ("SUDO_USER", "ENSIGN_CONFIG")}
    env["HOME"] = str(home)
    out = subprocess.run([sys.executable, "-c", PROBE, str(ROOT)], env=env, capture_output=True,
                         text=True, check=True, stdin=subprocess.DEVNULL).stdout
    got = {}
    for line in out.splitlines():
        key, _, value = line.partition(" ")
        if key in ("CONFIG", "DATA", "NOTICE"):
            got[key] = value
    return got


def tree(home: Path, *, old_config=False, old_data=False, new_config=False, new_data=False,
         config_text="max_workers = 0\n") -> None:
    if old_config:
        (home / ".config/ensign").mkdir(parents=True)
        (home / ".config/ensign/config.toml").write_text(config_text)
    if old_data:
        (home / ".local/share/ensign").mkdir(parents=True)
        (home / ".local/share/ensign/system.db").write_bytes(b"")
    if new_config:
        (home / ".config/ensign-scan").mkdir(parents=True)
        (home / ".config/ensign-scan/config.toml").write_text("max_workers = 0\n")
    if new_data:
        (home / ".local/share/ensign-scan").mkdir(parents=True)


with tempfile.TemporaryDirectory() as d:
    # --- nothing old ------------------------------------------------------------------------------
    home = Path(d, "fresh")
    home.mkdir()
    got = probe(home)
    assert got["CONFIG"] == str(home / ".config/ensign-scan/config.toml"), got
    assert got["DATA"] == str(home / ".local/share/ensign-scan"), got
    assert got["NOTICE"] == "None", got
    assert not (home / ".config/ensign").exists(), "made an old folder"

    # --- only the old folders ------------------------------------------------------------------
    home = Path(d, "old")
    home.mkdir()
    tree(home, old_config=True, old_data=True)
    got = probe(home)
    assert got["CONFIG"] == str(home / ".config/ensign/config.toml"), got
    assert got["DATA"] == str(home / ".local/share/ensign"), got
    assert not (home / ".config/ensign-scan").exists(), "a starter config would hide the old one"
    notice = eval(got["NOTICE"])
    assert "mv ~/.config/ensign ~/.config/ensign-scan" in notice, notice
    assert "mv ~/.local/share/ensign ~/.local/share/ensign-scan" in notice, notice
    assert str(home) not in notice, "the notice should show ~, not the home path"

    # --- old data only, no config anywhere -------------------------------------------------------
    home = Path(d, "olddata")
    home.mkdir()
    tree(home, old_data=True)
    (home / ".config/ensign-scan").mkdir(parents=True)   # ensure_default_config would write here
    got = probe(home)
    assert got["DATA"] == str(home / ".local/share/ensign"), got
    notice = eval(got["NOTICE"])
    assert "data:" in notice and "config:" not in notice, notice

    # --- both old and new: the new ones win, no notice ---------------------------------------
    home = Path(d, "both")
    home.mkdir()
    tree(home, old_config=True, old_data=True, new_config=True, new_data=True)
    got = probe(home)
    assert got["CONFIG"] == str(home / ".config/ensign-scan/config.toml"), got
    assert got["DATA"] == str(home / ".local/share/ensign-scan"), got
    assert got["NOTICE"] == "None", got

    # --- data_dir names the old folder ---------------------------------------------------------
    home = Path(d, "setdir")
    home.mkdir()
    tree(home, old_data=True, new_config=True)
    (home / ".config/ensign-scan/config.toml").write_text('data_dir = "~/.local/share/ensign"\n')
    got = probe(home)
    notice = eval(got["NOTICE"])
    assert 'change data_dir in your config to "~/.local/share/ensign-scan"' in notice, notice

    # --- a real run: start and end -----------------------------------------------------------------
    home = Path(d, "run")
    home.mkdir()
    tree(home, old_config=True, old_data=True)
    env = {k: v for k, v in os.environ.items() if k not in ("SUDO_USER", "ENSIGN_CONFIG")}
    env.update(HOME=str(home), COLUMNS="200")
    out = subprocess.run([sys.executable, str(ROOT / "main.py"), "--list-allowed"], env=env,
                         capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)
    text = out.stdout + out.stderr
    assert text.count("Ensign's folders are now named ensign-scan") == 2, text

print("legacy paths test passed ✓")


# ======================================================================
# The automatic move (migrate.py)
# ======================================================================
import sqlite3  # noqa: E402
import fcntl  # noqa: E402

MOVE = """
import sys
sys.path.insert(0, sys.argv[1])
from ensign_scan import migrate
moved, not_moved = migrate.move_legacy_folders(sys.argv[2] or None)
print("MOVED", repr(moved))
print("NOT", repr(not_moved))
"""


def move(home: Path, explicit: str = "", env_extra: dict | None = None) -> tuple[list, list]:
    env = {k: v for k, v in os.environ.items() if k not in ("SUDO_USER", "ENSIGN_CONFIG")}
    env["HOME"] = str(home)
    env.update(env_extra or {})
    out = subprocess.run([sys.executable, "-c", MOVE, str(ROOT), explicit], env=env, capture_output=True,
                         text=True, check=True, stdin=subprocess.DEVNULL).stdout
    got = dict(line.split(" ", 1) for line in out.splitlines() if line.startswith(("MOVED", "NOT")))
    return eval(got["MOVED"]), eval(got["NOT"])


def ensign_tree(home: Path, *, config_text: str = "max_workers = 0\n") -> None:
    """Old folders as Ensign really leaves them: a database with its tables
    and a row, the lock, a log folder."""
    (home / ".config/ensign").mkdir(parents=True)
    (home / ".config/ensign/config.toml").write_text(config_text)
    data = home / ".local/share/ensign"
    (data / "logs").mkdir(parents=True)
    conn = sqlite3.connect(data / "system.db")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE files (filepath TEXT)")
    conn.execute("CREATE TABLE directories (path TEXT)")
    conn.execute("INSERT INTO files VALUES ('/x')")
    conn.commit()
    conn.close()
    (data / "ensign.lock").write_text("")


def rows(db: Path) -> int:
    conn = sqlite3.connect(db)
    try:
        return conn.execute("SELECT count(*) FROM files").fetchone()[0]
    finally:
        conn.close()


with tempfile.TemporaryDirectory() as d:
    # --- the normal case: both move, the database comes along whole -----------------------------
    home = Path(d, "ok")
    home.mkdir()
    ensign_tree(home)
    moved, not_moved = move(home)
    assert len(moved) == 2 and not not_moved, (moved, not_moved)
    assert not (home / ".config/ensign").exists() and not (home / ".local/share/ensign").exists()
    assert (home / ".config/ensign-scan/config.toml").read_text() == "max_workers = 0\n"
    assert rows(home / ".local/share/ensign-scan/system.db") == 1
    assert move(home) == ([], []), "a second run has nothing left to do"

    # --- a file Ensign doesn't make: not ours alone, stays put ---------------------------------
    home = Path(d, "foreign")
    home.mkdir()
    ensign_tree(home)
    (home / ".local/share/ensign/someone-elses.dat").write_text("x")
    (home / ".config/ensign/other.ini").write_text("x")
    moved, not_moved = move(home)
    assert moved == [] and len(not_moved) == 2, (moved, not_moved)
    assert (home / ".local/share/ensign/someone-elses.dat").exists()

    # --- a config with a setting Ensign doesn't have: not Ensign's ------------------------------
    home = Path(d, "otherconfig")
    home.mkdir()
    ensign_tree(home, config_text='theme = "dark"\n')
    moved, not_moved = move(home)
    assert (home / ".config/ensign/config.toml").exists(), "moved a config that isn't Ensign's"
    assert any("config.toml" in w for w in not_moved), not_moved

    # --- a database without Ensign's tables ------------------------------------------------------
    home = Path(d, "otherdb")
    home.mkdir()
    ensign_tree(home)
    conn = sqlite3.connect(home / ".local/share/ensign/system.db")
    conn.execute("DROP TABLE files")
    conn.commit()
    conn.close()
    moved, not_moved = move(home)
    assert (home / ".local/share/ensign").exists() and any("doesn't create" in w for w in not_moved)

    # --- another run holds the lock ------------------------------------------------------------------
    home = Path(d, "busy")
    home.mkdir()
    ensign_tree(home)
    fd = os.open(home / ".local/share/ensign/ensign.lock", os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        moved, not_moved = move(home)
    finally:
        os.close(fd)
    assert (home / ".local/share/ensign/system.db").exists(), "moved the data under a running scan"
    assert any("another Ensign run" in w for w in not_moved), not_moved

    # --- data_dir names the old folder: the next run would start an empty database ----------
    home = Path(d, "datadir")
    home.mkdir()
    ensign_tree(home, config_text='data_dir = "~/.local/share/ensign"\n')
    moved, not_moved = move(home)
    assert (home / ".local/share/ensign").exists() and any("data_dir" in w for w in not_moved)

    # --- --config / $ENSIGN_CONFIG names the old file: nothing moves ----------------------------
    for explicit, extra in ((str(Path(d, "byflag/.config/ensign/config.toml")), {}),
                            ("", {"ENSIGN_CONFIG": str(Path(d, "byenv/.config/ensign/config.toml"))})):
        home = Path(d, "byflag" if explicit else "byenv")
        home.mkdir()
        ensign_tree(home)
        moved, not_moved = move(home, explicit, extra)
        assert moved == [] and (home / ".config/ensign").exists() and (home / ".local/share/ensign").exists()

    # --- the new folder already exists: never merged ---------------------------------------------
    home = Path(d, "both2")
    home.mkdir()
    ensign_tree(home)
    (home / ".local/share/ensign-scan").mkdir(parents=True)
    moved, not_moved = move(home)
    assert (home / ".local/share/ensign/system.db").exists() and not any("data" in m for m in moved)

    # --- end to end: a real database made by Ensign, then renamed back to the old names -----
    home = Path(d, "real")
    home.mkdir()
    env = {k: v for k, v in os.environ.items() if k not in ("SUDO_USER", "ENSIGN_CONFIG")}
    env.update(HOME=str(home), COLUMNS="200")
    run = [sys.executable, str(ROOT / "main.py"), "--list-allowed"]
    subprocess.run(run, env=env, capture_output=True, stdin=subprocess.DEVNULL, timeout=120)
    assert (home / ".local/share/ensign-scan/system.db").exists()
    os.rename(home / ".config/ensign-scan", home / ".config/ensign")
    os.rename(home / ".local/share/ensign-scan", home / ".local/share/ensign")
    (home / ".local/share/ensign/ensign.lock").write_text("")  # a scan would have left it
    out = subprocess.run(run, env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)
    text = out.stdout + out.stderr
    assert "Moved Ensign's folders" in text and "now named ensign-scan" not in text, text
    assert (home / ".local/share/ensign-scan/system.db").exists() and not (home / ".local/share/ensign").exists()

# --- every name the code puts in the data folder is one the move knows -----------------------
import re  # noqa: E402

sys.path.insert(0, str(ROOT))
from ensign_scan import bigrules, migrate  # noqa: E402

source = "\n".join(p.read_text() for p in (ROOT / "ensign_scan").rglob("*.py"))
written = set(re.findall(r'data_dir\)?\s*/\s*["\']([^"\'/]+)["\']', source))
written |= {bigrules.RULES_DIRNAME, "logs", "system.db"}
assert written, "the pattern found nothing: it's out of date"
missing = written - migrate._DATA_NAMES
assert not missing, f"Ensign writes these to the data folder, but the move doesn't know them: {missing}"

with tempfile.TemporaryDirectory() as d:   # and a folder with reports in it still moves
    home = Path(d)
    ensign_tree(home)
    (home / ".local/share/ensign/clamav-reports").mkdir()
    moved, not_moved = move(home)
    assert len(moved) == 2 and not not_moved, (moved, not_moved)

print("automatic move test passed ✓")
