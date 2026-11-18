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
