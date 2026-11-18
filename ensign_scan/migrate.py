"""Move the pre-0.8.1 folders to their new names, when that's clearly safe.

Before 0.8.1 the config and data folders were named just "ensign"; they're
now "ensign-scan" (see config.LEGACY_*). This moves an old folder to its new
name at the start of a run, but only when every check below passes. When
any check fails, nothing is moved and the run keeps using the old folder,
printing how to move it by hand (config.legacy_notice).

The checks, and why each one is there:

  * The new folder doesn't exist yet. Never merge two folders: whichever
    one "wins", the other's files would be lost or mixed in.
  * The old folder is Ensign's and only Ensign's. Avoiding a collision with
    another program's folder is the reason for the rename, so moving
    another program's "ensign" folder would cause exactly the harm it is
    meant to prevent. Every entry must be a name Ensign creates; one
    unknown file and the folder stays put.
  * This run would really use the old folder: no --config/$ENSIGN_CONFIG
    naming the old config, and no data_dir setting. A config that names the
    old data folder would make the very next run create an empty database
    there and quietly lose the scan history.
  * No other Ensign run is going: take its own run lock in the old folder
    first, and hold it through the move.
  * One os.rename() per folder, never a copy. A rename is atomic -- the
    folder is entirely in the old place or entirely in the new one -- and it
    carries the database's -wal/-shm files with it. A rename across two
    filesystems fails (EXDEV); that's left to the by-hand notice too.
"""
from __future__ import annotations

import errno
import os
import sqlite3
import tomllib
from pathlib import Path

from . import config as cfg
from .runlock import AlreadyRunning, RunLock

# What Ensign creates in each folder. Anything else means "not only ours".
_CONFIG_NAMES = ("config.toml",)
_DATA_NAMES = {"system.db", "system.db-wal", "system.db-shm", "system.db-journal", "logs", "yara",
               "persistence_acknowledged.log", "alert_state.json", "ensign.lock", "error_logs.txt"}
# Created only by Ensign; at least one must be there besides the database.
_DATA_MARKERS = ("ensign.lock", "logs", "yara", "persistence_acknowledged.log", "alert_state.json")


def _config_is_ensigns(folder: Path) -> bool:
    """Only config.toml (or an editor's backup of it), and it holds only
    Ensign's settings."""
    try:
        entries = list(folder.iterdir())
    except OSError:
        return False
    if not all(e.is_file() and not e.is_symlink() and e.name.startswith(_CONFIG_NAMES) for e in entries):
        return False
    try:
        with open(folder / "config.toml", "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return False
    hosts = data.pop("hosts", {})
    if not isinstance(hosts, dict) or not all(isinstance(h, dict) for h in hosts.values()):
        return False
    keys = set(data).union(*(h.keys() for h in hosts.values()))
    return keys <= cfg.KNOWN_SETTINGS


def _data_is_ensigns(folder: Path) -> bool:
    """Only names Ensign creates, a system.db with Ensign's tables, and at
    least one other file only Ensign makes."""
    try:
        names = {e.name for e in folder.iterdir()}
    except OSError:
        return False
    if not names <= _DATA_NAMES or "system.db" not in names:
        return False
    if not any(m in names for m in _DATA_MARKERS):
        return False
    db = folder / "system.db"
    if db.is_symlink() or not db.is_file():
        return False
    try:
        # Read-only: this check must never change the database it's checking.
        conn = sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True, timeout=1)
        try:
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            conn.close()
    except sqlite3.Error:
        return False
    return {"files", "directories"} <= tables


def _settings(path: Path) -> dict:
    """The settings a config file sets for this machine (top level plus its
    [hosts.<hostname>] section); empty if it can't be read."""
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    host = data.get("hosts", {})
    host = host.get(cfg.HOSTNAME, {}) if isinstance(host, dict) else {}
    return {**data, **(host if isinstance(host, dict) else {})}


def _rename(old: Path, new: Path) -> str | None:
    """Rename; None if it worked, else why not."""
    try:
        os.rename(old, new)
    except OSError as exc:
        if exc.errno == errno.EXDEV:
            return f"{cfg._tilde(new)}/ would be on a different filesystem"
        return f"renaming {cfg._tilde(old)}/ failed ({exc.strerror})"
    return None


def move_legacy_folders(explicit_config: str | None) -> tuple[list[str], list[str]]:
    """Move whichever old folders pass every check.

    Returns (moved, not_moved): a line for each folder moved, and for each
    old folder that's still there, why it wasn't. Both are empty when there
    are no old folders.
    """
    explicit = explicit_config or os.environ.get("ENSIGN_CONFIG")
    old_cfg_dir, new_cfg_dir = cfg.LEGACY_CONFIG_PATH.parent, cfg.DEFAULT_CONFIG_PATH.parent
    old_data, new_data = cfg.LEGACY_DATA_DIR, cfg.DEFAULT_DATA_DIR
    moved: list[str] = []
    not_moved: list[str] = []
    have_old_cfg = old_cfg_dir.is_dir() and not old_cfg_dir.is_symlink()
    have_old_data = old_data.is_dir() and not old_data.is_symlink()
    if not (have_old_cfg or have_old_data):
        return moved, not_moved

    def names_old_config(path: str) -> bool:
        try:
            return Path(path).resolve() == cfg.LEGACY_CONFIG_PATH.resolve()
        except OSError:
            return True   # can't tell: don't move it out from under this run
    if explicit and names_old_config(explicit):
        # This run asked for the old file by name; moving it would break the run.
        how = "--config" if explicit_config else "$ENSIGN_CONFIG"
        not_moved.append(f"{how} names the old config file")
        return moved, not_moved

    # -- the config folder --------------------------------------------------
    if have_old_cfg:
        if new_cfg_dir.exists():
            pass   # both exist: the new one is used; the old one is just left over
        elif not _config_is_ensigns(old_cfg_dir):
            not_moved.append(f"{cfg._tilde(old_cfg_dir)}/ holds something besides Ensign's config.toml")
        elif (why := _rename(old_cfg_dir, new_cfg_dir)) is not None:
            not_moved.append(why)
        else:
            moved.append(f"  config: {cfg._tilde(old_cfg_dir)}/ -> {cfg._tilde(new_cfg_dir)}/")

    # -- the data folder ----------------------------------------------------
    if not have_old_data or new_data.exists():
        return moved, not_moved
    config_path = Path(explicit) if explicit else cfg.default_config_path()
    if "data_dir" in _settings(config_path):
        # The data folder is the config's call. If it names the old folder, the
        # notice says to change it; if it names another, the old one isn't used.
        if Path(cfg._expand(_settings(config_path)["data_dir"])) == old_data:
            not_moved.append("your config's data_dir names the old folder")
        return moved, not_moved
    if not _data_is_ensigns(old_data):
        not_moved.append(f"{cfg._tilde(old_data)}/ holds files Ensign doesn't create")
        return moved, not_moved
    lock = RunLock(old_data / "ensign.lock")
    try:
        lock.acquire()
    except AlreadyRunning:
        not_moved.append("another Ensign run was going (it'll be moved on a later run)")
        return moved, not_moved
    except OSError as exc:
        not_moved.append(f"couldn't take the run lock ({exc.strerror})")
        return moved, not_moved
    try:
        # flock follows the open file, not its path, so the lock stays held
        # while its folder is renamed.
        if (why := _rename(old_data, new_data)) is not None:
            not_moved.append(why)
        else:
            moved.append(f"  data:   {cfg._tilde(old_data)}/ -> {cfg._tilde(new_data)}/")
    finally:
        lock.release()
    return moved, not_moved
