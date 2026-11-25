"""Protected mode: your config and your decisions, kept where only root can write.

Without it, your config (~/.config/ensign-scan/config.toml) and the
decisions in your database (allowances, folder allowances, acknowledged
startup entries) belong to you, so any program running as you can change
them: exclude its own folder, point clamd_socket elsewhere, allow its own
file, acknowledge its own startup entry. A check that *reads* your state
can't catch that, because such a program controls that state and can see
when root reads it. The fix is to stop your user from *writing* it.

`sudo ensign-scan --protect` copies your config, after showing it to you,
to a file root owns, and creates an empty decisions file next to it
(nothing is carried over from your database: root never parses a file you
can write). From then on your own runs:

  * load root's copy of the config, never ~/.config/ensign-scan/config.toml,
    and refuse --config and $ENSIGN_CONFIG;
  * read allowances, folder allowances and acknowledgments from root's
    decisions file (db.make_engine attaches it read-only and puts it in
    front of your own tables);
  * check both files first with trust.untrusted_reason(): owned by root,
    in folders only root can change. If that fails, the run stops. It
    never falls back to your own files, which is what an attacker would want.

Layout, for user <uid>:

    /etc/ensign-scan/users/<uid>/config.toml        (0600 + read for <uid>)
    /var/lib/ensign-scan/users/<uid>/decisions.db   (0600 + read for <uid>)

Each <uid> folder is 0700 plus search (x) for <uid> only, through a POSIX
ACL (acl.py): nobody else can read either file. The folders above it are
0711, so anyone can pass through and nobody can list them. That way your
runs can always tell whether you're protected: if the <uid> folder exists
but can't be entered (its ACL was lost, say in a restore that didn't keep
extended attributes), the run stops with the reason instead of quietly
using your own config again.

Root's own runs (sudo) keep their own config, database and decisions, as
before: a sudo run stays an independent check.
"""
from __future__ import annotations

import logging
import os
import shutil
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path

from . import acl, trust

log = logging.getLogger(__name__)

CONFIG_ROOT = Path("/etc/ensign-scan")
DATA_ROOT = Path("/var/lib/ensign-scan")

# The tables that hold decisions, and live in root's decisions file in
# protected mode. Everything else (the verdict for each file) stays yours.
DECISION_TABLES = ("allowances", "allowed_folders", "persistence_entries")


class Unsafe(Exception):
    """You are protected, but root's copies can't be used as they are."""


class CantProtect(Exception):
    """--protect / --unprotect can't go ahead (the reason is the message)."""


@dataclass(frozen=True)
class Protected:
    config: Path
    decisions: Path


def config_dir(uid: int) -> Path:
    return CONFIG_ROOT / "users" / str(uid)


def data_dir(uid: int) -> Path:
    return DATA_ROOT / "users" / str(uid)


def config_path(uid: int) -> Path:
    return config_dir(uid) / "config.toml"


def decisions_path(uid: int) -> Path:
    return data_dir(uid) / "decisions.db"


# ----------------------------------------------------------------------
# Your runs: are you protected, and are root's copies safe to use?
# ----------------------------------------------------------------------

def status(uid: int | None = None) -> Protected | None:
    """For a run as an ordinary user: root's copies if you're protected,
    None if you aren't. Raises Unsafe if you are, but they can't be used."""
    uid = os.geteuid() if uid is None else uid
    try:
        os.lstat(config_dir(uid))
    except (FileNotFoundError, NotADirectoryError):
        return None
    except PermissionError:
        # /etc/ensign-scan or its users folder can't be passed through: only
        # root can set that up, and --protect makes them 0711. Nobody on this
        # machine has run --protect.
        return None
    except OSError as exc:   # anything else (a symlink loop, an I/O error): fail closed
        raise Unsafe(f"couldn't check whether you are protected ({config_dir(uid)}): "
                     f"{exc.strerror or exc}") from None
    found = Protected(config_path(uid), decisions_path(uid))
    for what, path in (("config", found.config), ("decisions file", found.decisions)):
        try:
            st = os.lstat(path)
        except PermissionError:
            raise Unsafe(f"you are protected, but your user can't reach root's copy of your {what} "
                         f"({path}): the permission that lets you read it is missing. Run "
                         f"sudo ensign-scan --unprotect, then sudo ensign-scan --protect again.") from None
        except FileNotFoundError:
            raise Unsafe(f"you are protected, but root's copy of your {what} ({path}) is missing. "
                         f"Run sudo ensign-scan --unprotect, then sudo ensign-scan --protect "
                         f"again.") from None
        except OSError as exc:
            raise Unsafe(f"you are protected, but root's copy of your {what} ({path}) can't be "
                         f"checked: {exc.strerror or exc}") from None
        if not stat.S_ISREG(st.st_mode):
            raise Unsafe(f"{path} isn't a regular file")
        why = trust.untrusted_reason(path)
        if why:
            raise Unsafe(f"root's copy of your {what} isn't safe to use: {why}")
    _check_readable(found)
    return found


def _check_readable(found: Protected) -> None:
    try:
        with open(found.config, "rb"):
            pass
        # mode=ro: never create a journal in root's folder. A run that can't
        # read the decisions stops here, before anything is scanned.
        conn = sqlite3.connect(f"file:{found.decisions}?mode=ro", uri=True)
        try:
            missing = missing_columns(conn)
            if missing:
                # A newer Ensign than the one that made the file: its
                # queries would fail with "no such column" mid-run.
                what = "; ".join(f"{t} has no {', '.join(c)}" for t, c in missing.items())
                if upgradable(missing):
                    raise Unsafe(f"root's copy of your decisions was made by an older Ensign "
                                 f"({what}), and only root can upgrade it. Run any sudo command "
                                 f"once, and it's upgraded: sudo ensign-scan --list-allowed")
                raise Unsafe(f"root's copy of your decisions was made by an older Ensign ({what}), "
                             f"and this version can't upgrade it: report it as a bug.")
            for table, columns in _expected_columns().items():
                conn.execute(f"SELECT {', '.join(columns)} FROM {table} LIMIT 1").fetchall()
        finally:
            conn.close()
    except (OSError, sqlite3.Error) as exc:
        if os.path.lexists(f"{found.decisions}-journal"):
            # Root stopped partway through changing them (a crash, Ctrl+C at
            # the wrong moment): the half-made change can only be undone by
            # root, which SQLite does the next time root opens the file.
            raise Unsafe("root was interrupted while changing your protected decisions, and only "
                         "root can finish undoing that. Run any sudo command on them, for example: "
                         "sudo ensign-scan --protected --persistence") from None
        raise Unsafe(f"you are protected, but root's copies can't be read: {exc}") from None


def upgrade_all() -> list[int]:
    """Bring every protected decisions file up to this version's tables
    (db.upgrade_decision_tables). Run by root at the start of every sudo
    run, so a protected user's runs, which can't upgrade root's file and
    stop until it's done, need nothing more than any sudo command. Returns
    the uids whose file changed. A file that isn't safe to use is left
    alone: the user's runs report it."""
    from sqlalchemy import create_engine

    from .db import upgrade_decision_tables
    if os.geteuid() != 0:
        return []
    try:
        folders = sorted((DATA_ROOT / "users").iterdir())
    except OSError:
        return []   # nobody is protected here
    changed = []
    for folder in folders:
        path = folder / "decisions.db"
        if not folder.name.isdigit() or not path.is_file() or trust.untrusted_reason(path):
            continue
        engine = create_engine(f"sqlite:///{path}", connect_args={"timeout": 30})
        try:
            with engine.begin() as conn:
                conn.exec_driver_sql("PRAGMA journal_mode=DELETE")
                if upgrade_decision_tables(conn):
                    changed.append(int(folder.name))
        except Exception as exc:  # e.g. another sudo run upgrading it at the same moment
            # Nothing is lost: the rebuild is one transaction, and the
            # user's runs keep saying what to run until it's done.
            log.warning("could not upgrade the protected decisions in %s: %s", path, exc)
        finally:
            engine.dispose()
    return changed


# Columns db.upgrade_decision_tables adds. Anything else missing can't be upgraded.
_UPGRADABLE = {("allowances", "engine"), ("allowed_folders", "engine")}


def missing_columns(conn: sqlite3.Connection) -> dict[str, list[str]]:
    """{table: columns this version needs that the decisions file lacks}."""
    missing = {}
    for table, columns in _expected_columns().items():
        have = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        lacking = sorted(set(columns) - have)
        if lacking:
            missing[table] = lacking
    return missing


def upgradable(missing: dict[str, list[str]]) -> bool:
    return all((table, column) in _UPGRADABLE for table, columns in missing.items() for column in columns)


def _expected_columns() -> dict[str, list[str]]:
    from .models import Base
    return {t: [c.name for c in Base.metadata.tables[t].columns] for t in DECISION_TABLES}


# ----------------------------------------------------------------------
# sudo ensign-scan --protect / --unprotect
# ----------------------------------------------------------------------

def target_uid() -> int:
    """The user --protect / --unprotect is for: the one who ran sudo."""
    if os.geteuid() != 0:
        raise CantProtect("this needs root. Run it with sudo: sudo ensign-scan --protect")
    raw = os.environ.get("SUDO_UID", "")
    if not raw.isdigit() or int(raw) == 0:
        raise CantProtect("run it with sudo from your own account (not as root directly): "
                          "it protects the account that ran sudo")
    return int(raw)


def is_protected(uid: int) -> bool:
    return config_dir(uid).exists() or data_dir(uid).exists()


def _make_passable(folder: Path) -> None:
    """Create `folder` if needed (0700, from the umask), and let anyone pass
    through it (0711) without listing it. Only adds the x bits."""
    folder.mkdir(mode=0o700, exist_ok=True)
    mode = stat.S_IMODE(folder.lstat().st_mode)
    if mode & 0o011 != 0o011:
        os.chmod(folder, mode | 0o011)


def _check_places() -> None:
    for place in (CONFIG_ROOT / "users", DATA_ROOT / "users"):
        why = trust.untrusted_reason(place)
        if why:
            raise CantProtect(f"{place} isn't safe to use: {why}")


def _write_private(path: Path, data: bytes) -> None:
    """Write a new file root owns (0600), without following a symlink."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def _create_decisions(path: Path) -> None:
    """An empty decisions file: the three decision tables, as models.py
    defines them. Rollback journal, not WAL: a reader can then open it
    without writing anything (a WAL reader writes the -shm file)."""
    from sqlalchemy import create_engine

    from .models import Base
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    os.close(fd)
    engine = create_engine(f"sqlite:///{path}")
    try:
        with engine.begin() as conn:
            conn.exec_driver_sql("PRAGMA journal_mode=DELETE")
        Base.metadata.create_all(engine, tables=[Base.metadata.tables[t] for t in DECISION_TABLES])
    finally:
        engine.dispose()


def _verify_as(uid: int, found: Protected) -> str | None:
    """Check, as the user, that their runs can read both files: fork, drop
    to the user, and run the same check their runs do. None if it works."""
    import pwd
    try:
        gid = pwd.getpwuid(uid).pw_gid
    except KeyError:
        return f"there's no account with uid {uid}"
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:   # the child: never returns
        try:
            os.close(read_end)
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            if status(uid) is None:   # can't even see it's protected: the folders above aren't 0711
                raise CantProtect("your user can't see that it's protected")
            os._exit(0)
        except BaseException as exc:   # noqa: BLE001 -- report anything, then exit
            os.write(write_end, str(exc).encode("utf-8", "replace")[:2000])
            os._exit(1)
    os.close(write_end)
    with os.fdopen(read_end, "rb") as r:
        message = r.read().decode("utf-8", "replace")
    _, code = os.waitpid(pid, 0)
    return None if os.waitstatus_to_exitcode(code) == 0 else (message or "unknown error")


def protect(uid: int, config_text: str, copied_from: str | None, confirm) -> Protected | None:
    """Set up protected mode for `uid`: root's copy of `config_text` and an
    empty decisions file, readable by `uid` only. `confirm(prompt)` asks.
    Returns None if the user said no. Raises CantProtect."""
    from .config import Config
    from .fsutil import shown
    if is_protected(uid):
        raise CantProtect(f"you are already protected: your config is {config_path(uid)}. "
                          f"Change it with: sudoedit {config_path(uid)}")
    _check_places()

    print(f"Your config, from {shown(str(copied_from))}:" if copied_from else
          "You have no config of your own; root's copy will be the starter config.")
    print("-" * 71)
    for line in config_text.splitlines():
        print(shown(line))
    print("-" * 71)
    print("From now on your own runs use root's copy of this config, and root's decisions file "
          "for allowances and acknowledged startup entries. It starts empty: the ones in your "
          "own database are no longer used. Changing any of these will need sudo.")
    if not confirm("Protect your Ensign settings with this config? [y/N] "):
        print("Nothing was changed.")
        return None

    created: list[Path] = []
    try:
        for root in (CONFIG_ROOT, DATA_ROOT):
            _make_passable(root)
            _make_passable(root / "users")
        for folder in (config_dir(uid), data_dir(uid)):
            folder.mkdir(mode=0o700)
            created.append(folder)
            acl.set_only(str(folder), uid, acl.EXECUTE)

        found = Protected(config_path(uid), decisions_path(uid))
        staged = config_dir(uid) / ".config.toml.new"
        _write_private(staged, config_text.encode("utf-8"))
        try:
            Config._load_file(staged, explicit=staged)   # a config your runs can't load is refused now
        except (ValueError, OSError) as exc:
            raise CantProtect(f"your config has an error, so nothing was protected: {exc}") from None
        os.rename(staged, found.config)
        acl.set_only(str(found.config), uid, acl.READ)

        # Made whole under another name, then renamed into place: a crash
        # midway leaves no half-made decisions file where your runs look.
        staged_decisions = data_dir(uid) / ".decisions.db.new"
        _create_decisions(staged_decisions)
        acl.set_only(str(staged_decisions), uid, acl.READ)
        os.rename(staged_decisions, found.decisions)

        # Nobody but the user may read them: no entry inherited from a default
        # ACL above, no group or other access.
        for path, perm in ((config_dir(uid), acl.EXECUTE), (data_dir(uid), acl.EXECUTE),
                           (found.config, acl.READ), (found.decisions, acl.READ)):
            if not acl.exactly(str(path), uid, perm):
                raise CantProtect(f"{path} didn't get the permissions it should (only your user "
                                  f"may read it), so nothing was protected")

        problem = _verify_as(uid, found)
        if problem:
            raise CantProtect(f"your user couldn't read root's copies afterwards, so nothing "
                              f"was protected: {problem}")
    except acl.ACLUnsupported as exc:
        _remove(created)
        raise CantProtect(f"{exc}. Protected mode needs ACLs, so that only your user can read "
                          f"root's copies; nothing was protected.") from None
    except OSError as exc:   # a read-only /etc, a full disk, ...
        _remove(created)
        where = f" ({exc.filename})" if exc.filename else ""
        raise CantProtect(f"couldn't set up root's copies{where}: {exc.strerror or exc}. "
                          f"Nothing was protected.") from None
    except BaseException:
        _remove(created)
        raise
    return found


def _remove(folders: list[Path]) -> None:
    for folder in folders:
        shutil.rmtree(folder, ignore_errors=True)


def unprotect(uid: int, confirm) -> bool:
    """Undo --protect for `uid`: delete root's copies. Their own config and
    database are used again from the next run. Returns False if there was
    nothing to undo or the user said no."""
    if not is_protected(uid):
        print("You aren't protected: your runs already use your own config and database.")
        return False
    print("This deletes root's copy of your config and your protected decisions:")
    print(f"  {config_dir(uid)}")
    print(f"  {data_dir(uid)}")
    print("From your next run, your own config (~/.config/ensign-scan/config.toml) and the "
          "allowances and acknowledgments in your own database are used again, as they are "
          "now: check them, since anything running as you could have changed them meanwhile.")
    if not confirm("Go back to your own, unprotected settings? [y/N] "):
        print("Nothing was changed.")
        return False
    _check_places()
    # The decisions first, the config last: your runs go by the config folder,
    # so if removing fails partway they still see you as protected (and stop,
    # saying what's missing) instead of quietly using your own config again.
    for folder in (data_dir(uid), config_dir(uid)):
        try:
            shutil.rmtree(folder)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise CantProtect(f"couldn't remove {exc.filename or folder}: {exc.strerror or exc}. "
                              f"Fix that, then run sudo ensign-scan --unprotect again.") from None
    return True
