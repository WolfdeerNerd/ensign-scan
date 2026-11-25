"""ensign-scan --uninstall: remove everything Ensign made, then say how to
remove the program itself.

What goes (each run lists it first, with sizes, and asks you to type
"uninstall"):

  * yours: ~/.config/ensign-scan and ~/.local/share/ensign-scan (config,
    database, logs, YARA rules cache, ClamAV reports), the pre-0.8.1
    folders ~/.config/ensign and ~/.local/share/ensign if they hold only
    Ensign's files (migrate.py's checks), and Ensign's files in a data_dir
    your config moved elsewhere -- only Ensign's names there, the folder
    itself only if that leaves it empty;
  * with sudo, also root's: /etc/ensign-scan and /var/lib/ensign-scan,
    which hold root's own config and data and every user's protected-mode
    copies, and Ensign's files in a data_dir root's config names.

Under sudo your files are deleted by a child process running as you, never
as root: a folder in your home could be a symlink to anywhere, and root
following it would delete whatever it points to.

What stays, and is only pointed out (Ensign changes only its own files):
the program itself (its removal depends on how it was installed, and a
program deleting its own running install is fragile, so the command is
printed instead), ClamAV, which you installed separately (Ensign never
installs it), and any timer, service or cron job you set up to run Ensign.

Before deleting, you can save your decisions (allowances, allowed folders,
acknowledged startup entries) to a JSON file in your home, to look up or
re-enter if you come back. There's no import for it yet.
"""
from __future__ import annotations

import json
import os
import pwd
import shutil
import sqlite3
import stat
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import migrate, protect
from rich import print as rich_print

from .fsutil import shown
from .runlock import AlreadyRunning, RunLock

DECISION_TABLES = protect.DECISION_TABLES
CONFIRM_WORD = "uninstall"
_SCHEDULE_HINTS = ("ensign-scan", "ensign_scan")


@dataclass
class Item:
    """One thing to delete: a whole folder (names empty), or only `names`
    inside a folder that isn't Ensign's alone."""
    path: str
    what: str
    size: int = 0
    names: list[str] = field(default_factory=list)


@dataclass
class Plan:
    items: list[Item] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)       # looked at, and left: why
    schedules: list[str] = field(default_factory=list)  # things you set up that run Ensign
    databases: list[str] = field(default_factory=list)  # whose decisions can be exported
    busy: str | None = None                             # a run is going


# ----------------------------------------------------------------------
# What there is
# ----------------------------------------------------------------------

def _size(path: Path) -> int:
    try:
        st = path.lstat()
    except OSError:
        return 0
    if not stat.S_ISDIR(st.st_mode):
        return st.st_size
    total = 0
    for root, dirs, files in os.walk(path):
        for name in files + dirs:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
    return total


def _is_real_dir(path: Path) -> bool:
    try:
        return stat.S_ISDIR(path.lstat().st_mode)
    except OSError:
        return False


def _data_dir_setting(config_path: Path) -> Path | None:
    """The data_dir a config names, if any. Read as plain TOML: a config
    Ensign can't load any more must not stop the uninstall."""
    import tomllib
    try:
        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    value = raw.get("data_dir")
    if not isinstance(value, str) or not value.strip():
        return None
    return Path(os.path.expanduser(value)).absolute()


def _ensigns_names_in(folder: Path, what: str, plan: Plan) -> None:
    """Ensign's files in a folder that may hold other things too."""
    if not _is_real_dir(folder):
        return
    try:
        names = sorted(e.name for e in folder.iterdir() if e.name in migrate._DATA_NAMES)
    except OSError as exc:
        plan.kept.append(f"{folder}: couldn't be read ({exc.strerror or exc})")
        return
    if names:
        plan.items.append(Item(str(folder), what, sum(_size(folder / n) for n in names), names))
        if "system.db" in names:
            plan.databases.append(str(folder / "system.db"))


def _check_lock(data_dir: Path, plan: Plan) -> None:
    lock_path = data_dir / "ensign.lock"
    if plan.busy or not lock_path.exists():
        return
    lock = RunLock(lock_path)
    try:
        lock.acquire()
    except AlreadyRunning as exc:
        pid = f" (pid {exc.holder_pid})" if getattr(exc, "holder_pid", None) else ""
        plan.busy = f"an Ensign run is going{pid}, using {data_dir}"
    except OSError:
        pass
    finally:
        lock.release()


def _schedules(folders: list[Path], plan: Plan) -> None:
    """Unit files that mention Ensign: you made them, so you remove them."""
    for folder in folders:
        try:
            entries = sorted(folder.iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_file() and entry.stat().st_size < 1_000_000 and any(
                        h in entry.read_text(errors="replace") for h in _SCHEDULE_HINTS):
                    plan.schedules.append(str(entry))
            except OSError:
                pass


def _crontab(plan: Plan, who: str) -> None:
    import subprocess
    try:
        out = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10,
                             stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return
    for line in out.stdout.splitlines():
        if not line.lstrip().startswith("#") and any(h in line for h in _SCHEDULE_HINTS):
            plan.schedules.append(f"{who} crontab: {line.strip()}")


def user_plan(home: Path) -> Plan:
    """Your files. Runs as you (under sudo: in a child dropped to you)."""
    plan = Plan()
    config_dir = home / ".config" / "ensign-scan"
    data_dir = home / ".local" / "share" / "ensign-scan"
    # A data_dir your config moves elsewhere, or root's protected copy of it.
    custom = [d for d in (_data_dir_setting(config_dir / "config.toml"),
                          _data_dir_setting(protect.config_path(os.getuid()))) if d]
    for folder, what in ((config_dir, "your config"), (data_dir, "your database, logs and reports")):
        if _is_real_dir(folder):
            plan.items.append(Item(str(folder), what, _size(folder)))
            _check_lock(folder, plan)
    if (data_dir / "system.db").exists():
        plan.databases.append(str(data_dir / "system.db"))
    legacy_config, legacy_data = home / ".config" / "ensign", home / ".local" / "share" / "ensign"
    if _is_real_dir(legacy_config):
        if migrate._config_is_ensigns(legacy_config):
            plan.items.append(Item(str(legacy_config), "your config, from before 0.8.1",
                                   _size(legacy_config)))
            custom += [d for d in (_data_dir_setting(legacy_config / "config.toml"),) if d]
        else:
            plan.kept.append(f"{legacy_config}: not only Ensign's files (another program may use it)")
    if _is_real_dir(legacy_data):
        if migrate._data_is_ensigns(legacy_data):
            plan.items.append(Item(str(legacy_data), "your database, from before 0.8.1", _size(legacy_data)))
            plan.databases.append(str(legacy_data / "system.db"))
            _check_lock(legacy_data, plan)
        else:
            plan.kept.append(f"{legacy_data}: not only Ensign's files (another program may use it)")
    whole = {item.path for item in plan.items}
    for folder in custom:
        if str(folder) not in whole:
            _ensigns_names_in(folder, "your data_dir (Ensign's files only)", plan)
            _check_lock(folder, plan)
    _schedules([home / ".config" / "systemd" / "user"], plan)
    _crontab(plan, "your")
    return plan


def root_plan() -> Plan:
    """Root's files, protected-mode copies included."""
    plan = Plan()
    config_root, data_root = protect.CONFIG_ROOT, protect.DATA_ROOT
    for folder, what in ((data_root, "root's database and logs, and every user's protected decisions"),
                         (config_root, "root's config, and every user's protected config")):
        try:
            st = folder.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            plan.kept.append(f"{folder}: couldn't be checked ({exc.strerror or exc})")
            continue
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0:
            plan.kept.append(f"{folder}: not a folder owned by root, so not Ensign's to delete")
            continue
        plan.items.append(Item(str(folder), what, _size(folder)))
    if (data_root / "system.db").exists():
        plan.databases.append(str(data_root / "system.db"))
    users = data_root / "users"
    if _is_real_dir(users):
        for decisions in sorted(users.glob("*/decisions.db")):
            plan.databases.append(str(decisions))
    _check_lock(data_root, plan)
    custom = _data_dir_setting(config_root / "config.toml")
    if custom and not str(custom).startswith(str(data_root)):
        _ensigns_names_in(custom, "root's data_dir (Ensign's files only)", plan)
        _check_lock(custom, plan)
    _schedules([Path("/etc/systemd/system")], plan)
    _crontab(plan, "root's")
    return plan


# ----------------------------------------------------------------------
# Your decisions, saved before they go
# ----------------------------------------------------------------------

def read_decisions(db_paths: list[str]) -> dict:
    """{database path: {table: [rows as dicts]}}, read-only."""
    found: dict = {}
    for path in db_paths:
        try:
            conn = sqlite3.connect(f"{Path(path).as_uri()}?mode=ro", uri=True, timeout=5)
        except sqlite3.Error:
            continue
        try:
            conn.row_factory = sqlite3.Row
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            rows = {t: [dict(r) for r in conn.execute(f"SELECT * FROM {t}")]
                    for t in DECISION_TABLES if t in tables}
        except sqlite3.Error:
            continue
        finally:
            conn.close()
        if any(rows.values()):
            found[path] = rows
    return found


def write_export(home: Path, decisions: dict) -> Path:
    """Save to ~/ensign-scan-decisions-DATE.json (0600, never over a file)."""
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%S")
    path = home / f"ensign-scan-decisions-{stamp}.json"
    from importlib.metadata import PackageNotFoundError, version
    try:
        made_by = version("ensign-scan")
    except PackageNotFoundError:
        made_by = "unknown (running from source)"
    body = {"ensign_version": made_by, "made": stamp,
            "note": "Your Ensign decisions, saved by --uninstall. There's no import yet: "
                    "re-enter what you need with --allow, --allow-folder and --acknowledge.",
            "databases": decisions}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(body, f, indent=2, default=str)
        f.write("\n")
    return path


# ----------------------------------------------------------------------
# Deleting
# ----------------------------------------------------------------------

def delete(items: list[Item]) -> list[str]:
    """Delete in order; returns what failed. rmtree doesn't follow symlinks
    inside a folder (shutil.rmtree.avoids_symlink_attacks on Linux)."""
    failed = []
    for item in items:
        folder = Path(item.path)
        lock = RunLock(folder / "ensign.lock") if (folder / "ensign.lock").exists() else None
        try:
            if lock:
                lock.acquire()   # held while it goes, so no run starts using it midway
            if item.names:
                for name in item.names:
                    target = folder / name
                    if _is_real_dir(target):
                        shutil.rmtree(target)
                    else:
                        target.unlink(missing_ok=True)
                try:
                    folder.rmdir()   # only if that left it empty
                except OSError:
                    pass
            elif _is_real_dir(folder):
                shutil.rmtree(folder)
        except AlreadyRunning:
            failed.append(f"{item.path}: an Ensign run started meanwhile")
        except OSError as exc:
            failed.append(f"{exc.filename or item.path}: {exc.strerror or exc}")
        finally:
            if lock:
                lock.release()
    return failed


# ----------------------------------------------------------------------
# Running as you, under sudo
# ----------------------------------------------------------------------

def as_user(uid: int, fn, *args):
    """Run fn(*args) in a child process dropped to `uid`, and return its
    JSON-able result. Raises RuntimeError with the child's error."""
    account = pwd.getpwuid(uid)
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:   # the child: never returns
        try:
            os.close(read_end)
            os.setgroups(os.getgrouplist(account.pw_name, account.pw_gid))
            os.setgid(account.pw_gid)
            os.setuid(uid)
            os.environ["HOME"] = account.pw_dir
            result = json.dumps({"ok": fn(*args)}, default=_jsonable)
        except BaseException as exc:  # noqa: BLE001 -- report anything, then exit
            result = json.dumps({"error": f"{type(exc).__name__}: {exc}"})
        try:
            with os.fdopen(write_end, "w", encoding="utf-8") as w:
                w.write(result)
        finally:
            os._exit(0)
    os.close(write_end)
    with os.fdopen(read_end, encoding="utf-8") as r:
        text = r.read()
    os.waitpid(pid, 0)
    try:
        answer = json.loads(text)
    except ValueError:
        raise RuntimeError("the step run as you ended without an answer") from None
    if "error" in answer:
        raise RuntimeError(answer["error"])
    return answer["ok"]


def _jsonable(value):
    if isinstance(value, (Plan, Item)):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    raise TypeError(type(value).__name__)


def _plan_from(data: dict) -> Plan:
    plan = Plan(**{k: v for k, v in data.items() if k != "items"})
    plan.items = [Item(**i) for i in data["items"]]
    return plan


def _user_plan_json(home: str) -> dict:
    return asdict(user_plan(Path(home)))


def _delete_json(items: list[dict]) -> list[str]:
    return delete([Item(**i) for i in items])


def _export_json(home: str, decisions: dict) -> str:
    return str(write_export(Path(home), decisions))


# ----------------------------------------------------------------------
# The program itself
# ----------------------------------------------------------------------

def removal_hints() -> list[str]:
    """How to remove the installed program, as far as can be told."""
    here = Path(__file__).resolve().parent
    hints = []
    checkout = here.parent
    if (checkout / "main.py").is_file() and (checkout / "pyproject.toml").is_file():
        hints.append(f"Ensign runs from a checkout: delete the folder {checkout}")
    elif "/pipx/venvs/ensign-scan/" in str(here):
        hints.append("Installed with pipx: pipx uninstall ensign-scan")
    elif sys.prefix != sys.base_prefix:
        hints.append(f"Installed in a virtual environment: {sys.prefix}/bin/pip uninstall ensign-scan "
                     f"(or delete {sys.prefix} if it's only for Ensign)")
    else:
        from . import pkgdb
        state, package = pkgdb.active().owner(str(here / "__init__.py"))
        if state == "owned" and package:
            name = package.split()[0]
            command = {"pacman": f"sudo pacman -Rns {name}", "dpkg": f"sudo apt remove {name}",
                       "rpm": f"sudo dnf remove {name}"}.get(pkgdb.active().name)
            hints.append(f"Installed by the package {name}: {command or 'remove it with your package manager'}")
        else:
            hints.append(f"Installed with pip at {here.parent}: pip uninstall ensign-scan")
    hints.append("ClamAV isn't part of Ensign (you installed it separately), so it's untouched. "
                 "If you only installed it for Ensign, you can stop and remove it with your "
                 "package manager (on Arch: sudo systemctl disable --now clamav-daemon "
                 "clamav-freshclam, then sudo pacman -Rns clamav).")
    return hints


# ----------------------------------------------------------------------
# The command
# ----------------------------------------------------------------------

def _human(size: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size} B"


def run(confirm_word=input, ask_yes_no=None, out=rich_print) -> int:
    """The whole command. confirm_word and ask_yes_no are input() stand-ins
    for tests; without a terminal it refuses."""
    as_root = os.geteuid() == 0
    sudo_uid = os.environ.get("SUDO_UID")
    user_uid = int(sudo_uid) if as_root and sudo_uid and sudo_uid.isdigit() and int(sudo_uid) else None
    if confirm_word is input and not sys.stdin.isatty():
        out("✗ --uninstall asks you to type a word to confirm, and there's no terminal here. "
            "Run it from one. (--yes doesn't skip this: it can't be undone.)")
        return 1

    plans: list[tuple[str, Plan, int | None]] = []
    try:
        if as_root:
            plans.append(("root", root_plan(), None))
            if user_uid is not None:
                home = pwd.getpwuid(user_uid).pw_dir
                plans.append(("you", _plan_from(as_user(user_uid, _user_plan_json, home)), user_uid))
        else:
            plans.append(("you", user_plan(Path.home()), None))
    except (RuntimeError, KeyError) as exc:
        out(f"✗ Couldn't look at your files: {exc}. Nothing was changed.")
        return 1

    busy = [p.busy for _, p, _ in plans if p.busy]
    if busy:
        out(f"✗ {busy[0]}. Let it finish (or stop it), then run --uninstall again. Nothing was changed.")
        return 1

    failed: list[str] = []
    items = [(who, item) for who, plan, _ in plans for item in plan.items]
    leftovers = [] if as_root else [str(p) for p in (protect.CONFIG_ROOT, protect.DATA_ROOT) if p.exists()]
    out("This deletes everything Ensign made" + (" (yours and root's):" if as_root else " for you:"))
    for _who, item in items:
        inside = f" (only {', '.join(item.names)})" if item.names else ""
        out(f"  {shown(item.path)}{shown(inside)}  {_human(item.size)}  · {item.what}")
    if not items:
        out("  nothing: Ensign has no files here.")
    for _, plan, _ in plans:
        for note in plan.kept:
            out(f"  left alone: {shown(note)}")
    if leftovers:
        out("Root's files stay, since only root can delete them: " + ", ".join(leftovers)
            + ". Remove them too with: sudo ensign-scan --uninstall")
    schedules = [s for _, p, _ in plans for s in p.schedules]
    if schedules:
        out("These run Ensign, and you set them up, so they stay; remove or disable them yourself:")
        for s in schedules:
            out(f"  {shown(s)}")

    if items:
        databases = {who: p.databases for who, p, _ in plans}
        if any(databases.values()):
            ask = ask_yes_no or (lambda prompt: input(prompt).strip().lower() in ("y", "yes"))
            try:
                want_export = ask("Save your decisions (allowances, allowed folders, acknowledged "
                                  "startup entries) to a file in your home first? [y/N] ")
            except EOFError:
                want_export = False
        else:
            want_export = False
        try:
            typed = confirm_word(f"Type {CONFIRM_WORD} to delete all of the above: ").strip()
        except EOFError:
            typed = ""
        if typed != CONFIRM_WORD:
            out("Nothing was changed.")
            return 0

        if want_export:
            try:
                decisions = read_decisions(databases.get("root", []))
                if user_uid is not None:
                    decisions.update(as_user(user_uid, read_decisions, databases.get("you", [])))
                    saved = as_user(user_uid, _export_json, pwd.getpwuid(user_uid).pw_dir, decisions)
                else:
                    decisions.update(read_decisions(databases.get("you", [])))
                    saved = str(write_export(Path.home(), decisions))
                out(f"✓ Saved your decisions to {shown(saved)}")
            except (OSError, RuntimeError) as exc:
                out(f"✗ Couldn't save your decisions ({exc}), so nothing was deleted.")
                return 1

        for _who, plan, uid in plans:
            if uid is not None:
                try:
                    failed += as_user(uid, _delete_json, [asdict(i) for i in plan.items])
                except RuntimeError as exc:
                    failed.append(f"your files: {exc}")
            else:
                failed += delete(plan.items)
        if failed:
            out("✗ Some of it couldn't be deleted:")
            for f in failed:
                out(f"  {shown(f)}")
        else:
            out("✓ Ensign's files are gone.")

    out("To remove the program itself:")
    for hint in removal_hints():
        out(f"  {shown(hint)}")
    return 1 if items and failed else 0
