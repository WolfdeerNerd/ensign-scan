"""The persistence audit: what is set to start by itself, and what changed.

Malware that wants to survive a reboot or a logout has to leave something
behind in a place that runs programs automatically: a systemd unit or
timer, a line in ~/.bashrc, an XDG autostart entry, a cron job,
/etc/ld.so.preload, a pacman hook. These files are few and rarely change,
so instead of judging them, the audit compares them with a baseline you
set: each one you acknowledged, as it was then.

  ensign-scan --persistence           list new, changed and removed entries
  ensign-scan --acknowledge PATH      accept one entry as it is now
  ensign-scan --acknowledge-all       accept everything the audit lists

An entry is the file's content (SHA-256), or a symlink's target, plus its
permission bits and owner. Nothing about the entry's content is stored
except that hash. Files that look like credentials (secrets.py) are never
opened here either; their size and modification time stand in for the hash.

The audit never changes anything on the system. Acknowledging only writes
to Ensign's own database and to an acknowledgment log next to it.

Its known limit: malware running as you can also write to Ensign's
database, and so could acknowledge its own entry. The log makes that
visible to someone who reads it, but sits in the same folder. The README
says so.
"""
from __future__ import annotations

import hashlib
import os
import stat as statmod
from dataclasses import dataclass, field
from pathlib import Path

from rich import print
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from . import pkgdb, secrets
from .fsutil import CHUNK_SIZE, print_unwrapped, printable, shown
from .models import PersistenceEntry, utcnow

# ----------------------------------------------------------------------
# Where to look
# ----------------------------------------------------------------------

SYSTEMD_SYSTEM = "systemd (system)"
SYSTEMD_USER = "systemd (user)"
SHELL = "shell startup"
AUTOSTART = "desktop autostart"
CRON = "cron"
PRELOAD = "ld.so.preload"
PACMAN_HOOKS = "pacman hooks"

# One line per category, printed above its entries.
WHY = {
    SYSTEMD_SYSTEM: "Units and timers systemd starts at boot, as root unless the unit says otherwise.",
    SYSTEMD_USER: "Units and timers systemd starts when you log in, as you.",
    SHELL: "Scripts every new shell or login session runs.",
    AUTOSTART: "Programs your desktop starts when you log in.",
    CRON: "Jobs run on a schedule.",
    PRELOAD: "Libraries loaded into every program that starts. Normally this file doesn't exist.",
    PACMAN_HOOKS: "Commands pacman runs, as root, during installs and updates.",
}

ORDER = (PRELOAD, SYSTEMD_SYSTEM, SYSTEMD_USER, CRON, PACMAN_HOOKS, AUTOSTART, SHELL)

_SHELL_FILES = (
    ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
    ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout",
    ".xprofile", ".xinitrc", ".xsession", ".xsessionrc",
)


@dataclass(frozen=True)
class Location:
    category: str
    path: str
    # True: a folder; everything under it is an entry. False: one file.
    folder: bool
    # Under the user's home: never asked about package ownership.
    personal: bool = False


def locations(home: str, root: str = "/") -> list[Location]:
    """Every place the audit checks. `home` is the invoking user's home
    (config.HOME, correct under sudo); `root` lets tests use a fake tree."""
    def r(*parts: str) -> str:
        return os.path.join(root, *parts)

    def h(*parts: str) -> str:
        return os.path.join(home, *parts)

    found: list[Location] = []
    for base in ("etc/systemd/system", "usr/lib/systemd/system", "usr/local/lib/systemd/system",
                 "lib/systemd/system", "etc/systemd/system-generators",
                 "usr/lib/systemd/system-generators", "usr/local/lib/systemd/system-generators",
                 "lib/systemd/system-generators"):
        found.append(Location(SYSTEMD_SYSTEM, r(base), True))
    for base in ("etc/systemd/user", "usr/lib/systemd/user", "usr/local/lib/systemd/user",
                 "lib/systemd/user", "etc/systemd/user-generators", "usr/lib/systemd/user-generators"):
        found.append(Location(SYSTEMD_USER, r(base), True))
    found.append(Location(SYSTEMD_USER, h(".config/systemd/user"), True, personal=True))
    found.append(Location(SYSTEMD_USER, h(".local/share/systemd/user"), True, personal=True))

    for name in _SHELL_FILES:
        found.append(Location(SHELL, h(name), False, personal=True))
    found.append(Location(SHELL, h(".config/fish/config.fish"), False, personal=True))
    found.append(Location(SHELL, h(".config/fish/conf.d"), True, personal=True))
    found.append(Location(SHELL, h(".config/environment.d"), True, personal=True))
    for name in ("etc/profile", "etc/bash.bashrc", "etc/bash.bash_logout", "etc/bashrc",
                 "etc/zshrc", "etc/zprofile", "etc/zshenv", "etc/zlogin", "etc/zlogout",
                 "etc/environment", "etc/fish/config.fish"):
        found.append(Location(SHELL, r(name), False))
    for name in ("etc/profile.d", "etc/zsh", "etc/fish/conf.d", "etc/environment.d",
                 "usr/lib/environment.d", "etc/X11/xinit/xinitrc.d"):
        found.append(Location(SHELL, r(name), True))
    if os.path.realpath(home) != os.path.realpath(r("root")):
        # root's own startup files: readable only with sudo, reported as
        # "couldn't check" otherwise.
        for name in (".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zshenv",
                     ".zprofile", ".zlogin"):
            found.append(Location(SHELL, r("root", name), False, personal=True))

    found.append(Location(AUTOSTART, h(".config/autostart"), True, personal=True))
    found.append(Location(AUTOSTART, h(".config/autostart-scripts"), True, personal=True))
    found.append(Location(AUTOSTART, h(".config/plasma-workspace/env"), True, personal=True))
    found.append(Location(AUTOSTART, h(".config/plasma-workspace/shutdown"), True, personal=True))
    found.append(Location(AUTOSTART, r("etc/xdg/autostart"), True))

    for name in ("etc/crontab", "etc/anacrontab"):
        found.append(Location(CRON, r(name), False))
    for name in ("etc/cron.d", "etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly",
                 "etc/cron.monthly", "var/spool/cron"):
        found.append(Location(CRON, r(name), True))

    found.append(Location(PRELOAD, r("etc/ld.so.preload"), False))

    found.append(Location(PACMAN_HOOKS, r("etc/pacman.d/hooks"), True))
    found.append(Location(PACMAN_HOOKS, r("usr/share/libalpm/hooks"), True))
    return found


# ----------------------------------------------------------------------
# What is there now
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class Entry:
    path: str
    category: str
    kind: str
    digest: str
    mode: int
    uid: int
    gid: int
    personal: bool = False
    # The audited folder (or file) it was found in, for grouping the report.
    place: str = ""

    def key(self) -> tuple:
        return (self.kind, self.digest, self.mode, self.uid, self.gid)


@dataclass
class Snapshot:
    entries: dict[str, Entry] = field(default_factory=dict)
    # path -> why it couldn't be checked (a file or a whole folder)
    unchecked: dict[str, str] = field(default_factory=dict)


def _kind(mode: int) -> str:
    if statmod.S_ISREG(mode):
        return "file"
    if statmod.S_ISLNK(mode):
        return "symlink"
    if statmod.S_ISDIR(mode):
        return "directory"
    if statmod.S_ISFIFO(mode):
        return "fifo"
    if statmod.S_ISSOCK(mode):
        return "socket"
    return "device"


# Never follow a symlink (its target is the entry), never wait on a FIFO
# swapped in after the lstat(), never take a terminal as controlling tty.
_OPEN_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOCTTY | os.O_NOFOLLOW


def _sha256_nofollow(path: str) -> tuple[str | None, os.stat_result | None]:
    """(hex digest, fstat) of a regular file, opened without following a
    symlink. (None, fstat) if what got opened isn't a regular file."""
    fd = os.open(path, _OPEN_FLAGS)
    try:
        st = os.fstat(fd)
        if not statmod.S_ISREG(st.st_mode):
            return None, st
        hasher = hashlib.sha256()
        offset = 0
        while chunk := os.pread(fd, CHUNK_SIZE, offset):
            hasher.update(chunk)
            offset += len(chunk)
        return hasher.hexdigest(), st
    finally:
        os.close(fd)


def fingerprint(path: str, category: str, personal: bool, place: str = "") -> Entry | str:
    """The Entry for `path`, or a reason it couldn't be checked."""
    try:
        st = os.lstat(path)
    except OSError as exc:
        return exc.strerror or type(exc).__name__
    kind = _kind(st.st_mode)
    digest = ""
    if kind == "symlink":
        try:
            digest = os.readlink(path)
        except OSError as exc:
            return exc.strerror or type(exc).__name__
    elif kind == "file":
        if secrets.skip_reason(path, path, st.st_mode):
            # Looks like a credential file: never opened, same as in a scan.
            digest = f"metadata size={st.st_size} mtime_ns={st.st_mtime_ns}"
        else:
            try:
                sha, opened = _sha256_nofollow(path)
            except OSError as exc:
                return exc.strerror or type(exc).__name__
            if sha is None:  # replaced by something else after the lstat()
                st, kind = opened, _kind(opened.st_mode)
            else:
                digest, st = f"sha256:{sha}", opened
    return Entry(path, category, kind, digest, st.st_mode & 0o7777, st.st_uid, st.st_gid, personal,
                 place or path)


def collect(places: list[Location]) -> Snapshot:
    """Fingerprint every entry in every location. Symlinked folders are
    entries themselves and never walked into. A location reached twice
    (/lib/systemd/system and /usr/lib/systemd/system on a merged-/usr
    system) is read once, under its real path."""
    snap = Snapshot()
    seen_dirs: set[str] = set()
    for place in places:
        if not place.folder:
            path = resolve_dirs(place.path)
            if os.path.lexists(path):
                _add(snap, path, fingerprint(path, place.category, place.personal))
            elif _blocked(path):
                snap.unchecked[path] = _blocked(path)
            continue
        real = os.path.realpath(place.path)
        if real in seen_dirs:
            continue
        try:
            is_dir = statmod.S_ISDIR(os.stat(real).st_mode)
        except FileNotFoundError:
            continue
        except OSError as exc:
            snap.unchecked[place.path] = exc.strerror or type(exc).__name__
            continue
        if not is_dir:
            path = resolve_dirs(place.path)
            _add(snap, path, fingerprint(path, place.category, place.personal))
            continue
        seen_dirs.add(real)

        for folder, dirs, files in os.walk(real, onerror=_unreadable_into(snap, real), followlinks=False):
            for name in sorted(files) + sorted(d for d in dirs if os.path.islink(os.path.join(folder, d))):
                path = os.path.join(folder, name)
                _add(snap, path, fingerprint(path, place.category, place.personal, real))
    return snap


def resolve_dirs(path: str) -> str:
    """The path with its folders resolved, the file itself not: how every
    entry is stored and looked up, so /lib/x and /usr/lib/x (merged /usr),
    or /home/you and /var/home/you, name one entry."""
    head, tail = os.path.split(path)
    return os.path.join(os.path.realpath(head or "/"), tail)


def _unreadable_into(snap: Snapshot, top: str):
    """os.walk's onerror: a folder that can't be listed is "couldn't check"."""
    def record(exc: OSError) -> None:
        snap.unchecked[exc.filename or top] = exc.strerror or type(exc).__name__
    return record


def _blocked(path: str) -> str | None:
    """Why a missing-looking path can't be checked: lexists() is also False
    when a parent folder can't be entered (/root without sudo)."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return exc.strerror or type(exc).__name__
    return None


def _add(snap: Snapshot, path: str, result: Entry | str) -> None:
    if isinstance(result, Entry):
        snap.entries[path] = result
    else:
        snap.unchecked[path] = result


# ----------------------------------------------------------------------
# Comparing with the baseline
# ----------------------------------------------------------------------

@dataclass
class Audit:
    new: list[Entry] = field(default_factory=list)
    changed: list[tuple[PersistenceEntry, Entry]] = field(default_factory=list)
    removed: list[PersistenceEntry] = field(default_factory=list)
    unchecked: dict[str, str] = field(default_factory=dict)
    acknowledged: int = 0      # rows in the baseline
    checked: int = 0           # entries looked at this run
    # path -> (pkgdb origin state, package name), for new and changed
    # entries outside your home folder
    origins: dict[str, tuple[str, str | None]] = field(default_factory=dict)

    @property
    def pending(self) -> int:
        return len(self.new) + len(self.changed) + len(self.removed)


def _row_key(row: PersistenceEntry) -> tuple:
    return (row.kind, row.digest or "", row.mode, row.uid, row.gid)


def _under(path: str, folder: str) -> bool:
    return path == folder or path.startswith(folder.rstrip("/") + "/")


def compare(engine: Engine, snap: Snapshot, check_packages: bool = True) -> Audit:
    audit = Audit(unchecked=dict(snap.unchecked), checked=len(snap.entries))
    with Session(engine) as session:
        rows = {row.path: row for row in session.query(PersistenceEntry).all()}
        session.expunge_all()
    audit.acknowledged = len(rows)
    for path, entry in snap.entries.items():
        row = rows.get(path)
        if row is None:
            audit.new.append(entry)
        elif _row_key(row) != entry.key():
            audit.changed.append((row, entry))
    for path, row in rows.items():
        if path in snap.entries:
            continue
        if any(_under(path, blocked) for blocked in snap.unchecked):
            continue  # not checked this run (no permission), not gone
        try:
            os.lstat(path)
        except (FileNotFoundError, NotADirectoryError):
            audit.removed.append(row)
            continue
        except OSError as exc:
            audit.unchecked[path] = exc.strerror or type(exc).__name__
            continue
        # Still there but no longer collected: it became a folder (or
        # moved out of every audited place, which only a code change does).
        entry = fingerprint(path, row.category, False)
        if isinstance(entry, Entry) and entry.kind == "directory":
            audit.changed.append((row, entry))
    if check_packages:
        system = [e.path for e in audit.new if not e.personal]
        system += [e.path for _, e in audit.changed if not e.personal and e.kind != "directory"]
        if system:
            audit.origins = pkgdb.origins(system)
    return audit


# ----------------------------------------------------------------------
# The report
# ----------------------------------------------------------------------

def _describe(entry: Entry) -> str:
    if entry.kind == "symlink":
        return f" → {shown(entry.digest)}"
    if entry.kind not in ("file", "symlink"):
        return f"  [yellow]({entry.kind})[/yellow]"
    return ""


def _differences(row: PersistenceEntry, entry: Entry) -> str:
    parts = []
    if row.kind != entry.kind:
        parts.append(f"was a {row.kind}, now a {entry.kind}")
    elif (row.digest or "") != entry.digest:
        if entry.kind == "symlink":
            parts.append(f"now points to {shown(entry.digest)} (was {shown(row.digest)})")
        elif entry.digest.startswith("metadata"):
            parts.append("size or modification time changed")
        else:
            parts.append("content changed")
    if row.mode != entry.mode:
        parts.append(f"permissions {row.mode:04o} → {entry.mode:04o}")
    if row.uid != entry.uid or row.gid != entry.gid:
        parts.append(f"owner {row.uid}:{row.gid} → {entry.uid}:{entry.gid}")
    return "; ".join(parts)


def _origin_note(audit: Audit, path: str) -> str:
    state, package = audit.origins.get(path, (pkgdb.UNKNOWN, None))
    if state == pkgdb.UNOWNED:
        return "  [yellow](no package owns this)[/yellow]"
    if state == pkgdb.MODIFIED:
        return f"  [yellow](differs from what {shown(package)} installed)[/yellow]"
    if state == pkgdb.OWNED:
        return f"  [dim](from {shown(package)}; couldn't compare it with the package)[/dim]"
    return ""


def _print_section(title: str, color: str, icon: str, items: list, audit: Audit) -> None:
    """items: (category, path, line suffix, folder it was found in). Every entry is printed: a
    startup entry hidden behind "… and 40 more" is one nobody looks at.
    The one exception is an entry a package installed that still matches
    the package: those are counted per folder (see pkgdb.origins)."""
    if not items:
        return
    print(f"\n[bold {color}]-- {title} ({len(items)}) --[/bold {color}]")
    grouped: dict[str, dict[str, int]] = {}  # category -> folder -> count
    listed: dict[str, list[tuple[str, str]]] = {}
    for category, path, suffix, place in items:
        if audit.origins.get(path, (None,))[0] == pkgdb.FROM_PACKAGE:
            folder = place
            grouped.setdefault(category, {}).setdefault(folder, 0)
            grouped[category][folder] += 1
        else:
            listed.setdefault(category, []).append((path, suffix))
    backend = pkgdb.active().label
    for category in ORDER:
        if category not in listed and category not in grouped:
            continue
        print(f"\n  [bold]{category}[/bold]: [dim]{WHY[category]}[/dim]")
        for path, suffix in sorted(listed.get(category, [])):
            print_unwrapped(f"    [{color}]{icon}[/{color}] {shown(path)}{suffix}")
        for folder, count in sorted(grouped.get(category, {}).items()):
            print_unwrapped(f"    [dim]{count} in {shown(folder)} came from packages and match "
                            f"what the package installed ({shown(backend)} checked)[/dim]")


def _unchecked_lines(unchecked: dict[str, str]) -> list[str]:
    """Several entries in one folder for the same reason (root's startup
    files without sudo) are shown as the folder, once."""
    by_parent: dict[tuple[str, str], list[str]] = {}
    for path, why in unchecked.items():
        by_parent.setdefault((os.path.dirname(path), why), []).append(path)
    lines = []
    for (parent, why), paths in sorted(by_parent.items()):
        if len(paths) == 1:
            lines.append(f"    [dim]?[/dim] {shown(paths[0])}  ({shown(why)})")
        else:
            lines.append(f"    [dim]?[/dim] {shown(parent)}/  ({len(paths)} entries, {shown(why)})")
    return lines


def report(audit: Audit) -> None:
    print("\n[bold]=== PERSISTENCE AUDIT: WHAT STARTS BY ITSELF ===[/bold]")
    print(f"Checked {audit.checked} startup entries. Acknowledged so far: {audit.acknowledged}.")
    if audit.acknowledged == 0 and audit.new:
        print("[yellow]Nothing has been acknowledged yet, so every entry counts as new.[/yellow] Look "
              "through the list (entries no package owns, and those in your home folder, matter "
              "most), then set the baseline with --acknowledge-all.")

    new = [(e.category, e.path, _describe(e) + _origin_note(audit, e.path), e.place) for e in audit.new]
    _print_section("NEW SINCE YOU LAST ACKNOWLEDGED", "yellow", "+", new, audit)

    changed = [(e.category, e.path, f"  ({_differences(row, e)})" + _origin_note(audit, e.path), e.place)
               for row, e in audit.changed]
    _print_section("CHANGED SINCE YOU ACKNOWLEDGED THEM", "cyan", "~", changed, audit)

    removed = [(row.category, row.path, "", "") for row in audit.removed]
    _print_section("GONE SINCE YOU ACKNOWLEDGED THEM", "magenta", "-", removed, audit)

    if audit.unchecked:
        print(f"\n[bold]-- COULDN'T CHECK ({len(audit.unchecked)}) --[/bold]")
        for line in _unchecked_lines(audit.unchecked):
            print_unwrapped(line)
        if os.geteuid() != 0:
            print("  Most of these need root to read. To include them: sudo ensign-scan --persistence")

    if not audit.pending:
        print("\n[green]✓ Nothing new, changed or gone since you last acknowledged.[/green]")
        return
    sudo = "sudo " if os.geteuid() == 0 else ""  # root-only entries need root to acknowledge
    print("\nIf you know where an entry came from (something you installed or set up), accept it:")
    print(f"  {sudo}ensign-scan --acknowledge PATH     one entry")
    print(f"  {sudo}ensign-scan --acknowledge-all      everything listed above")
    print("If you don't, look at it before you accept it: an entry you can't explain is the "
          "reason this check exists.")


# ----------------------------------------------------------------------
# Acknowledging
# ----------------------------------------------------------------------

def _log(log_path: Path, action: str, path: str, *detail: str) -> None:
    """One line per acknowledgment, appended: time, action, path, then the
    entry's category, kind, hash or link target, permissions and owner,
    separated by tabs. Plain text, so you can read it (or diff it) without
    Ensign."""
    stamp = utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write("\t".join([stamp, action, printable(path), *map(printable, detail)]) + "\n")
    except OSError as exc:
        # Still acknowledged (the database has it), but say so: the log is
        # how a change to the baseline stays visible.
        print(f"  [red]✗ Couldn't write the acknowledgment log ({shown(exc.strerror)}):[/red] "
              f"{shown(log_path)}")


def _store(session: Session, entry: Entry) -> None:
    row = session.query(PersistenceEntry).filter(PersistenceEntry.path == entry.path).one_or_none()
    if row is None:
        row = PersistenceEntry(path=entry.path)
        session.add(row)
    row.category, row.kind, row.digest = entry.category, entry.kind, entry.digest
    row.mode, row.uid, row.gid = entry.mode, entry.uid, entry.gid
    row.acknowledged_at = utcnow()


def _detail(entry: Entry) -> tuple[str, ...]:
    return (entry.category, entry.kind, entry.digest, f"{entry.mode:04o}", f"{entry.uid}:{entry.gid}")


def acknowledge(engine: Engine, audit: Audit, paths: list[str], log_path: Path) -> int:
    """Accept these entries as they are now. Returns how many were accepted."""
    by_path: dict[str, Entry | PersistenceEntry] = {e.path: e for e in audit.new}
    by_path.update({e.path: e for _, e in audit.changed})
    by_path.update({row.path: row for row in audit.removed})
    done = 0
    with Session(engine) as session:
        for path in paths:
            item = by_path.get(path)
            if item is None:
                known = session.query(PersistenceEntry).filter(PersistenceEntry.path == path).count()
                blocked = audit.unchecked.get(path) or next(
                    (why for folder, why in audit.unchecked.items() if _under(path, folder)), None)
                if blocked:
                    # Checked first: "unchanged" would be a claim this run couldn't check.
                    print_unwrapped(f"  [yellow]Couldn't read it ({shown(blocked)}), so there is "
                                    f"nothing to acknowledge; with sudo it can be:[/yellow] {shown(path)}")
                elif known:
                    print_unwrapped(f"  [dim]Already acknowledged, unchanged:[/dim] {shown(path)}")
                else:
                    print_unwrapped(f"  [yellow]Not a startup entry the audit checks:[/yellow] {shown(path)}")
                continue
            done += _apply(session, item, log_path)
        session.commit()
    return done


def _apply(session: Session, item, log_path: Path) -> int:
    if isinstance(item, PersistenceEntry):
        session.query(PersistenceEntry).filter(PersistenceEntry.path == item.path).delete()
        _log(log_path, "gone", item.path, item.category)
        print_unwrapped(f"  [green]✓[/green] Gone, and forgotten: {shown(item.path)}")
        return 1
    if item.kind == "directory":
        # A folder now stands where an entry was: its contents are already
        # listed as new entries of their own, so the old row just goes.
        session.query(PersistenceEntry).filter(PersistenceEntry.path == item.path).delete()
        _log(log_path, "gone", item.path, item.category, "now a directory")
        print_unwrapped(f"  [green]✓[/green] Now a folder; its contents are listed separately: {shown(item.path)}")
        return 1
    _store(session, item)
    _log(log_path, "acknowledged", item.path, *_detail(item))
    print_unwrapped(f"  [green]✓[/green] Acknowledged: {shown(item.path)}")
    return 1


def acknowledge_all(engine: Engine, audit: Audit, log_path: Path) -> int:
    """Accept every new, changed and gone entry in this audit, in one go."""
    with Session(engine) as session:
        for item in audit.new:
            _store(session, item)
            _log(log_path, "acknowledged", item.path, *_detail(item))
        for _, item in audit.changed:
            if item.kind == "directory":
                session.query(PersistenceEntry).filter(PersistenceEntry.path == item.path).delete()
                _log(log_path, "gone", item.path, item.category, "now a directory")
            else:
                _store(session, item)
                _log(log_path, "acknowledged", item.path, *_detail(item))
        for row in audit.removed:
            session.query(PersistenceEntry).filter(PersistenceEntry.path == row.path).delete()
            _log(log_path, "gone", row.path, row.category)
        session.commit()
    return audit.pending


def run_audit(engine: Engine, home: str, root: str = "/", check_packages: bool = True) -> Audit:
    """Collect and compare: the one call the command line makes."""
    return compare(engine, collect(locations(home, root)), check_packages=check_packages)
