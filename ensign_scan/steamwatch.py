"""The Steam watch: Workshop items that carry code, and game updates worth a look.

Steam's own record says where a file came from, not whether it's safe
(steam.py): games have shipped malware inside their official Steam builds,
often as a clean game first and a malicious update later (BlockBlasters),
or an old game renamed and then updated (Beyond The Dark). And Workshop
items are uploaded by anyone (Wallpaper Engine, Project Zomboid, People
Playground). So, on every scan, this reads Steam's files and lists:

  workshop  a Workshop item (steamapps/workshop/content/<appid>/<item>) with
            programs, scripts or password-protected zip archives in it: static
            content (wallpapers, maps, music) shouldn't need any. Lua on its
            own doesn't count (some games run Lua mods by design).
  update    a game's depot changed build since Ensign last saw it, and
              - a small update (5 files or fewer) adds a program or script,
              - a small update changes a program, or
              - the update adds scripts (.bat, .ps1, .vbs, .js, .py, ...).
            Measured on a real machine before choosing these: across 80
            legitimate updates they fired 0, 2 and 3 times; "an update changes
            a program" (25 times) is left out as noise.
  rename    a game's name changed since Ensign last saw it.

Each finding has an ID that says exactly what it's about (the build's
manifest, the item's current code files, the new name), and is listed until
you acknowledge it (acknowledge-steam ID, or --all). Anything that changes
after that gets a new ID and is listed again.

What it never does: change, delete or move anything of Steam's, unsubscribe
from or disable an item, start or stop a game, or talk to Steam's servers.
It only reads Steam's files and lists folders; it hashes nothing.

What it can't do: the first time it sees a game, it just records it (there's
nothing to compare with yet); a game malicious from its first build gives no
"update" (the scan and the Steam line under a hit still apply); and malware
running as you could edit Ensign's records along with Steam's, as with the
rest of Ensign's state (see the README's "Malware running as you").
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import textwrap
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from . import steam
from .models import SteamAcknowledged, SteamPending, SteamSnapshot, utcnow

log = logging.getLogger(__name__)

PROGRAMS = frozenset({".exe", ".dll", ".scr", ".com", ".sys", ".msi", ".so", ".jar"})
SCRIPTS = frozenset({".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".py", ".sh"})
CODE = PROGRAMS | SCRIPTS
SMALL = 5                       # files added or changed, at most, for a "small" update
_MAX_NAMES = 5                  # file names shown per reason
_MAX_WALK = 50_000              # files looked at per Workshop item, at most


# What an ID looks like: kind, app id, then the parts that pin down what was
# looked at. Only these characters, so a pasted command needs no quoting.
_KEY = re.compile(r"(workshop-[0-9]+-[0-9]+-[0-9a-f]{12}|update-[0-9]+-[0-9]+-[0-9]+|rename-[0-9]+-[0-9a-f]{12})")
_PROTECTED = False   # set for protected runs: acknowledging then needs sudo --protected


def valid_key(key: str) -> bool:
    return isinstance(key, str) and _KEY.fullmatch(key) is not None


def _number(text) -> bool:
    """An ID made of ASCII digits only ("١٢٣".isdigit() is True too)."""
    return isinstance(text, str) and text.isascii() and text.isdigit()


def show_protected_commands() -> None:
    global _PROTECTED
    _PROTECTED = True


@dataclass
class Finding:
    key: str
    kind: str                   # "workshop", "update" or "rename"
    appid: str
    game: str
    detail: list[str]
    library: str | None = None


# ----------------------------------------------------------------------
# Where Steam is
# ----------------------------------------------------------------------

def libraries(home: Path) -> list[Path]:
    """Every Steam library: the Steam folders in your home, plus the others
    their libraryfolders.vdf lists."""
    found: dict[Path, None] = {}
    for root in (home / r for r in steam._ROOTS):
        if not (root / "steamapps").is_dir():
            continue
        found[root.resolve()] = None
        text = steam._read_text(root / "steamapps" / "libraryfolders.vdf")
        folders = steam.parse_vdf(text).get("libraryfolders", {}) if text else {}
        for entry in folders.values() if isinstance(folders, dict) else ():
            path = entry.get("path") if isinstance(entry, dict) else None
            if isinstance(path, str) and Path(path).is_absolute() and (Path(path) / "steamapps").is_dir():
                found[Path(path).resolve()] = None
    return list(found)


def _apps(library: Path) -> dict[str, tuple[str | None, dict[str, str]]]:
    """{appid: (name or None, {depot: manifest id})} for the games installed there."""
    apps: dict[str, tuple[str | None, dict[str, str]]] = {}
    try:
        acfs = sorted((library / "steamapps").glob("appmanifest_*.acf"))
    except OSError:
        return apps
    for acf in acfs:
        text = steam._read_text(acf)
        state = steam.parse_vdf(text).get("appstate", {}) if text else {}
        if not isinstance(state, dict) or not _number(state.get("appid")):
            continue
        depots = state.get("installeddepots", {})
        depots = {d: v["manifest"] for d, v in depots.items()
                  if _number(d) and isinstance(v, dict) and _number(v.get("manifest"))} \
            if isinstance(depots, dict) else {}
        name = state.get("name") if isinstance(state.get("name"), str) and state["name"].strip() else None
        apps[state["appid"]] = (name, depots)
    return apps


def _suffix(name: str) -> str:
    return os.path.splitext(name)[1].lower()


# ----------------------------------------------------------------------
# A build, as a snapshot
# ----------------------------------------------------------------------

def _snapshot(data: bytes) -> tuple[bytes, dict[str, str], bool]:
    """(sorted 8-byte tokens for every file, {lowercased name: content SHA-1
    hex} for programs and scripts, names encrypted)."""
    encrypted, entries = steam.read_entries(data)
    tokens = sorted({hashlib.sha1(e.name_hash + e.content_hash).digest()[:8] for e in entries})
    code: dict[str, str] = {}
    if not encrypted:
        for e in entries:
            name = e.name.decode("utf-8", "replace").replace("\\", "/").lower()
            if _suffix(name) in CODE:
                code[name] = e.content_hash.hex()
    return b"".join(tokens), code, encrypted


def _tokens(blob: bytes) -> set[bytes]:
    return {blob[i:i + 8] for i in range(0, len(blob), 8)}


def _listed(label: str, names: list[str]) -> list[str]:
    """A label, then its names one per line under it, the last one ending
    the list (or "and N more.")."""
    shown_names = names[:_MAX_NAMES]
    rest = len(names) - len(shown_names)
    lines = [label]
    for i, name in enumerate(shown_names):
        last = i == len(shown_names) - 1
        lines.append(f"    {name}{'.' if last and not rest else ','}")
    if rest:
        lines.append(f"    and {rest} more.")
    return lines


def compare(old_files: bytes, old_code: dict[str, str], new_files: bytes, new_code: dict[str, str],
            encrypted: bool) -> list[list[str]]:
    """The reasons an update is worth a look, each as its lines; [] if none."""
    touched = len(_tokens(new_files) - _tokens(old_files))   # files added or changed
    if encrypted:
        return []   # no names to tell code from data
    added = sorted(n for n in new_code if n not in old_code)
    changed_programs = sorted(n for n in new_code if n in old_code and new_code[n] != old_code[n]
                              and _suffix(n) in PROGRAMS)
    added_scripts = [n for n in added if _suffix(n) in SCRIPTS]
    reasons = []
    small = f"A small update ({touched} file{'s' if touched != 1 else ''} added or changed)"
    if touched <= SMALL and added:
        reasons.append(_listed(f"{small} adds code:", added))
    if touched <= SMALL and changed_programs:
        reasons.append(_listed(f"{small} changes a program:", changed_programs))
    if added_scripts and not (touched <= SMALL and added):
        reasons.append(_listed("The update adds scripts:", added_scripts))
    return reasons


# ----------------------------------------------------------------------
# Workshop
# ----------------------------------------------------------------------

def _workshop_item(item: Path) -> tuple[list[str], str] | None:
    """(what's in it worth a look, a fingerprint of those files), or None."""
    code, protected, fingerprint = [], [], hashlib.sha1()
    seen = 0
    for dirpath, dirnames, names in os.walk(item):
        dirnames.sort()
        if seen > _MAX_WALK:
            break   # an item this big: what's been seen so far is what's listed
        for n in sorted(names):
            seen += 1
            if seen > _MAX_WALK:
                break
            path = Path(dirpath, n)
            s = _suffix(n)
            if s not in CODE and s != ".zip":
                continue
            try:
                st = path.lstat()
            except OSError:
                continue
            rel = os.fsdecode(path.relative_to(item))
            if s == ".zip":
                if not path.is_file() or path.is_symlink():
                    continue
                try:
                    with zipfile.ZipFile(path) as zf:
                        if not any(i.flag_bits & 1 for i in zf.infolist()):
                            continue
                except (OSError, zipfile.BadZipFile, ValueError):
                    continue
                protected.append(rel)
            else:
                code.append(rel)
            fingerprint.update(f"{rel}\0{st.st_size}\0{st.st_mtime_ns}\0".encode("utf-8", "surrogateescape"))
    if not code and not protected:
        return None
    detail: list[str] = []
    programs = [c for c in code if _suffix(c) in PROGRAMS]
    scripts = [c for c in code if _suffix(c) in SCRIPTS]
    if programs:
        detail += _listed("Programs:", programs)
    if scripts:
        detail += _listed("Scripts:", scripts)
    if protected:
        detail += _listed("Password-protected archives:", protected)
    return detail, fingerprint.hexdigest()[:12]


def _workshop_updated(library: Path, appid: str) -> dict[str, str]:
    """{item id: the day Steam last updated it} from appworkshop_<appid>.acf.
    Steam keeps no item names on disk (those are on its servers)."""
    text = steam._read_text(library / "steamapps" / "workshop" / f"appworkshop_{appid}.acf")
    state = steam.parse_vdf(text).get("appworkshop", {}) if text else {}
    items = state.get("workshopitemsinstalled", {}) if isinstance(state, dict) else {}
    days = {}
    for item, info in items.items() if isinstance(items, dict) else ():
        stamp = info.get("timeupdated") if isinstance(info, dict) else None
        if _number(item) and _number(stamp):
            try:
                days[item] = datetime.fromtimestamp(int(stamp), timezone.utc).strftime("%Y-%m-%d")
            except (OverflowError, OSError, ValueError):
                pass
    return days


def _workshop(library: Path, apps: dict[str, tuple[str | None, dict[str, str]]]) -> list[Finding]:
    content = library / "steamapps" / "workshop" / "content"
    found = []
    try:
        app_dirs = sorted(d for d in content.iterdir() if _number(d.name) and d.is_dir() and not d.is_symlink())
    except OSError:
        return found
    for app in app_dirs:
        game = apps.get(app.name, (None, {}))[0] or f"app {app.name}"
        try:
            items = sorted(d for d in app.iterdir() if _number(d.name) and d.is_dir() and not d.is_symlink())
        except OSError:
            continue
        updated = _workshop_updated(library, app.name) if items else {}
        for item in items:
            result = _workshop_item(item)
            if result:
                detail, fp = result
                when = f" (updated {updated[item.name]})" if item.name in updated else ""
                head = [f"Workshop item {item.name}{when}",
                        f"    {os.fsdecode(item)}",
                        f"    https://steamcommunity.com/sharedfiles/filedetails/?id={item.name}"]
                found.append(Finding(f"workshop-{app.name}-{item.name}-{fp}", "workshop", app.name, game,
                                     head + [f"    {line}" for line in detail]))
    return found


# ----------------------------------------------------------------------
# The watch
# ----------------------------------------------------------------------

def _manifest_path(library: Path, home: Path, depot: str, manifest: str) -> Path | None:
    name = f"{depot}_{manifest}.manifest"
    for cache in [library / "depotcache", *(home / r / "depotcache" for r in steam._ROOTS)]:
        if (cache / name).is_file():
            return cache / name
    return None


def watch(engine: Engine, home: Path) -> None:
    """Look at Steam now: record each installed depot's build, note what's
    worth a look since last time, and refresh the Workshop findings."""
    libs = libraries(home)
    seen_libs = {str(lib) for lib in libs}
    with Session(engine) as session:
        snapshots = {(r.appid, r.depot): r for r in session.query(SteamSnapshot)}
        pending = {r.key: r for r in session.query(SteamPending)}
        installed: set[str] = set()
        workshop: dict[str, Finding] = {}
        for library in libs:
            apps = _apps(library)
            for appid, (name, depots) in apps.items():
                installed.add(appid)
                game = name or f"app {appid}"
                known = [r for (a, _d), r in snapshots.items() if a == appid]
                for row in known:
                    row.library = str(library)
                if name and known and known[0].game and known[0].game != name:
                    key = f"rename-{appid}-{hashlib.sha1(game.encode('utf-8', 'replace')).hexdigest()[:12]}"
                    if key not in pending:
                        pending[key] = SteamPending(key=key, kind="rename", appid=appid, game=game,
                                                    library=str(library),
                                                    detail=f"Renamed: it was called {known[0].game}.")
                        session.add(pending[key])
                if name:   # no name in the appmanifest: keep the one we had, so it's no "rename"
                    for row in known:
                        row.game = name
                for depot, manifest in depots.items():
                    row = snapshots.get((appid, depot))
                    if row is not None and row.manifest == manifest:
                        continue   # unchanged since last time: nothing to read
                    path = _manifest_path(library, home, depot, manifest)
                    if path is None:
                        continue
                    try:
                        with open(path, "rb") as f:
                            data = f.read(steam._MAX_MANIFEST + 1)
                        files, code, encrypted = _snapshot(data)
                    except (OSError, ValueError) as e:
                        log.debug("can't read Steam manifest %s: %s", path, e)
                        continue
                    if row is None:   # first sight: record it, nothing to compare with yet
                        row = SteamSnapshot(appid=appid, depot=depot, manifest=manifest, game=name,
                                            library=str(library), files=files, code=json.dumps(code))
                        session.add(row)
                        snapshots[(appid, depot)] = row
                        continue
                    try:
                        old_code = json.loads(row.code or "{}")
                    except ValueError:
                        old_code = {}
                    reasons = compare(row.files, old_code, files, code, encrypted)
                    key = f"update-{appid}-{depot}-{manifest}"
                    if reasons and key not in pending:
                        pending[key] = SteamPending(key=key, kind="update", appid=appid, game=game,
                                                    library=str(library),
                                                    detail="\n".join([f"Depot {depot}, build {manifest}:",
                                                                      *(f"    {line}" for reason in reasons
                                                                        for line in reason)]))
                        session.add(pending[key])
                    row.manifest, row.files, row.code = manifest, files, json.dumps(code)
                    row.game = name or row.game
                    row.seen_at = utcnow()
            for f in _workshop(library, apps):
                f.library = str(library)
                workshop[f.key] = f

        def gone(library: str | None, appid: str) -> bool:
            """No longer installed, as far as can be seen: its library is here
            and lists no such game. A library that isn't (a drive not mounted)
            says nothing, so what was found there is kept."""
            return library in seen_libs and appid not in installed

        # Workshop findings are what's there now (in the libraries that are
        # here); the others stay until acknowledged, or the game is gone.
        for key, row in list(pending.items()):
            if (row.kind == "workshop" and row.library in seen_libs and key not in workshop) or \
                    (row.kind != "workshop" and gone(row.library, row.appid)):
                session.delete(row)
                del pending[key]
        for key, f in workshop.items():
            if key not in pending:
                pending[key] = SteamPending(key=key, kind="workshop", appid=f.appid, game=f.game,
                                            library=f.library, detail="\n".join(f.detail))
                session.add(pending[key])
            else:   # what's there now, in the current layout
                pending[key].detail, pending[key].game = "\n".join(f.detail), f.game
        for row in list(snapshots.values()):
            if gone(row.library, row.appid):
                session.delete(row)
        session.commit()


def open_findings(engine: Engine, decisions: Engine | None = None) -> list[Finding]:
    """What's listed and not acknowledged. decisions: where acknowledgments
    are read from (a protected run's are root's; the same engine otherwise)."""
    with Session(decisions or engine) as session:
        acked = {key for (key,) in session.query(SteamAcknowledged.key)}
    with Session(engine) as session:
        rows = session.query(SteamPending).order_by(SteamPending.kind, SteamPending.game,
                                                    SteamPending.key).all()
        # Only IDs in the form Ensign writes: the list goes into a command you
        # may paste with sudo, and this table is in a database you (and so,
        # anything running as you) can write.
        return [Finding(r.key, r.kind, r.appid, r.game or f"app {r.appid}", (r.detail or "").split("\n"))
                for r in rows if r.key not in acked and valid_key(r.key)]


def acknowledge(decisions: Engine, keys: list[str]) -> int:
    """Record keys as looked at. Returns how many were new."""
    added = 0
    with Session(decisions) as session:
        have = {k for (k,) in session.query(SteamAcknowledged.key)}
        for key in dict.fromkeys(keys):
            if key not in have:
                session.add(SteamAcknowledged(key=key))
                added += 1
        session.commit()
    return added


_KIND = {"workshop": "Workshop item carries code", "update": "Update worth a look", "rename": "Game renamed"}
_WHY = {"workshop": "Workshop items are uploaded by anyone and not reviewed like a game's own build; "
                    "static content (wallpapers, maps, music) shouldn't need programs or scripts.",
        "update": "Games have turned malicious through an update (BlockBlasters); a small update that "
                  "adds or changes code is the shape to look at.",
        "rename": "A game renamed and then updated is how one malicious game reached players (Beyond The Dark)."}


def report(findings: list[Finding]) -> None:
    """The section printed at the end of a scan, and by `ensign-scan steam`."""
    from rich import print as rprint

    from .commands import prefix
    from .fsutil import print_unwrapped, shown
    if not findings:
        return
    from rich.console import Console
    width = max(40, Console().width - 1)
    rprint(f"\n=== STEAM: WORTH A LOOK ({len(findings)}) ===")
    rprint("Ensign read Steam's files only. Each of these is a reason to look, not a verdict.")
    for kind in ("update", "rename", "workshop"):
        group = [f for f in findings if f.kind == kind]
        if not group:
            continue
        heading = f"{_KIND[kind]} ({len(group)}): {_WHY[kind]}"
        rprint("")
        for i, line in enumerate(textwrap.wrap(heading, width - 4, break_long_words=False)):
            if i == 0:
                rprint(f"    [bold]{_KIND[kind]}[/bold]{line[len(_KIND[kind]):]}")
            else:
                rprint(f"    {line}")
        for f in group:
            print_unwrapped(f"\n  {shown(f.game)} (app {f.appid})")
            for line in f.detail:
                print_unwrapped(f"      {shown(line)}")
            print(f"      ID: {shown(f.key)}")
    keys = " ".join(f.key for f in findings)
    if _PROTECTED:
        rprint("\n  Looked at them? Your decisions are protected, so acknowledging needs sudo:")
        print_unwrapped(f"    sudo {prefix().removeprefix('sudo ')} --protected acknowledge-steam {keys}")
    else:
        rprint("\n  Looked at one? Acknowledge it and it's not listed again (until it changes):")
        print(f"    {prefix()} acknowledge-steam ID ...   or, for all of them:   "
              f"{prefix()} acknowledge-steam --all")
