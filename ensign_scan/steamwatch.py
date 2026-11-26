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
import zipfile
from dataclasses import dataclass
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
_KEY = re.compile(r"(workshop-\d+-\d+-[0-9a-f]{12}|update-\d+-\d+-\d+|rename-\d+-[0-9a-f]{12})")
_PROTECTED = False   # set for protected runs: acknowledging then needs sudo --protected


def valid_key(key: str) -> bool:
    return _KEY.fullmatch(key) is not None


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


def _apps(library: Path) -> dict[str, tuple[str, dict[str, str]]]:
    """{appid: (name, {depot: manifest id})} for the games installed there."""
    apps: dict[str, tuple[str, dict[str, str]]] = {}
    try:
        acfs = sorted((library / "steamapps").glob("appmanifest_*.acf"))
    except OSError:
        return apps
    for acf in acfs:
        text = steam._read_text(acf)
        state = steam.parse_vdf(text).get("appstate", {}) if text else {}
        if not isinstance(state, dict) or not str(state.get("appid", "")).isdigit():
            continue
        depots = state.get("installeddepots", {})
        depots = {d: v["manifest"] for d, v in depots.items()
                  if d.isdigit() and isinstance(v, dict) and str(v.get("manifest", "")).isdigit()} \
            if isinstance(depots, dict) else {}
        name = state.get("name") if isinstance(state.get("name"), str) else f"app {state['appid']}"
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


def _names(names: list[str]) -> str:
    shown = ", ".join(names[:_MAX_NAMES])
    return shown + (f" and {len(names) - _MAX_NAMES} more" if len(names) > _MAX_NAMES else "")


def compare(old_files: bytes, old_code: dict[str, str], new_files: bytes, new_code: dict[str, str],
            encrypted: bool) -> list[str]:
    """The reasons an update is worth a look; [] if none."""
    touched = len(_tokens(new_files) - _tokens(old_files))   # files added or changed
    if encrypted:
        return []   # no names to tell code from data
    added = sorted(n for n in new_code if n not in old_code)
    changed_programs = sorted(n for n in new_code if n in old_code and new_code[n] != old_code[n]
                              and _suffix(n) in PROGRAMS)
    added_scripts = [n for n in added if _suffix(n) in SCRIPTS]
    reasons = []
    if touched <= SMALL and added:
        reasons.append(f"A small update ({touched} file{'s' if touched != 1 else ''} added or changed) "
                       f"adds code: {_names(added)}.")
    if touched <= SMALL and changed_programs:
        reasons.append(f"A small update ({touched} file{'s' if touched != 1 else ''} added or changed) "
                       f"changes a program: {_names(changed_programs)}.")
    if added_scripts and not (touched <= SMALL and added):
        reasons.append(f"The update adds scripts: {_names(added_scripts)}.")
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
    detail = []
    programs = [c for c in code if _suffix(c) in PROGRAMS]
    scripts = [c for c in code if _suffix(c) in SCRIPTS]
    if programs:
        detail.append(f"Programs: {_names(programs)}.")
    if scripts:
        detail.append(f"Scripts: {_names(scripts)}.")
    if protected:
        detail.append(f"Password-protected archives: {_names(protected)}.")
    return detail, fingerprint.hexdigest()[:12]


def _workshop(library: Path, apps: dict[str, tuple[str, dict[str, str]]]) -> list[Finding]:
    content = library / "steamapps" / "workshop" / "content"
    found = []
    try:
        app_dirs = sorted(d for d in content.iterdir() if d.name.isdigit() and d.is_dir() and not d.is_symlink())
    except OSError:
        return found
    for app in app_dirs:
        game = apps.get(app.name, (f"app {app.name}", {}))[0]
        try:
            items = sorted(d for d in app.iterdir() if d.name.isdigit() and d.is_dir() and not d.is_symlink())
        except OSError:
            continue
        for item in items:
            result = _workshop_item(item)
            if result:
                detail, fp = result
                found.append(Finding(f"workshop-{app.name}-{item.name}-{fp}", "workshop", app.name, game,
                                     [f"Workshop item {item.name}: {line}" for line in detail]))
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
    with Session(engine) as session:
        snapshots = {(r.appid, r.depot): r for r in session.query(SteamSnapshot)}
        pending = {r.key: r for r in session.query(SteamPending)}
        installed: set[str] = set()
        workshop: dict[str, Finding] = {}
        for library in libs:
            apps = _apps(library)
            for appid, (game, depots) in apps.items():
                installed.add(appid)
                known = [r for (a, _d), r in snapshots.items() if a == appid]
                if known and known[0].game and known[0].game != game:
                    key = f"rename-{appid}-{hashlib.sha1(game.encode('utf-8', 'replace')).hexdigest()[:12]}"
                    if key not in pending:
                        pending[key] = SteamPending(key=key, kind="rename", appid=appid, game=game,
                                                    detail=f"Renamed: it was called {known[0].game}.")
                        session.add(pending[key])
                for row in known:
                    row.game = game
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
                        row = SteamSnapshot(appid=appid, depot=depot, manifest=manifest, game=game,
                                            files=files, code=json.dumps(code))
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
                                                    detail="\n".join([f"Depot {depot}, build {manifest}:",
                                                                      *reasons]))
                        session.add(pending[key])
                    row.manifest, row.files, row.code, row.game = manifest, files, json.dumps(code), game
                    row.seen_at = utcnow()
            for f in _workshop(library, apps):
                workshop[f.key] = f
        # Workshop findings are what's there now; the others stay until acknowledged,
        # or until the game is no longer installed.
        for key, row in list(pending.items()):
            if (row.kind == "workshop" and key not in workshop) or \
                    (row.kind != "workshop" and libs and row.appid not in installed):
                session.delete(row)
                del pending[key]
        for key, f in workshop.items():
            if key not in pending:
                pending[key] = SteamPending(key=key, kind="workshop", appid=f.appid, game=f.game,
                                            detail="\n".join(f.detail))
                session.add(pending[key])
        if libs:
            for (appid, _depot), row in list(snapshots.items()):
                if appid not in installed:
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
        return [Finding(r.key, r.kind, r.appid, r.game or f"app {r.appid}", (r.detail or "").split("\n"))
                for r in rows if r.key not in acked]


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
    rprint(f"\n=== STEAM: WORTH A LOOK ({len(findings)}) ===")
    rprint("Ensign read Steam's files only. Each of these is a reason to look, not a verdict.")
    for kind in ("update", "rename", "workshop"):
        group = [f for f in findings if f.kind == kind]
        if not group:
            continue
        rprint(f"\n[bold]{_KIND[kind]}[/bold] ({len(group)}): {_WHY[kind]}")
        for f in group:
            print_unwrapped(f"\n  {shown(f.game)} (app {f.appid})")
            for line in f.detail:
                print_unwrapped(f"      {shown(line)}")
            print(f"      ID: {f.key}")
    keys = " ".join(f.key for f in findings)
    if _PROTECTED:
        rprint("\n  Looked at them? Your decisions are protected, so acknowledging needs sudo:")
        print_unwrapped(f"    sudo {prefix().removeprefix('sudo ')} --protected acknowledge-steam {keys}")
    else:
        rprint("\n  Looked at one? Acknowledge it and it's not listed again (until it changes):")
        print(f"    {prefix()} acknowledge-steam ID ...   or, for all of them:   "
              f"{prefix()} acknowledge-steam --all")
