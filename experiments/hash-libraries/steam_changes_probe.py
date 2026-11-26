#!/usr/bin/env python3
"""How noisy would "watch what changes between Steam builds" and "Workshop
items carrying code" be? Measures both on your real Steam folders.

  1. History: does Steam keep more than one manifest per depot in
     depotcache? If it does, the last update of each game can be compared
     with the one before, with no history of Ensign's own.
  2. Updates: for each depot with two or more manifests, what the newest
     build changed against the one before: scripts added (.bat, .cmd,
     .ps1, .vbs, .js, .py...), new executables (.exe, .dll...), executables
     changed, and how big the update was. These are the signals an
     update-watcher would raise; their counts on legitimate updates are
     its noise.
  3. Workshop: how many items under steamapps/workshop/content contain
     programs, scripts or archives (and zip archives with a password), per
     game, since static content (wallpapers, maps, music) shouldn't need any.

Prints counts only, unless --show (app ids, item ids, file names). Reads
Steam's files and lists folders; hashes nothing; changes nothing. Standard
library only.

    python experiments/hash-libraries/steam_changes_probe.py
    python experiments/hash-libraries/steam_changes_probe.py --show
    python experiments/hash-libraries/steam_changes_probe.py --steam-root /path/to/Steam
"""
from __future__ import annotations

import argparse
import io
import os
import re
import struct
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

PAYLOAD, METADATA, SIGNATURE, END = 0x71F617D0, 0x1F4812BE, 0x1B81B817, 0x32C415AB
DIRECTORY = 64
PROGRAMS = {".exe", ".dll", ".scr", ".com", ".sys", ".msi", ".so", ".elf", ".jar"}
SCRIPTS = {".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".py", ".sh", ".lua"}
ARCHIVES = {".zip", ".7z", ".rar"}
ROOTS = (".local/share/Steam", ".steam/steam", ".steam/root", ".var/app/com.valvesoftware.Steam/.local/share/Steam")
_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|([{}])')


def parse_vdf(text: str) -> dict:
    stack, current, key = [], {}, None
    for quoted, brace in _TOKEN.findall(text):
        if brace == "{":
            child = {}
            if key is not None:
                current[key.lower()] = child
            stack.append(current)
            current, key = child, None
        elif brace == "}":
            current, key = (stack.pop() if stack else current), None
        elif key is None:
            key = quoted
        else:
            current[key.lower()], key = quoted, None
    return current


def varint(buf, i):
    shift = result = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7


def fields(buf):
    i = 0
    while i < len(buf):
        tag, i = varint(buf, i)
        wire = tag & 7
        if wire == 0:
            value, i = varint(buf, i)
        elif wire == 2:
            n, i = varint(buf, i)
            value, i = buf[i:i + n], i + n
        elif wire in (1, 5):
            w = 8 if wire == 1 else 4
            value, i = buf[i:i + w], i + w
        else:
            raise ValueError(wire)
        yield tag >> 3, value


def read_manifest(path: Path) -> tuple[int, dict[str, bytes], bool] | None:
    """(creation time, {lowercased name: content SHA-1}, names encrypted)."""
    try:
        data = path.read_bytes()
        if data[:2] == b"PK":
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                data = zf.read(zf.infolist()[0])
        created, encrypted, files, i = 0, False, {}, 0
        while i + 8 <= len(data):
            magic, length = struct.unpack_from("<II", data, i)
            if magic == END:
                break
            body, i = data[i + 8:i + 8 + length], i + 8 + length
            if magic == PAYLOAD:
                for n, m in fields(body):
                    if n != 1:
                        continue
                    name, flags, sha = b"", 0, b""
                    for k, v in fields(m):
                        if k == 1:
                            name = v
                        elif k == 3:
                            flags = v
                        elif k == 5:
                            sha = v
                    if not flags & DIRECTORY:
                        files[name.decode("utf-8", "replace").replace("\\", "/").lower()] = sha
            elif magic == METADATA:
                for n, v in fields(body):
                    if n == 3 and isinstance(v, int):
                        created = v
                    elif n == 4:
                        encrypted = bool(v)
        return created, files, encrypted
    except (OSError, ValueError, IndexError, struct.error, zipfile.BadZipFile):
        return None


def steam_roots(given):
    home = Path.home()
    seen, out = set(), []
    for c in given or [home / r for r in ROOTS]:
        if (c / "steamapps").is_dir() and c.resolve() not in seen:
            seen.add(c.resolve())
            out.append(c)
    return out


def libraries(root: Path) -> list[Path]:
    libs = {root.resolve()}
    vdf = root / "steamapps" / "libraryfolders.vdf"
    try:
        for entry in parse_vdf(vdf.read_text(errors="replace")).get("libraryfolders", {}).values():
            if isinstance(entry, dict) and entry.get("path"):
                libs.add(Path(entry["path"]).resolve())
    except OSError:
        pass
    return sorted(p for p in libs if (p / "steamapps").is_dir())


def suffix(name: str) -> str:
    return os.path.splitext(name)[1].lower()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--steam-root", type=Path, action="append", default=[])
    ap.add_argument("--show", action="store_true", help="print app ids, item ids and file names")
    args = ap.parse_args()
    roots = steam_roots(args.steam_root)
    if not roots:
        print("No Steam folder found. Pass --steam-root.")
        return 1
    libs = sorted({lib for r in roots for lib in libraries(r)})
    caches = [r / "depotcache" for r in roots] + [lib / "depotcache" for lib in libs]

    # 1. History
    by_depot: dict[str, list[Path]] = defaultdict(list)
    for cache in caches:
        for m in cache.glob("*_*.manifest") if cache.is_dir() else []:
            depot = m.name.split("_", 1)[0]
            if m.resolve() not in {p.resolve() for p in by_depot[depot]}:
                by_depot[depot].append(m)
    depth = Counter(min(len(v), 4) for v in by_depot.values())
    print(f"Depots with manifests: {len(by_depot)}")
    print("  manifests kept per depot: " + ", ".join(
        f"{'4+' if k == 4 else k}: {depth[k]}" for k in sorted(depth)))

    # 2. Updates: newest vs the one before, where Steam kept both
    tally, shown = Counter(), 0
    for depot, paths in sorted(by_depot.items()):
        if len(paths) < 2:
            continue
        read = [r for r in (read_manifest(p) for p in paths) if r is not None]
        if len(read) < 2:
            tally["updates unreadable"] += 1
            continue
        read.sort(key=lambda r: r[0])
        (_, old, enc_old), (_, new, enc_new) = read[-2], read[-1]
        if enc_old or enc_new:
            tally["updates with encrypted names (not compared)"] += 1
            continue
        tally["updates compared"] += 1
        added = set(new) - set(old)
        changed = {n for n in set(new) & set(old) if new[n] != old[n]}
        added_scripts = sorted(n for n in added if suffix(n) in SCRIPTS)
        added_programs = sorted(n for n in added if suffix(n) in PROGRAMS)
        changed_programs = sorted(n for n in changed if suffix(n) in PROGRAMS)
        small = len(added) + len(changed) <= 5
        tally["  ...adding scripts"] += bool(added_scripts)
        tally["  ...adding new programs (.exe/.dll/...)"] += bool(added_programs)
        tally["  ...changing programs"] += bool(changed_programs)
        tally["  ...small updates (5 files or fewer) that change a program"] += small and bool(changed_programs)
        tally["  ...small updates that add a script or program"] += small and bool(added_scripts or added_programs)
        if args.show and (added_scripts or added_programs) and shown < 40:
            shown += 1
            print(f"    depot {depot}: +{len(added)} ~{len(changed)} files; "
                  f"new: {', '.join((added_scripts + added_programs)[:6])}")
    print("\nLast update of each depot, where Steam kept the one before:")
    for k in ("updates compared", "  ...adding scripts", "  ...adding new programs (.exe/.dll/...)",
              "  ...changing programs", "  ...small updates (5 files or fewer) that change a program",
              "  ...small updates that add a script or program", "updates with encrypted names (not compared)",
              "updates unreadable"):
        print(f"  {k}: {tally[k]}")

    # 3. Workshop
    per_app: dict[str, Counter] = defaultdict(Counter)
    for lib in libs:
        content = lib / "steamapps" / "workshop" / "content"
        if not content.is_dir():
            continue
        for app in sorted(content.iterdir()):
            if not app.is_dir():
                continue
            for item in sorted(app.iterdir()):
                if not item.is_dir():
                    continue
                kinds, notes = set(), []
                for dirpath, _dirs, names in os.walk(item):
                    for n in names:
                        s = suffix(n)
                        if s in PROGRAMS:
                            kinds.add("programs")
                        elif s in SCRIPTS:
                            kinds.add("scripts" if s != ".lua" else "lua")
                        elif s in ARCHIVES:
                            kinds.add("archives")
                            if s == ".zip":
                                try:
                                    with zipfile.ZipFile(Path(dirpath, n)) as zf:
                                        if any(i.flag_bits & 1 for i in zf.infolist()):
                                            kinds.add("password-protected zips")
                                except (OSError, zipfile.BadZipFile):
                                    pass
                        if args.show and s in PROGRAMS | SCRIPTS and len(notes) < 3:
                            notes.append(n)
                c = per_app[app.name]
                c["items"] += 1
                for k in kinds:
                    c[k] += 1
                if args.show and kinds - {"lua"}:
                    print(f"    workshop {app.name}/{item.name}: {', '.join(sorted(kinds))}  {', '.join(notes)}")
    print("\nWorkshop items, per game (app ids):")
    if not per_app:
        print("  none")
    total = Counter()
    for app, c in sorted(per_app.items()):
        total.update(c)
        detail = ", ".join(f"{k}: {c[k]}" for k in ("programs", "scripts", "lua", "archives", "password-protected zips")
                           if c[k])
        print(f"  {app if args.show else 'a game'}: {c['items']} items" + (f"; with {detail}" if detail else ""))
    print(f"  all: {total['items']} items in {len(per_app)} games; with programs {total['programs']}, "
          f"scripts {total['scripts']}, lua {total['lua']}, archives {total['archives']}, "
          f"password-protected zips {total['password-protected zips']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
