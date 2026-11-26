#!/usr/bin/env python3
"""Could Steam's own records vouch for game files Ensign flags?

Steam keeps a manifest for each installed depot (a part of a game) in a
`depotcache` folder: every file of that exact build, with its size and
SHA-1. It's what "Verify integrity of game files" checks against. This
probe reads them, read-only, and answers the questions the design
depends on:

  1. How many installed depots have their manifest on disk at all.
  2. How many manifests have encrypted file names, and whether a file can
     still be matched through the SHA-1 of its name (sha_filename), which
     needs no key.
  3. Whether the SHA-1s match the files on disk (a sample of files per game).
  4. Proton prefixes: how many of the Windows DLLs in each game's prefix
     are byte-for-byte copies of a file that ships with a Proton install.
  5. With --ensign-db: how many flagged files these two sources vouch for.

Prints counts only, never paths or game names, unless --show. Reads
Steam's files and hashes a sample of game files; changes nothing.
Standard library only.

    python experiments/hash-libraries/steam_probe.py
    python experiments/hash-libraries/steam_probe.py --ensign-db ~/.local/share/ensign-scan/system.db
    python experiments/hash-libraries/steam_probe.py --steam-root /path/to/Steam --per-game 50
"""
from __future__ import annotations

import argparse
import hashlib
import io
import os
import random
import re
import sqlite3
import struct
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

PAYLOAD_MAGIC, METADATA_MAGIC = 0x71F617D0, 0x1F4812BE
SIGNATURE_MAGIC, END_MAGIC = 0x1B81B817, 0x32C415AB
FLAG_DIRECTORY = 64   # EDepotFileFlag.Directory
MAX_HASH_BYTES = 512 * 2**20   # skip files bigger than this in samples (--big lifts it)


# ----------------------------------------------------------------------
# Steam's text formats (VDF / ACF): just enough to read nested key/values
# ----------------------------------------------------------------------

_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|([{}])')


def parse_vdf(text: str) -> dict:
    stack, current, key = [], {}, None
    for quoted, brace in _TOKEN.findall(text):
        if brace == "{":
            child = {}
            current[key] = child
            stack.append(current)
            current, key = child, None
        elif brace == "}":
            current = stack.pop() if stack else current
        elif key is None:
            key = quoted.replace("\\\\", "\\")
        else:
            current[key] = quoted.replace("\\\\", "\\")
            key = None
    return current


def lower_keys(d):
    return {k.lower(): lower_keys(v) if isinstance(v, dict) else v for k, v in d.items()}


# ----------------------------------------------------------------------
# Depot manifests: zip (maybe) around sections of protobuf
# ----------------------------------------------------------------------

def _varint(buf: bytes, i: int) -> tuple[int, int]:
    shift = result = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7


def protobuf_fields(buf: bytes):
    """(field number, value) pairs; length-delimited values as bytes."""
    i = 0
    while i < len(buf):
        tag, i = _varint(buf, i)
        number, wire = tag >> 3, tag & 7
        if wire == 0:
            value, i = _varint(buf, i)
        elif wire == 1:
            value, i = buf[i:i + 8], i + 8
        elif wire == 2:
            length, i = _varint(buf, i)
            value, i = buf[i:i + length], i + length
        elif wire == 5:
            value, i = buf[i:i + 4], i + 4
        else:
            raise ValueError(f"protobuf wire type {wire}")
        yield number, value


@dataclass
class Mapping:
    filename: bytes
    size: int = 0
    flags: int = 0
    sha_filename: bytes = b""
    sha_content: bytes = b""


@dataclass
class Manifest:
    depot_id: int = 0
    encrypted: bool = False
    mappings: list[Mapping] = field(default_factory=list)


def parse_manifest(data: bytes) -> Manifest:
    if data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            data = zf.read(zf.filelist[0])
    manifest, i = Manifest(), 0
    while i + 4 <= len(data):
        (magic,) = struct.unpack_from("<I", data, i)
        if magic == END_MAGIC:
            break
        length = struct.unpack_from("<I", data, i + 4)[0]
        body, i = data[i + 8:i + 8 + length], i + 8 + length
        if magic == PAYLOAD_MAGIC:
            for number, value in protobuf_fields(body):
                if number == 1:
                    m = Mapping(b"")
                    for n, v in protobuf_fields(value):
                        if n == 1:
                            m.filename = v
                        elif n == 2:
                            m.size = v
                        elif n == 3:
                            m.flags = v
                        elif n == 4:
                            m.sha_filename = v
                        elif n == 5:
                            m.sha_content = v
                    manifest.mappings.append(m)
        elif magic == METADATA_MAGIC:
            for number, value in protobuf_fields(body):
                if number == 1:
                    manifest.depot_id = value
                elif number == 4:
                    manifest.encrypted = bool(value)
        elif magic != SIGNATURE_MAGIC:
            raise ValueError(f"unknown section 0x{magic:08x}")
    return manifest


def name_hashes(relpath: str) -> dict[str, bytes]:
    """The forms Steam might hash a file name in, to learn which one it uses."""
    forms = {"lower, backslashes": relpath.replace("/", "\\").lower(),
             "lower, slashes": relpath.lower(),
             "as is, backslashes": relpath.replace("/", "\\")}
    return {k: hashlib.sha1(v.encode("utf-8", "surrogateescape")).digest() for k, v in forms.items()}


# ----------------------------------------------------------------------
# Finding Steam
# ----------------------------------------------------------------------

def steam_roots(given: list[Path]) -> list[Path]:
    home = Path.home()
    candidates = given or [home / ".local/share/Steam", home / ".steam/steam", home / ".steam/root",
                           home / ".var/app/com.valvesoftware.Steam/.local/share/Steam"]
    seen, roots = set(), []
    for c in candidates:
        if (c / "steamapps").is_dir() and c.resolve() not in seen:
            seen.add(c.resolve())
            roots.append(c)
    return roots


def libraries(root: Path) -> list[Path]:
    libs = {root.resolve()}
    vdf = root / "steamapps" / "libraryfolders.vdf"
    if vdf.is_file():
        for entry in lower_keys(parse_vdf(vdf.read_text(errors="replace"))).get("libraryfolders", {}).values():
            if isinstance(entry, dict) and entry.get("path"):
                libs.add(Path(entry["path"]).resolve())
    return sorted(p for p in libs if (p / "steamapps").is_dir())


@dataclass
class Game:
    appid: str
    name: str
    install: Path
    depots: dict[str, str]           # depot id -> manifest id
    manifests: list[Manifest] = field(default_factory=list)
    missing: int = 0


def games(roots: list[Path]) -> list[Game]:
    caches = [r / "depotcache" for r in roots]
    found = []
    for root in roots:
        for lib in libraries(root):
            caches.append(lib / "depotcache")
            for acf in sorted((lib / "steamapps").glob("appmanifest_*.acf")):
                try:
                    state = lower_keys(parse_vdf(acf.read_text(errors="replace"))).get("appstate", {})
                except OSError:
                    continue
                depots = {d: v.get("manifest", "") for d, v in state.get("installeddepots", {}).items()
                          if isinstance(v, dict)}
                found.append(Game(state.get("appid", "?"), state.get("name", "?"),
                                  lib / "steamapps" / "common" / state.get("installdir", ""), depots))
    for game in found:
        for depot, manifest_id in game.depots.items():
            path = next((c / f"{depot}_{manifest_id}.manifest" for c in caches
                         if (c / f"{depot}_{manifest_id}.manifest").is_file()), None)
            if path is None:
                game.missing += 1
                continue
            try:
                game.manifests.append(parse_manifest(path.read_bytes()))
            except (OSError, ValueError, zipfile.BadZipFile, IndexError, struct.error):
                game.missing += 1
    return found


def sha1_of(path: Path) -> bytes:
    digest = hashlib.sha1()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            digest.update(chunk)
    return digest.digest()


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


# ----------------------------------------------------------------------
# The checks
# ----------------------------------------------------------------------

def check_games(found: list[Game], per_game: int, big: bool, show: bool) -> Counter:
    tally = Counter()
    for game in found:
        if not game.install.is_dir():
            continue
        files = [m for man in game.manifests for m in man.mappings
                 if not m.flags & FLAG_DIRECTORY and m.sha_content and (big or m.size <= MAX_HASH_BYTES)]
        encrypted = any(man.encrypted for man in game.manifests)
        by_name_hash = {m.sha_filename: m for m in files}
        if encrypted:
            # Names can't be read: walk the install folder and match each file
            # through the SHA-1 of its own name.
            on_disk = [p for p in game.install.rglob("*") if p.is_file() and not p.is_symlink()]
            picks = random.sample(on_disk, min(per_game, len(on_disk)))
            for p in picks:
                rel = os.fsdecode(p.relative_to(game.install))
                form = next((k for k, h in name_hashes(rel).items() if h in by_name_hash), None)
                tally[f"encrypted names: matched by name hash ({form})" if form else
                      "encrypted names: no name hash matched"] += 1
                if form:
                    m = by_name_hash[name_hashes(rel)[form]]
                    if big or m.size <= MAX_HASH_BYTES:
                        tally["content SHA-1 matches" if sha1_of(p) == m.sha_content
                              else "content SHA-1 differs"] += 1
        else:
            for m in random.sample(files, min(per_game, len(files))):
                rel = os.path.join(*os.fsdecode(m.filename.rstrip(b"\x00 \n\t")).split("\\"))
                path = game.install / rel
                if not path.is_file():
                    tally["listed but not on disk"] += 1
                    continue
                same = sha1_of(path) == m.sha_content
                tally["content SHA-1 matches" if same else "content SHA-1 differs"] += 1
                if not same and show:
                    print(f"    differs: {game.name}: {rel}")
                if name_hashes(rel)["lower, backslashes"] == m.sha_filename:
                    tally["name hash = SHA-1 of lowercase name with backslashes"] += 1
    return tally


def proton_index(roots: list[Path]) -> dict[str, list[Path]]:
    """SHA-256 -> files, for every .dll/.exe that ships with a Proton install."""
    index: dict[str, list[Path]] = {}
    for root in roots:
        for lib in libraries(root):
            for proton in sorted((lib / "steamapps" / "common").glob("Proton*")):
                for p in proton.rglob("*"):
                    if p.suffix.lower() in (".dll", ".exe") and p.is_file() and not p.is_symlink():
                        try:
                            index.setdefault(sha256_of(p), []).append(p)
                        except OSError:
                            pass
    return index


def check_prefixes(roots: list[Path], index: dict[str, list[Path]], per_prefix: int) -> Counter:
    tally = Counter()
    for root in roots:
        for lib in libraries(root):
            for prefix in sorted((lib / "steamapps" / "compatdata").glob("*/pfx/drive_c/windows")):
                tally["prefixes"] += 1
                dlls = [p for d in ("system32", "syswow64") for p in (prefix / d).glob("*.dll")
                        if p.is_file() and not p.is_symlink()]
                tally["prefix DLLs that are links (to Proton's files)"] += sum(
                    1 for d in ("system32", "syswow64") for p in (prefix / d).glob("*.dll") if p.is_symlink())
                for p in random.sample(dlls, min(per_prefix, len(dlls))):
                    twins = index.get(sha256_of(p), [])
                    tally["DLL is a copy of a Proton file" if twins else "DLL not in any Proton install"] += 1
                    if twins and any(t.name.lower() == p.name.lower() for t in twins):
                        tally["  ...with the same file name"] += 1
    return tally


def check_flagged(ensign_db: Path, found: list[Game], index: dict[str, list[Path]], show: bool) -> Counter:
    conn = sqlite3.connect(f"{ensign_db.resolve().as_uri()}?mode=ro", uri=True)
    rows = conn.execute("SELECT filepath, file_hash, threat_name FROM files "
                        "WHERE scan_status IN ('infected', 'allowed')").fetchall()
    conn.close()
    tally = Counter(flagged=len(rows))
    for raw, digest, threat in rows:
        path = Path(os.fsdecode(raw) if isinstance(raw, bytes) else raw)
        if digest and digest in index:
            tally["vouched for: a copy of a Proton file"] += 1
            if show:
                print(f"    Proton copy: {path}  [{threat}]")
            continue
        game = next((g for g in found if g.install.is_dir() and path.is_relative_to(g.install)), None)
        if game is None:
            continue
        tally["in a Steam game folder"] += 1
        rel = os.fsdecode(path.relative_to(game.install))
        entry = None
        for man in game.manifests:
            for m in man.mappings:
                if (not man.encrypted and os.path.join(*os.fsdecode(m.filename.rstrip(b"\x00 \n\t")).split("\\")) == rel) \
                        or m.sha_filename in name_hashes(rel).values():
                    entry = m
                    break
            if entry:
                break
        if entry is None:
            tally["  ...not in that game's manifests"] += 1
            continue
        try:
            same = sha1_of(path) == entry.sha_content
        except OSError:
            tally["  ...couldn't be read"] += 1
            continue
        tally["  ...vouched for: Steam's manifest has this exact file" if same
              else "  ...differs from Steam's manifest"] += 1
        if show:
            print(f"    {'matches' if same else 'DIFFERS'}: {path}  [{threat}]")
    return tally


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--steam-root", type=Path, action="append", default=[])
    ap.add_argument("--ensign-db", type=Path)
    ap.add_argument("--per-game", type=int, default=20, help="files to hash per game (default 20)")
    ap.add_argument("--per-prefix", type=int, default=20, help="DLLs to hash per Proton prefix (default 20)")
    ap.add_argument("--big", action="store_true", help=f"also hash files over {MAX_HASH_BYTES >> 20} MiB")
    ap.add_argument("--no-proton", action="store_true", help="skip the Proton checks (they hash every Proton DLL)")
    ap.add_argument("--show", action="store_true", help="print paths and game names for flagged files and mismatches")
    args = ap.parse_args()

    roots = steam_roots(args.steam_root)
    if not roots:
        print("No Steam folder found. Pass --steam-root.")
        return 1
    found = games(roots)
    depots = sum(len(g.depots) for g in found)
    manifests = sum(len(g.manifests) for g in found)
    print(f"Steam folders: {len(roots)}; libraries: {len({l for r in roots for l in libraries(r)})}")
    print(f"Installed games: {len(found)}; depots: {depots}; manifests on disk: {manifests} "
          f"({manifests * 100 // max(1, depots)}%)")
    print(f"Games with every manifest: {sum(1 for g in found if g.depots and not g.missing)}; "
          f"with none: {sum(1 for g in found if g.depots and not g.manifests)}")
    print(f"Manifests with encrypted names: {sum(1 for g in found for m in g.manifests if m.encrypted)}")
    print(f"Files listed: {sum(len(m.mappings) for g in found for m in g.manifests)}")

    print(f"\nSample of up to {args.per_game} files per game:")
    for k, v in sorted(check_games(found, args.per_game, args.big, args.show).items()):
        print(f"  {k}: {v}")

    index = {}
    if not args.no_proton:
        index = proton_index(roots)
        print(f"\nProton: {sum(len(v) for v in index.values())} DLL/EXE files in Proton installs "
              f"({len(index)} distinct)")
        for k, v in check_prefixes(roots, index, args.per_prefix).items():
            print(f"  {k}: {v}")

    if args.ensign_db:
        print("\nFiles Ensign has flagged:")
        for k, v in check_flagged(args.ensign_db, found, index, args.show).items():
            print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
