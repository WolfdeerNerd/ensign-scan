"""Steam's own record of a game's files, as a second opinion on a flagged one.

For every depot (a part of a game) it installs, Steam keeps a manifest in a
`depotcache` folder: each file of that exact build, with its SHA-1. It's
what "Verify integrity of game files" checks against. When a flagged file
sits in a Steam library's steamapps/common folder, check() finds the game
that owns that folder and looks the file up in that game's manifests:

  MATCH     Steam's record has this file with exactly these bytes
  DIFFERS   Steam's record has this file, with other bytes (games rewrite
            some of their own files, so this alone isn't a warning)
  WORKSHOP  the file is Steam Workshop content (steamapps/workshop/content/
            <appid>/<item>/...): uploaded by a community member, so it gets
            a caveat and never a match, whatever Steam's records say

A file the record doesn't list gets no answer, and neither does anything
in a Proton prefix (compatdata), the shader cache, or anywhere else Steam
doesn't install from a game's depots. Everything is local and
read-only: Steam's text files (libraryfolders.vdf, appmanifest_*.acf) and
its manifests, which are a zip around sections of protobuf.

What a MATCH is worth: where the file came from, not whether it's safe.
Games have shipped malware inside their official Steam builds (PirateFi,
Chemia, BlockBlasters, Beyond The Dark, 2023's hijacked developer
accounts), and those files matched Steam's record. The record also lives
in your home folder, where anything running as you could change it along
with the file, and Ensign can't check Valve's signature on it. So it's a
line next to the hit, never a verdict, and never "likely false positive".

Format notes (checked against a real Steam install, Nov 2026): sections
are <uint32 LE magic><uint32 LE length><protobuf>; a file's entry has its
name (Windows separators), size, flags, the SHA-1 of its lowercased name
and the SHA-1 of its content. The name's hash is used for matching, so a
manifest whose names are encrypted still works.
"""
from __future__ import annotations

import hashlib
import io
import logging
import os
import pwd
import re
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .fsutil import NotScannable, open_for_scan

log = logging.getLogger(__name__)

MATCH = "steam-installed"
DIFFERS = "steam-differs"
WORKSHOP = "steam-workshop"

_PAYLOAD, _METADATA, _SIGNATURE, _END = 0x71F617D0, 0x1F4812BE, 0x1B81B817, 0x32C415AB
_DIRECTORY = 64                  # EDepotFileFlag.Directory
_MAX_MANIFEST = 256 * 2**20      # a manifest bigger than this (zipped or not) isn't read
_MAX_TEXT = 4 * 2**20            # .vdf / .acf files
_ROOTS = (".local/share/Steam", ".steam/steam", ".steam/root",
          ".var/app/com.valvesoftware.Steam/.local/share/Steam")


@dataclass(frozen=True)
class Answer:
    verdict: str                 # MATCH, DIFFERS or WORKSHOP
    game: str                    # the game's name, as Steam has it


# ----------------------------------------------------------------------
# Steam's text format (VDF): nested "key" "value" / "key" { ... }
# ----------------------------------------------------------------------

_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|([{}])')


def parse_vdf(text: str) -> dict:
    stack: list[dict] = []
    current: dict = {}
    key = None
    for quoted, brace in _TOKEN.findall(text):
        if brace == "{":
            child: dict = {}
            if key is not None:
                current[key.lower()] = child
            stack.append(current)
            current, key = child, None
        elif brace == "}":
            if stack:
                current = stack.pop()
            key = None
        elif key is None:
            key = quoted.replace("\\\\", "\\")
        else:
            current[key.lower()] = quoted.replace("\\\\", "\\")
            key = None
    return current


def _read_text(path: Path) -> str | None:
    try:
        with open(path, "rb") as f:
            data = f.read(_MAX_TEXT + 1)
    except OSError:
        return None
    return None if len(data) > _MAX_TEXT else data.decode("utf-8", "replace")


# ----------------------------------------------------------------------
# Manifests
# ----------------------------------------------------------------------

def _varint(buf: bytes, i: int) -> tuple[int, int]:
    shift = result = 0
    while True:
        if i >= len(buf) or shift > 63:
            raise ValueError("truncated varint")
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7


def _fields(buf: bytes):
    """(field number, value) for each protobuf field; length-delimited
    values as bytes. Raises ValueError on anything malformed."""
    i = 0
    while i < len(buf):
        tag, i = _varint(buf, i)
        wire = tag & 7
        if wire == 0:
            value, i = _varint(buf, i)
        elif wire == 2:
            length, i = _varint(buf, i)
            if i + length > len(buf):
                raise ValueError("truncated field")
            value, i = buf[i:i + length], i + length
        elif wire in (1, 5):
            width = 8 if wire == 1 else 4
            if i + width > len(buf):
                raise ValueError("truncated field")
            value, i = buf[i:i + width], i + width
        else:
            raise ValueError(f"wire type {wire}")
        yield tag >> 3, value


@dataclass(frozen=True)
class Entry:
    name: bytes                  # as stored: Windows separators; unreadable if names are encrypted
    name_hash: bytes             # SHA-1 of the lowercased name
    content_hash: bytes          # SHA-1 of the content


def read_entries(data: bytes) -> tuple[bool, list[Entry]]:
    """(names encrypted, every file (not folder) in a manifest). Raises
    ValueError if it can't be read: size-capped, including after unzipping,
    and every field bounds-checked."""
    if data[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                member = zf.infolist()[0]
                if member.file_size > _MAX_MANIFEST:
                    raise ValueError("manifest too large")
                with zf.open(member) as f:
                    data = f.read(_MAX_MANIFEST + 1)
        except (zipfile.BadZipFile, IndexError, OSError, EOFError) as e:
            raise ValueError(f"bad zip: {e}") from e
        if len(data) > _MAX_MANIFEST:
            raise ValueError("manifest too large")
    entries: list[Entry] = []
    encrypted = False
    i = 0
    while i + 4 <= len(data):
        (magic,) = struct.unpack_from("<I", data, i)
        if magic == _END:
            break
        if i + 8 > len(data):
            raise ValueError("truncated section")
        (length,) = struct.unpack_from("<I", data, i + 4)
        body, i = data[i + 8:i + 8 + length], i + 8 + length
        if len(body) != length:
            raise ValueError("truncated section")
        if magic == _PAYLOAD:
            for number, mapping in _fields(body):
                if number != 1 or not isinstance(mapping, bytes):
                    continue
                name, flags, name_sha, content_sha = b"", 0, b"", b""
                for n, v in _fields(mapping):
                    if n == 1 and isinstance(v, bytes):
                        name = v
                    elif n == 3 and isinstance(v, int):
                        flags = v
                    elif n == 4 and isinstance(v, bytes):
                        name_sha = v
                    elif n == 5 and isinstance(v, bytes):
                        content_sha = v
                if not flags & _DIRECTORY and len(name_sha) == 20 and len(content_sha) == 20:
                    entries.append(Entry(name, name_sha, content_sha))
        elif magic == _METADATA:
            for n, v in _fields(body):
                if n == 4 and isinstance(v, int):
                    encrypted = bool(v)
        elif magic != _SIGNATURE:
            raise ValueError(f"unknown section 0x{magic:08x}")
    return encrypted, entries


def parse_manifest(data: bytes) -> dict[bytes, set[bytes]]:
    """{SHA-1 of the lowercased name: {SHA-1s of the content}} for every
    file (not folder) in a manifest. Raises ValueError if it can't be read."""
    files: dict[bytes, set[bytes]] = {}
    for e in read_entries(data)[1]:
        files.setdefault(e.name_hash, set()).add(e.content_hash)
    return files


def name_hash(relative: tuple[str, ...]) -> bytes:
    """How Steam hashes a file's name: its path inside the game folder,
    with Windows separators, lowercased."""
    return hashlib.sha1("\\".join(relative).lower().encode("utf-8", "surrogateescape")).digest()


# ----------------------------------------------------------------------
# Finding a file's game and its manifests
# ----------------------------------------------------------------------

def _in_workshop(path: Path) -> tuple[Path, str] | None:
    """(library, app id) for a path under
    <library>/steamapps/workshop/content/<appid>/<item>/..., else None."""
    parts = path.parts
    for i in range(len(parts) - 5, 0, -1):   # at least <appid>/<item>/<file> after content
        if parts[i:i + 3] == ("steamapps", "workshop", "content") and parts[i + 3].isascii() \
                and parts[i + 3].isdigit():
            return Path(*parts[:i]), parts[i + 3]
    return None


def _in_library(path: Path) -> tuple[Path, str, tuple[str, ...]] | None:
    """(library, game folder name, path inside it) for a path under
    <library>/steamapps/common/<game>/..., else None."""
    parts = path.parts
    for i in range(len(parts) - 4, 0, -1):   # at least <game>/<file> after common
        if parts[i] == "steamapps" and parts[i + 1] == "common":
            return Path(*parts[:i]), parts[i + 2], tuple(parts[i + 3:])
    return None


class Records:
    """Steam's records, read once per run and kept for the run's lookups."""

    def __init__(self):
        self._games: dict[Path, dict[str, tuple[str, dict[str, str]]]] = {}
        self._manifests: dict[Path, dict[bytes, set[bytes]] | None] = {}

    def game_name(self, library: Path, appid: str) -> str | None:
        """The name Steam has for an app in this library, from its appmanifest."""
        text = _read_text(library / "steamapps" / f"appmanifest_{appid}.acf")
        state = parse_vdf(text).get("appstate", {}) if text else {}
        name = state.get("name") if isinstance(state, dict) else None
        return name if isinstance(name, str) else None

    def _library_games(self, library: Path) -> dict[str, tuple[str, dict[str, str]]]:
        """{game folder: (name, {depot: manifest id})} from a library's appmanifests."""
        if library not in self._games:
            games: dict[str, tuple[str, dict[str, str]]] = {}
            try:
                acfs = sorted((library / "steamapps").glob("appmanifest_*.acf"))
            except OSError:
                acfs = []
            for acf in acfs:
                text = _read_text(acf)
                state = parse_vdf(text).get("appstate", {}) if text else {}
                if not isinstance(state, dict) or not isinstance(state.get("installdir"), str):
                    continue
                depots = state.get("installeddepots", {})
                depots = {d: v["manifest"] for d, v in depots.items()
                          if isinstance(v, dict) and isinstance(v.get("manifest"), str)} \
                    if isinstance(depots, dict) else {}
                name = state.get("name") if isinstance(state.get("name"), str) else state["installdir"]
                games.setdefault(state["installdir"], (name, depots))
            self._games[library] = games
        return self._games[library]

    def _manifest(self, path: Path) -> dict[bytes, set[bytes]] | None:
        if path not in self._manifests:
            try:
                with open(path, "rb") as f:
                    data = f.read(_MAX_MANIFEST + 1)
                self._manifests[path] = None if len(data) > _MAX_MANIFEST else parse_manifest(data)
            except (OSError, ValueError, struct.error) as e:
                log.debug("can't read Steam manifest %s: %s", path, e)
                self._manifests[path] = None
        return self._manifests[path]

    @staticmethod
    def _caches(library: Path, owner_uid: int) -> list[Path]:
        """Where a library's manifests can be: its own depotcache, and the
        Steam folders in the home of whoever owns the file."""
        caches = [library / "depotcache"]
        try:
            home = Path(pwd.getpwuid(owner_uid).pw_dir)
        except KeyError:
            return caches
        caches += [home / root / "depotcache" for root in _ROOTS]
        return caches

    def listing(self, path: Path, owner_uid: int) -> tuple[str, set[bytes]] | None:
        """(game name, SHA-1s Steam's record lists for this file), or None
        when the file isn't in a Steam game folder or its records don't list it."""
        found = _in_library(path)
        if found is None:
            return None
        library, folder, relative = found
        game = self._library_games(library).get(folder)
        if game is None:
            return None
        name, depots = game
        key, listed = name_hash(relative), set()
        caches = self._caches(library, owner_uid)
        for depot, manifest_id in depots.items():
            file_name = f"{depot}_{manifest_id}.manifest"
            for cache in caches:
                if (cache / file_name).is_file():
                    manifest = self._manifest(cache / file_name)
                    if manifest is not None:
                        listed |= manifest.get(key, set())
                    break
        return (name, listed) if listed else None


def unchanged_since(filepath: str, when: float) -> bool:
    """True when nothing an answer about this file depends on has changed
    since `when` (a timestamp): the file itself (its change time moves with
    any write), and for a game folder, every appmanifest of its library and
    every manifest in the depotcache folders it could be read from. Then the
    answer can stand without hashing the file again (a flagged game file can
    be 80 GB). Anything that can't be checked counts as changed."""
    path = Path(filepath)
    try:
        if path.stat().st_ctime >= when:
            return False
        if _in_workshop(path) is not None:
            return True
        found = _in_library(path)
        if found is None:
            return False
        library = found[0]
        caches = Records._caches(library, path.stat().st_uid)
        newest = max([p.stat().st_mtime for p in (library / "steamapps").glob("appmanifest_*.acf")]
                     + [c.stat().st_mtime for c in caches if c.is_dir()]
                     + [m.stat().st_mtime for c in caches if c.is_dir() for m in c.glob("*.manifest")],
                     default=float("inf"))
    except OSError:
        return False
    return newest < when


def _hashes(path: Path) -> tuple[str, bytes] | None:
    """(SHA-256 hex, SHA-1) of the file, in one read, opened the way the
    scanner opens files (no FIFOs, devices or other surprises)."""
    try:
        fd, _st = open_for_scan(path)
    except (OSError, NotScannable):
        return None
    try:
        sha256, sha1 = hashlib.sha256(), hashlib.sha1()
        while chunk := os.read(fd, 1 << 20):
            sha256.update(chunk)
            sha1.update(chunk)
        return sha256.hexdigest(), sha1.digest()
    except OSError:
        return None
    finally:
        os.close(fd)


def check(records: Records, filepath: str, flagged_hash: str) -> Answer | None:
    """What Steam's record says about a flagged file, for the content that
    was flagged (flagged_hash, SHA-256 hex). None: nothing to say -- not in
    a Steam game folder, not listed, unreadable, or the file has changed
    since it was flagged."""
    path = Path(filepath)
    workshop = _in_workshop(path)
    if workshop is not None:
        library, appid = workshop
        return Answer(WORKSHOP, records.game_name(library, appid) or f"app {appid}")
    try:
        owner = path.stat().st_uid
    except OSError:
        return None
    listing = records.listing(path, owner)
    if listing is None:
        return None
    game, listed = listing
    hashes = _hashes(path)
    if hashes is None or hashes[0] != flagged_hash:
        return None   # other content than what was flagged: no answer about it
    return Answer(MATCH if hashes[1] in listed else DIFFERS, game)
