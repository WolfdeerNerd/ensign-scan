"""Steam's record as a second opinion on flagged game files (0.12.0).

Checked here:

  * manifests are read as Steam writes them (zipped sections of protobuf),
    plain or with encrypted names, and anything malformed is refused
    without a crash;
  * a flagged file in a game folder that Steam's record has with these
    exact bytes says where it came from -- never "likely false positive",
    since games have shipped malware in their Steam builds -- and becomes a
    warning when ClamAV names a known malware family; the file stays flagged;
  * Workshop content gets a caveat, and a Proton prefix gets nothing;
  * a listed file with other bytes gets a neutral note; an unlisted file,
    a file outside a game folder, or a game Steam has no record of gets
    nothing;
  * the answer is about the flagged content only: a file changed since it
    was flagged gets no answer, and an answer for older content isn't shown.

Runs anywhere: the Steam library is built here, and clamd is a stand-in.

    python3 tests/steam_test.py
"""
from __future__ import annotations

import sys as _sys_path
from pathlib import Path as _Path

ROOT = _Path(__file__).resolve().parent.parent
_sys_path.path.insert(0, str(ROOT))

import base64  # noqa: E402
import contextlib  # noqa: E402
import hashlib  # noqa: E402
import io  # noqa: E402
import os  # noqa: E402
import struct  # noqa: E402
import tempfile  # noqa: E402
import zipfile  # noqa: E402
from pathlib import Path  # noqa: E402

from sqlalchemy.orm import Session  # noqa: E402

from ensign_scan import allowlist, evidence, findings, pkgdb, reports, steam  # noqa: E402
from ensign_scan.clamd import ScanOutcome  # noqa: E402
from ensign_scan.config import Config  # noqa: E402
from ensign_scan.models import Evidence, FileRecord, ScanStatus  # noqa: E402
from ensign_scan.scanner import Scanner  # noqa: E402


# --- writing manifests the way Steam does ------------------------------------------------------
def _varint(n: int) -> bytes:
    out = b""
    while True:
        b, n = n & 0x7F, n >> 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def _field(number: int, value) -> bytes:
    if isinstance(value, int):
        return _varint(number << 3) + _varint(value)
    return _varint(number << 3 | 2) + _varint(len(value)) + value


def manifest(depot: int, files: dict[str, bytes], encrypted: bool = False, folders=()) -> bytes:
    payload = b""
    for rel, content in files.items():
        name = rel.replace("/", "\\")
        shown_name = base64.b64encode(os.urandom(24)) if encrypted else name.encode()
        payload += _field(1, _field(1, shown_name) + _field(2, len(content)) + _field(3, 0)
                          + _field(4, hashlib.sha1(name.lower().encode()).digest())
                          + _field(5, hashlib.sha1(content).digest()))
    for rel in folders:   # a folder entry: flags say Directory, and it has no content hash to match
        name = rel.replace("/", "\\")
        payload += _field(1, _field(1, name.encode()) + _field(3, 64)
                          + _field(4, hashlib.sha1(name.lower().encode()).digest())
                          + _field(5, b"\0" * 20))
    meta = _field(1, depot) + _field(2, 222) + _field(4, int(encrypted))
    raw = (struct.pack("<II", 0x71F617D0, len(payload)) + payload + struct.pack("<II", 0x1F4812BE, len(meta))
           + meta + struct.pack("<II", 0x1B81B817, 0) + struct.pack("<I", 0x32C415AB))
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w") as zf:
        zf.writestr("z", raw)
    return zipped.getvalue()


def acf(appid: str, name: str, folder: str, depots: dict[str, str]) -> str:
    installed = "".join(f'  "{d}"\n  {{\n   "manifest" "{m}"\n   "size" "1"\n  }}\n' for d, m in depots.items())
    return (f'"AppState"\n{{\n "appid" "{appid}"\n "name" "{name}"\n "installdir" "{folder}"\n'
            f' "InstalledDepots"\n {{\n{installed} }}\n}}\n')


# --- the format, on its own --------------------------------------------------------------------
files = {"bin/Game.dll": b"game EVIL code", "data/Level.pak": b"level data"}
parsed = steam.parse_manifest(manifest(11, files, folders=["bin"]))
assert parsed[steam.name_hash(("bin", "Game.dll"))] == {hashlib.sha1(b"game EVIL code").digest()}
assert steam.name_hash(("BIN", "game.DLL")) == steam.name_hash(("bin", "Game.dll")), "Steam lowercases names"
assert steam.name_hash(("bin",)) not in parsed, "folders aren't files"
assert steam.parse_manifest(manifest(11, files, encrypted=True)) == {
    k: v for k, v in parsed.items()}, "encrypted names match through the name's hash"
for broken in (b"", b"PK\x03\x04 not really a zip", struct.pack("<II", 0x71F617D0, 99) + b"short",
               struct.pack("<II", 0x12345678, 0), struct.pack("<II", 0x71F617D0, 2) + b"\x0a\xff",
               struct.pack("<II", 0x71F617D0, 11) + b"\x0a\x09\x08" + b"\xff" * 8):
    try:
        steam.parse_manifest(broken)
        assert broken == b"", f"accepted a broken manifest: {broken!r}"
    except ValueError:
        pass
vdf = steam.parse_vdf('"A" { "B" "1" "C" { "D" "x\\\\y" } } "Stray" }}')
assert vdf == {"a": {"b": "1", "c": {"d": "x\\y"}}}, vdf
from ensign_scan.explanations import known_family  # noqa: E402

for name, family in {"Win.Infostealer.Vidar-123-0": "Vidar", "Win.Trojan.LummaStealer-1": "LummaStealer",
                     "Win.Malware.Stealc-10012345-0": "Stealc", "Win.Trojan.DarkKomet-1234-1": "DarkKomet",
                     "PUA.Win.Trojan.Remcos-9-0": "Remcos",
                     # real ClamAV signature names, seen flagging legitimate files; none is a known family
                     "Win.Packed.Mikey-9859688-0": None, "Win.Packer.MalwareCrypter-6620810-1": None,
                     "Win.Exploit.CVE_2015_2503-1": None, "Js.Downloader.Jsdownloader-6260766-0": None,
                     "Win.Trojan.Generic-1": None, "Heuristics.Encrypted.Zip": None, None: None, "": None}.items():
    assert known_family(name) == family, (name, known_family(name))
print("manifest format test passed ✓")


# --- a Steam library, and flagged files in it --------------------------------------------------
class FakeClamd:
    def daemon_uid(self):
        return 990

    def supports_fildes(self):
        return True

    def signature_version(self):
        return 27000

    def max_threads(self):
        return 4

    def scan_fd(self, fd, label=""):
        data = os.pread(fd, 1 << 20, 0)
        if b"STEALER" in data:
            return ScanOutcome(ScanStatus.INFECTED, f"{label}: Win.Infostealer.Vidar-123-0 FOUND",
                               "Win.Infostealer.Vidar-123-0", "clamav")
        if b"EVIL" in data:
            return ScanOutcome(ScanStatus.INFECTED, f"{label}: Win.Test FOUND", "Win.Test", "clamav")
        return ScanOutcome(ScanStatus.CLEAN, f"{label}: OK")


def quiet(fn, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        result = fn(*args, **kwargs)
    return result, " ".join(buf.getvalue().split())


def record(engine, path: Path):
    with Session(engine) as session:
        row = session.query(FileRecord).filter(FileRecord.filepath == str(path)).one()
        session.expunge(row)
        return row


class NoPackages:
    name, label = "none", "none"

    def owner(self, path):
        return ("unknown", None)


with tempfile.TemporaryDirectory() as d:
    library = Path(d, "games")
    apps = library / "steamapps"
    (library / "depotcache").mkdir(parents=True)
    game = apps / "common" / "Some Game"
    shipped = {**files, "bin/Patched.dll": b"the build Steam shipped", "bin/Thief.dll": b"STEALER shipped by Steam"}
    for rel, content in {**files, "bin/Patched.dll": b"patched EVIL build", "bin/Extra.dll": b"mod EVIL",
                         "bin/Thief.dll": b"STEALER shipped by Steam"}.items():
        (game / rel).parent.mkdir(parents=True, exist_ok=True)
        (game / rel).write_bytes(content)
    # Steam's record: Game.dll and Thief.dll as is; Patched.dll with other bytes; Extra.dll not listed.
    (apps / "appmanifest_10.acf").write_text(acf("10", "Some Game", "Some Game", {"11": "222", "12": "333"}))
    (library / "depotcache" / "11_222.manifest").write_bytes(manifest(11, shipped))
    (library / "depotcache" / "12_333.manifest").write_bytes(b"PK broken on purpose")   # unreadable depot: skipped
    # A game folder Steam has no appmanifest for, and a file outside any game folder.
    (apps / "common" / "Unknown Game").mkdir()
    (apps / "common" / "Unknown Game" / "x.dll").write_bytes(b"EVIL unknown")
    (apps / "loose.dll").write_bytes(b"EVIL loose")
    # A Workshop item for the game, and a Proton prefix: no manifest match for either.
    item = apps / "workshop" / "content" / "10" / "3000001"
    item.mkdir(parents=True)
    (item / "wallpaper.exe").write_bytes(b"EVIL in a mod")
    prefix = apps / "compatdata" / "10" / "pfx" / "drive_c" / "users" / "steamuser" / "Temp"
    prefix.mkdir(parents=True)
    (prefix / "Howard.exe").write_bytes(b"EVIL second stage")

    Path(d, "data").mkdir()
    config = Config(db_url=f"sqlite:///{d}/data/system.db", log_file=Path(d, "data", "e.txt"), max_workers=2)
    real_active = pkgdb.active
    pkgdb.active = lambda: NoPackages()   # Steam's evidence doesn't depend on package verification
    try:
        def scan():
            s = Scanner(config, clamd=FakeClamd())
            allowlist.reconcile(s.engine)
            findings.tidy(s.engine)
            quiet(s.scan_tree, library)
            return s.engine

        engine = scan()
        assert evidence.refresh(engine) == 4, "Game.dll, Thief.dll, Patched.dll, the Workshop file"
        _, text = quiet(reports.list_infected, engine)
        assert "Likely false positive" not in text, "a Steam match is never called a likely false positive"
        assert ("Matches Steam's build: Steam installed exactly this file for Some Game. That shows where it "
                "came from, not that it's safe") in text, text
        assert "PirateFi" in text and "home folder" in text, text
        assert ("Warning: Steam shipped this file for Some Game, and ClamAV names a known malware family "
                "(Vidar)") in text and "Treat it as real. Investigation required." in text, text
        assert "Steam: Steam's record for Some Game lists this file with other contents" in text, text
        assert "Workshop: Steam Workshop content for Some Game: uploaded by a community member" in text, text
        assert text.count("Steam's record") == 2 and text.count("Steam shipped this file") == 1, \
            "Extra.dll, the unknown game, the loose file and the Proton prefix: nothing"
        assert record(engine, game / "bin/Game.dll").scan_status == "infected", "evidence never changes a verdict"

        # Nothing changed since: the answers stand without hashing the files again.
        import time  # noqa: E402
        real_hashes, calls = steam._hashes, []
        steam._hashes = lambda p: calls.append(p) or real_hashes(p)
        try:
            time.sleep(0.05)
            assert evidence.refresh(engine) == 4 and calls == [], calls
            later = time.time() + 5   # a manifest edited after the answers
            os.utime(library / "depotcache" / "11_222.manifest", (later, later))
            assert evidence.refresh(engine) == 4 and len(calls) == 3, "checked again: the record changed"
        finally:
            steam._hashes = real_hashes

        # Encrypted names work the same way.
        (library / "depotcache" / "11_222.manifest").write_bytes(manifest(11, shipped, encrypted=True))
        assert evidence.refresh(engine) == 4

        # Changed since it was flagged: no answer about content that wasn't flagged.
        (game / "bin/Game.dll").write_bytes(b"game EVIL code, replaced")
        assert evidence.refresh(engine) == 3, "Game.dll's answer goes; the others keep theirs"
        with Session(engine) as session:
            kept = sorted((e.source, e.verdict) for e in session.query(Evidence))
        assert kept == [("steam", steam.DIFFERS), ("steam", steam.MATCH), ("steam", steam.WORKSHOP)], kept
        engine = scan()   # flagged again, as the new content
        assert evidence.refresh(engine) == 4, "the new content is listed, with other bytes: it differs"
        _, text = quiet(reports.list_infected, engine)
        assert "Steam installed exactly" not in text and text.count("lists this file with other contents") == 2, text

        # An answer stored for older content is never shown for the new.
        with Session(engine) as session:
            row = session.query(Evidence).filter(Evidence.file_id == record(engine, game / "bin/Game.dll").id,
                                                 Evidence.source == "steam").one()
            row.verdict, row.subject, row.content_hash = steam.MATCH, "Stale Game", "0" * 64
            session.commit()
        _, text = quiet(reports.list_infected, engine)
        assert "Stale Game" not in text, text

        # The game's manifests gone: nothing to say, and the old answers go.
        for m in (library / "depotcache").iterdir():
            m.unlink()
        assert evidence.refresh(engine) == 1, "only the Workshop caveat, which needs no manifest"
        with Session(engine) as session:
            left = [(e.verdict, e.subject) for e in session.query(Evidence)]
        assert left == [(steam.WORKSHOP, "Some Game")], left
    finally:
        pkgdb.active = real_active
    print("Steam evidence test passed ✓")

print("\nAll Steam tests passed ✓")
