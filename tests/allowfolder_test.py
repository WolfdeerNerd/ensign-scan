"""--allow-folder: allow every file under a folder that one signature flags.

It is a snapshot. Each file gets the same allowance --allow gives (its
exact content, that exact signature); nothing is allowed for being in the
folder. Checked here:

  * it needs a signature that flags something there, and a yes;
  * only that signature's files under that folder are allowed;
  * formats that can run code when loaded (.pkl, .pt, ...) are left out,
    and so is a file with the same content as one of them;
  * a file that changed since its scan is left out;
  * a new file, or a changed one, is flagged again on the next run, and the
    run prints the commands to allow it;
  * --list-allowed shows the folder; --unallow-folder undoes it;
  * the command line refuses a --signature with nothing to apply it to;
  * a file given as the folder is pointed to --allow;
  * undoing a folder also forgets the folders inside it;
  * a folder with tens of thousands of left-out files doesn't crash.

Runs anywhere: clamd is a stand-in that flags content containing "PHISH"
as Test.Phish and "EVIL" as Test.Evil.

    python3 tests/allowfolder_test.py
"""
from __future__ import annotations

import sys as _sys_path
from pathlib import Path as _Path

# Run against THIS checkout, never an installed copy of Ensign.
ROOT = _Path(__file__).resolve().parent.parent
_sys_path.path.insert(0, str(ROOT))

import contextlib  # noqa: E402
import io  # noqa: E402
import os  # noqa: E402
import shlex  # noqa: E402
import sys  # noqa: E402
import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

from sqlalchemy.orm import Session  # noqa: E402

from ensign_scan import allowlist, cli, reports  # noqa: E402
from ensign_scan.clamd import ScanOutcome  # noqa: E402
from ensign_scan.config import Config  # noqa: E402
from ensign_scan.models import AllowedFolder, Allowance, FileRecord, ScanStatus  # noqa: E402
from ensign_scan.scanner import Scanner  # noqa: E402


class FakeClamd:
    def daemon_uid(self):
        return 990   # not your uid: Ensign refuses a clamd running as you

    def supports_fildes(self):
        return True

    def signature_version(self):
        return 27000

    def max_threads(self):
        return 4

    def scan_fd(self, fd, label=""):
        data = os.pread(fd, 1 << 20, 0)
        for marker, name in ((b"PHISH", "Test.Phish"), (b"EVIL", "Test.Evil")):
            if marker in data:
                return ScanOutcome(ScanStatus.INFECTED, f"{label}: {name} FOUND", name)
        return ScanOutcome(ScanStatus.CLEAN, f"{label}: OK")


def statuses(engine) -> dict[str, str]:
    with Session(engine) as session:
        return {Path(r.filepath).name: r.scan_status for r in session.query(FileRecord)}


def quiet(fn, *args, **kwargs):
    """Run fn with its output captured. Returns (result, output), with line
    breaks folded into spaces: the console wraps long lines."""
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        result = fn(*args, **kwargs)
    return result, " ".join(buf.getvalue().split())


yes = lambda prompt: True  # noqa: E731
no = lambda prompt: False  # noqa: E731

with tempfile.TemporaryDirectory() as d:
    tree = Path(d, "tree")
    data = tree / "training data"   # a space: the printed commands must quote it
    (data / "batch").mkdir(parents=True)
    (tree / "elsewhere").mkdir()
    (data / "a.jsonl").write_bytes(b"scraped page one PHISH text")
    (data / "batch" / "b.jsonl").write_bytes(b"scraped page two PHISH text")
    (data / "c.txt").write_bytes(b"scraped page three PHISH text")
    (data / "other-sig.txt").write_bytes(b"something EVIL")           # another signature
    (data / "model.PKL").write_bytes(b"pickle bytes PHISH")            # can run code when loaded
    (data / "twin.txt").write_bytes(b"pickle bytes PHISH")             # same bytes as model.PKL
    (data / "fine.txt").write_bytes(b"nothing here")
    (tree / "elsewhere" / "outside.jsonl").write_bytes(b"outside the folder PHISH")
    (tree / "elsewhere" / "copy-of-a.jsonl").write_bytes(b"scraped page one PHISH text")
    Path(d, "data").mkdir()
    config = Config(db_url=f"sqlite:///{d}/data/system.db", log_file=Path(d, "data", "e.txt"),
                    max_workers=2)
    clamd = FakeClamd()

    def scan():
        s = Scanner(config, clamd=clamd)  # a fresh Scanner per run, like the CLI
        quiet(s.scan_tree, tree)
        quiet(s.rescan_infected)
        return s

    engine = scan().engine
    folder = str(data)

    # --- refusals -------------------------------------------------------------------------------
    n, out = quiet(allowlist.allow_folder, engine, folder, None, yes)
    assert n == 0 and "--signature NAME" in out and "Test.Phish (5 files)" in out \
        and "Test.Evil (1 file)" in out, out
    n, out = quiet(allowlist.allow_folder, engine, folder, "Test.Nope", yes)
    assert n == 0 and "no file under" in out and "Test.Phish" in out, out
    n, out = quiet(allowlist.allow_folder, engine, str(tree / "nowhere"), "Test.Phish", yes)
    assert n == 0 and "Scan it first" in out, out
    n, out = quiet(allowlist.allow_folder, engine, folder, "Test.Phish", no)
    assert n == 0 and "Not allowed" in out, out
    with Session(engine) as session:
        assert session.query(Allowance).count() == 0 and session.query(AllowedFolder).count() == 0
    print("allow-folder refusals test passed ✓")

    # --- a file that changed since its scan is left out ------------------------------------------
    (data / "c.txt").write_bytes(b"scraped page three PHISH text, edited since the scan")

    # --- allowing ---------------------------------------------------------------------------------
    n, out = quiet(allowlist.allow_folder, engine, folder + "/", "Test.Phish", yes)
    assert n == 2, out
    assert "1 identical copy elsewhere" in out, out
    assert "can run code" in out and "model.PKL" in out, out
    assert "changed since it was scanned" in out and "identical to a left-out file" in out, out
    assert "ensign-scan unallow-folder " + shlex.quote(folder) + " --signature Test.Phish" in out, out
    st = statuses(engine)
    assert st["a.jsonl"] == st["b.jsonl"] == "allowed"
    assert st["copy-of-a.jsonl"] == "allowed", "same content elsewhere is the same false positive"
    assert st["c.txt"] == "infected", "changed since the scan"
    assert st["model.PKL"] == "infected", "a format that can run code is never part of a folder allow"
    assert st["twin.txt"] == "infected", "same bytes as the left-out pickle"
    assert st["other-sig.txt"] == "infected", "another signature isn't covered"
    assert st["outside.jsonl"] == "infected", "outside the folder isn't covered"
    with Session(engine) as session:
        assert session.query(Allowance).count() == 2 and session.query(AllowedFolder).count() == 1
    print("allow-folder test passed ✓")

    # --- later runs: allowed stays allowed; anything new or changed is flagged ------------------
    scan()
    assert statuses(engine)["a.jsonl"] == "allowed"
    (data / "batch" / "new.jsonl").write_bytes(b"a new batch file PHISH text")
    (data / "a.jsonl").write_bytes(b"scraped page one PHISH text, appended to")
    scan()
    st = statuses(engine)
    assert st["new.jsonl"] == "infected", "a new file in an allowed folder is flagged"
    assert st["a.jsonl"] == "infected", "a changed file in an allowed folder is flagged again"
    assert st["b.jsonl"] == "allowed"
    infected, _ = quiet(reports.list_infected, engine)
    assert {"new.jsonl", "a.jsonl"} <= {Path(i["filepath"]).name for i in infected}, \
        "and they count as infected"
    print("new and changed files test passed ✓")

    # --- the run prints what to do about them; Ensign does neither --------------------------------
    count, out = quiet(allowlist.new_in_allowed_folders, engine)
    # a.jsonl, c.txt, new.jsonl, twin.txt, model.PKL: flagged by the allowed signature, not allowed
    assert count == 5 and "NEW IN FOLDERS YOU ALLOWED (5 files)" in out, out
    assert "ensign-scan allow-folder " + shlex.quote(folder) + " --signature Test.Phish" in out, out
    assert "Allow one:" in out and "ensign-scan allow " in out, out
    assert "1 of these can run code" in out, out
    assert "other-sig.txt" not in out and "outside.jsonl" not in out, out
    count, _ = quiet(allowlist.new_in_allowed_folders, engine, paths=[str(data / "batch")])
    assert count == 1, "scoped like the other reports"
    count, _ = quiet(allowlist.new_in_allowed_folders, engine, paths=[str(tree / "elsewhere")])
    assert count == 0
    assert statuses(engine)["new.jsonl"] == "infected", "printing the commands allows nothing"
    print("new-in-allowed-folders report test passed ✓")

    # --- rerunning the folder allow covers the new batch -----------------------------------------
    n, out = quiet(allowlist.allow_folder, engine, folder, "Test.Phish", yes)
    assert n == 3, out   # a.jsonl (new content), c.txt (scanned again since), new.jsonl
    st = statuses(engine)
    assert st["new.jsonl"] == st["a.jsonl"] == st["c.txt"] == "allowed"
    assert st["model.PKL"] == st["twin.txt"] == "infected"
    with Session(engine) as session:
        assert session.query(AllowedFolder).count() == 1, "the same folder, remembered once"
    count, out = quiet(allowlist.new_in_allowed_folders, engine)
    assert count == 2 and "Allow them all" in out, out   # twin.txt could go in a folder allow...
    print("rerun test passed ✓")

    # --- the pickle can only be allowed by itself; its twin then goes with it --------------------
    ok, _ = quiet(allowlist.allow, engine, str(data / "model.PKL"), yes)
    assert ok
    st = statuses(engine)
    assert st["model.PKL"] == st["twin.txt"] == "allowed"
    assert quiet(allowlist.new_in_allowed_folders, engine)[0] == 0
    print("left-out file test passed ✓")

    # --- --list-allowed shows the folder ---------------------------------------------------------
    count, out = quiet(allowlist.list_allowed, engine)
    flat = " ".join(out.split())
    assert "FOLDERS YOU ALLOWED (1)" in flat and "training data" in flat, flat
    assert "Test.Phish 6 files allowed" in flat, flat
    # the files the folder covers are counted there, not listed again
    assert "training data/a.jsonl" not in flat and "copy-of-a.jsonl" in flat, flat
    # the infected file in the folder that isn't allowed is pointed out
    assert "1 file here is infected now and not allowed" in flat and "ensign-scan list infected" in flat, flat
    print("list-allowed folders test passed ✓")

    # --- only a folder allow of pickles: nothing happens, nothing is remembered -------------------
    pk = tree / "pickles"
    pk.mkdir()
    (pk / "weights.pt").write_bytes(b"checkpoint PHISH")
    scan()
    n, out = quiet(allowlist.allow_folder, engine, str(pk), "Test.Phish", yes)
    assert n == 0 and "Nothing was allowed" in out, out
    with Session(engine) as session:
        assert session.query(AllowedFolder).count() == 1
    print("pickles-only folder test passed ✓")

    # --- unallow-folder: flagged again, allowances gone, folder forgotten ------------------------
    ok, out = quiet(allowlist.unallow_folder, engine, folder, "Test.Phish")
    assert ok and "flagged as infected again" in out, out
    st = statuses(engine)
    assert all(st[n] == "infected" for n in ("a.jsonl", "b.jsonl", "c.txt", "new.jsonl", "model.PKL"))
    assert st["copy-of-a.jsonl"] == "infected", \
        "a copy elsewhere of content allowed from the folder goes with it"
    with Session(engine) as session:
        assert session.query(Allowance).count() == 0 and session.query(AllowedFolder).count() == 0
    assert not quiet(allowlist.unallow_folder, engine, folder, "Test.Phish")[0], "nothing left to undo"
    scan()
    assert statuses(engine)["b.jsonl"] == "infected", "and they stay infected"
    assert quiet(allowlist.new_in_allowed_folders, engine)[0] == 0, "a forgotten folder gives no hints"
    print("unallow-folder test passed ✓")

    # --- hostile names are shown escaped ---------------------------------------------------------
    bad = tree / "x\x1b]0;pwned\x07 [red]"
    bad.mkdir()
    (bad / "f.txt").write_bytes(b"hostile folder PHISH")
    scan()
    n, out = quiet(allowlist.allow_folder, engine, str(bad), "Test.Phish", yes)
    (bad / "g.txt").write_bytes(b"hostile folder, new PHISH")
    scan()
    _, hint = quiet(allowlist.new_in_allowed_folders, engine)
    _, listed = quiet(allowlist.list_allowed, engine)
    assert n == 1 and all("\x1b" not in t for t in (out, hint, listed)), repr(out + hint + listed)
    assert "\\x1b" in hint and "[red]" in hint, repr(hint)
    print("hostile names test passed ✓")

    # --- a file given as the folder: pointed to --allow, not told to scan ------------------------
    n, out = quiet(allowlist.allow_folder, engine, str(data / "batch" / "b.jsonl"), "Test.Phish", yes)
    assert n == 0 and "is a file" in out and "ensign-scan allow " in out and "Scan it first" not in out, out
    print("file-as-folder test passed ✓")

    # --- undoing a folder forgets the folders inside it, for that signature ---------------------
    nest = tree / "nest"
    (nest / "inner").mkdir(parents=True)
    (nest / "top.txt").write_bytes(b"nest top PHISH")
    (nest / "inner" / "deep.txt").write_bytes(b"nest deep PHISH")
    (nest / "inner" / "evil.txt").write_bytes(b"nest deep EVIL")
    scan()
    assert quiet(allowlist.allow_folder, engine, str(nest / "inner"), "Test.Phish", yes)[0] == 1
    assert quiet(allowlist.allow_folder, engine, str(nest / "inner"), "Test.Evil", yes)[0] == 1
    assert quiet(allowlist.allow_folder, engine, str(nest), "Test.Phish", yes)[0] == 1
    ok, _ = quiet(allowlist.unallow_folder, engine, str(nest), "Test.Phish")
    st = statuses(engine)
    assert ok and st["top.txt"] == st["deep.txt"] == "infected"
    with Session(engine) as session:
        left = {(Path(f.folder).name, f.threat_name) for f in session.query(AllowedFolder)
                if f.folder.startswith(str(nest))}
    assert left == {("inner", "Test.Evil")}, f"only the other signature's folder is still remembered: {left}"
    assert st["evil.txt"] == "allowed", "another signature's allowance is untouched"
    _, hint = quiet(allowlist.new_in_allowed_folders, engine, paths=[str(nest)])
    assert "deep.txt" not in hint, "files you un-allowed are not reported as new"
    print("nested undo test passed ✓")

    # --- a folder with more left-out files than SQLite takes in one query ------------------------
    many = tree / "many"
    many.mkdir()
    (many / "text.jsonl").write_bytes(b"many PHISH")
    scan()
    with Session(engine) as session:
        session.add_all([FileRecord(filepath=f"{many}/m{i}.pt", filename=f"m{i}.pt",
                                    file_hash=f"{i:064d}", scan_status="infected",
                                    threat_name="Test.Phish") for i in range(40000)])
        session.commit()
    n, out = quiet(allowlist.allow_folder, engine, str(many), "Test.Phish", yes)
    assert n == 1 and "40000 files in a format that can run code" in out, out[-300:]
    with Session(engine) as session:
        session.query(FileRecord).filter(FileRecord.filename.like("m%.pt")).delete(synchronize_session=False)
        session.commit()
    print("many left-out files test passed ✓")

    # --- the command line -------------------------------------------------------------------------
    def parse(*argv):
        sys.argv = ["ensign-scan", *argv]
        with contextlib.redirect_stderr(io.StringIO()) as err:
            try:
                return cli.parse_args(), ""
            except SystemExit:
                return None, err.getvalue()

    args, _ = parse("--allow-folder", "some/dir", "--signature", "Test.Phish")
    assert args.allow_folder == "some/dir" and args.signature == "Test.Phish"
    assert parse("--allow-folder", "some/dir")[0] is not None, "no signature: lists what's there"
    for bad_argv, why in ((("--signature", "X"), "goes with"),
                          (("--unallow-folder", "d"), "needs --signature"),
                          (("--allow-folder", "d", "--unallow-folder", "d", "--signature", "X"),
                           "can't be used together")):
        args, err = parse(*bad_argv)
        assert args is None and why in err, (bad_argv, err)
    print("command line test passed ✓")

print("\nAll allow-folder tests passed ✓")
