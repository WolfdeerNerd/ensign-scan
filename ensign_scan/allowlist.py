"""Allowed by you: false positives you have told Ensign to stop flagging.

ClamAV sometimes flags a harmless file. Once you have checked one and are
sure, `ensign-scan --allow PATH` records it as allowed. That is your
judgment, not Ensign's or ClamAV's, so it is kept narrow and in plain view:

- It covers one exact content (the file's SHA-256) flagged by one exact
  signature name. If the file changes, or a different signature hits it,
  it is flagged again. An identical copy elsewhere is covered, since it is
  the same bytes and the same false positive.
- Allowed files are listed in their own section at the end of every run,
  and with --list-allowed. They are never hidden.
- They don't count as infected for alerts or the exit code.
- They are still rescanned when the signatures update, so a false positive
  ClamAV has since fixed simply turns clean.
- --unallow PATH undoes it.

--allow-folder FOLDER --signature NAME does the same for every file under
a folder that one signature flags right now: one confirmation instead of
hundreds. It is a snapshot, with no standing rule for the folder. Each file
gets the allowance above, tied to its own content, so a file that appears
or changes later is flagged again, and the run prints the commands to
allow it once you've checked it. Formats that can run code when a program
loads them (LOADS_CODE_EXTENSIONS) are left out and need their own --allow.

Everything stays in Ensign's own database. ClamAV and its signatures are
not touched, so nothing else using clamd is affected (unlike ClamAV's own
.sfp/.ign2 allow lists, which apply to every program using clamd).
"""
from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from pathlib import Path

from rich import print
from sqlalchemy import or_
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from .fsutil import open_for_scan, print_unwrapped, sha256_fd, shown
from .models import AllowedFolder, Allowance, FileRecord, ScanStatus, path_under, utcnow

# File formats that can run code the moment a program loads them: Python
# pickles, and the model checkpoints and saved objects built on pickle.
# --allow-folder never includes these. A signature hit on text is usually
# harmless, the same hit on one of these may not be, and in a batch of
# hundreds of files one of them is easy to miss. Each needs its own
# --allow PATH, where it is the only file on screen.
LOADS_CODE_EXTENSIONS = frozenset({".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".bin", ".joblib"})


def loads_code(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in LOADS_CODE_EXTENSIONS


def allowed_pairs(engine: Engine) -> set[tuple[str, str]]:
    """Every (SHA-256, signature name) you have allowed."""
    with Session(engine) as session:
        return {(h, t) for h, t in session.query(Allowance.file_hash, Allowance.threat_name)}


@dataclass
class _Candidate:
    path: str
    digest: str
    threat: str


def reconcile(engine: Engine) -> int:
    """Flag again every file recorded as allowed whose allowance is gone.
    Returns how many.

    An unchanged allowed file isn't sent to ClamAV again (like a clean
    one), so its record must follow the allowances by itself. --unallow
    does that in the same database; in protected mode the allowances are
    root's (protect.py) and root never writes your database, so your runs
    do it here, at the start. It also turns back a record that says
    "allowed" with no allowance behind it at all."""
    pairs = allowed_pairs(engine)
    flagged = 0
    with Session(engine) as session:
        for record in session.query(FileRecord).filter(
                FileRecord.scan_status == ScanStatus.ALLOWED.value):
            # "Unknown" when ClamAV named no signature: what --allow saved (_candidate).
            if (record.file_hash, record.threat_name or "Unknown") not in pairs:
                record.scan_status = ScanStatus.INFECTED.value
                flagged += 1
        session.commit()
    return flagged


def _candidate(engine: Engine, path: str) -> _Candidate | str:
    """What --allow would allow for `path`, or why it can't."""
    with Session(engine) as session:
        record = session.query(FileRecord).filter(FileRecord.filepath == path).first()
        if record is None:
            if _PROTECTED:
                return ("Root has no record of this file. Scan it with sudo first: "
                        "sudo ensign-scan " + shlex.quote(path))
            return "Ensign has no record of this file. Scan it first."
        if record.scan_status == ScanStatus.ALLOWED.value and not _PROTECTED:
            return "This file is already allowed."
        if record.scan_status not in _flagged_statuses():
            return (f"Only files ClamAV flagged can be allowed; this one is recorded as "
                    f"'{record.scan_status}'" + (" in root's last scan of it." if _PROTECTED else "."))
        stored, threat = record.file_hash, record.threat_name or "Unknown"
    # Hash it again now: only the exact bytes that were flagged can be
    # allowed, never whatever the file has become since.
    try:
        fd, _st = open_for_scan(Path(path))
    except OSError as exc:
        return f"Ensign can't open this file to check it: {exc.strerror or exc}."
    try:
        digest = sha256_fd(fd)
    finally:
        os.close(fd)
    if digest != stored:
        return ("This file has changed since it was scanned, so it isn't the content ClamAV "
                "flagged. Scan it again first" + (" (with sudo)." if _PROTECTED else "."))
    if _PROTECTED:
        with Session(engine) as session:
            if session.query(Allowance).filter(Allowance.file_hash == digest,
                                               Allowance.threat_name == threat).first():
                return "This file is already allowed."
    return _Candidate(path, digest, threat)


def _record(session: Session, found: _Candidate) -> int:
    """Save the allowance for `found` and mark every file with that content
    and signature as allowed. Returns how many files were marked. The
    caller commits."""
    exists = session.query(Allowance).filter(
        Allowance.file_hash == found.digest, Allowance.threat_name == found.threat).first()
    if exists is None:
        session.add(Allowance(file_hash=found.digest, threat_name=found.threat,
                              filepath=found.path, allowed_at=utcnow()))
        session.flush()
    # Every copy of the same content flagged by the same signature.
    copies = session.query(FileRecord).filter(
        FileRecord.file_hash == found.digest,
        FileRecord.threat_name == found.threat,
        FileRecord.scan_status.in_(_flagged_statuses()),
    ).all()
    if not _PROTECTED:   # root's records are evidence only; the user's runs mark their own
        for record in copies:
            record.scan_status = ScanStatus.ALLOWED.value
    return len(copies)


def allow(engine: Engine, path: str, confirm) -> bool:
    """Allow one flagged file. `confirm(prompt) -> bool` asks you to confirm.
    Returns True if it was allowed."""
    found = _candidate(engine, path)
    if isinstance(found, str):
        print_unwrapped(f"[yellow]Not allowed:[/yellow] {shown(path)}\n  {found}")
        return False
    print_unwrapped(f"\n  File:      {shown(found.path)}")
    print(f"  Signature: {shown(found.threat)}")
    print(f"  SHA-256:   {found.digest}")
    print("  Allowing tells Ensign this is a false positive: it stops counting this exact "
          "content, flagged by this exact signature, as infected. If the file changes or "
          "another signature flags it, it's flagged again. Only allow a file you've checked.")
    if not confirm("  Allow it? [y/N] "):
        print("  Not allowed.")
        return False
    with Session(engine) as session:
        marked = _record(session, found)
        session.commit()
    others = marked - 1
    also = f" (and {others} identical {'copy' if others == 1 else 'copies'} elsewhere)" if others > 0 else ""
    print_unwrapped(f"[green]  Allowed{also}.[/green] Undo with: {_command('--unallow', found.path)}")
    if _PROTECTED:
        print("  Your next run (as yourself) marks it allowed. Root's own runs keep flagging it.")
    return True


def unallow(engine: Engine, path: str) -> bool:
    """Undo --allow for the content at `path` (or allowed from there, if
    the file has since gone). Its copies are flagged as infected again."""
    with Session(engine) as session:
        record = session.query(FileRecord).filter(FileRecord.filepath == path).first()
        pairs = set()
        if record is not None and record.scan_status == ScanStatus.ALLOWED.value and not _PROTECTED:
            pairs.add((record.file_hash, record.threat_name))
        for row in session.query(Allowance).filter(Allowance.filepath == path):
            pairs.add((row.file_hash, row.threat_name))
        if not pairs:
            print_unwrapped(f"[yellow]Nothing to undo:[/yellow] {shown(path)} isn't allowed.")
            return False
        flagged = 0
        for digest, threat in pairs:
            session.query(Allowance).filter(
                Allowance.file_hash == digest, Allowance.threat_name == threat).delete()
            if not _PROTECTED:
                flagged += session.query(FileRecord).filter(
                    FileRecord.file_hash == digest,
                    FileRecord.threat_name == threat,
                    FileRecord.scan_status == ScanStatus.ALLOWED.value,
                ).update({FileRecord.scan_status: ScanStatus.INFECTED.value})
        session.commit()
    if _PROTECTED:
        print_unwrapped(f"[yellow]No longer allowed:[/yellow] {shown(path)}. Your next run flags "
                        f"it as infected again.")
    else:
        print_unwrapped(f"[yellow]No longer allowed:[/yellow] {shown(path)} "
                        f"({flagged} file{'s' if flagged != 1 else ''} flagged as infected again).")
    return True


# ----------------------------------------------------------------------
# Allowing a folder's flagged files in one go
# ----------------------------------------------------------------------

def _folder_text(folder: str) -> str:
    return folder.rstrip("/") or "/"


# How the commands in this module's messages are spelled, and whether it is
# working on a protected user's decisions (sudo ensign-scan --protected, see
# protect.py and db.make_protected_writer). In that mode the file records
# are root's own, read through a view: they are the evidence that a file was
# flagged, and are never changed. Set once by the command line.
_COMMAND = "ensign-scan"
_PROTECTED = False


def use_protected_decisions() -> None:
    """sudo ... --protected: write the user's protected decisions, with
    root's records as the evidence."""
    global _PROTECTED
    show_protected_commands()
    _PROTECTED = True


def show_protected_commands() -> None:
    """A protected user's own runs: they read their own records, but can't
    change decisions, so the commands they're shown need sudo --protected."""
    global _COMMAND
    _COMMAND = "sudo ensign-scan --protected"


def _command(*words: str) -> str:
    """An ensign-scan command you can paste: every argument shell-quoted."""
    return shown(_COMMAND + " " + " ".join(shlex.quote(w) for w in words))


def _flagged_statuses() -> tuple[str, ...]:
    # Root's own records: a file root allowed for itself was still flagged.
    if _PROTECTED:
        return (ScanStatus.INFECTED.value, ScanStatus.ALLOWED.value)
    return (ScanStatus.INFECTED.value,)


def _flagged_under(session: Session, folder: str) -> list[tuple[str, str, str]]:
    """(path, signature, stored SHA-256) of every infected file inside `folder`."""
    rows = session.query(FileRecord.filepath, FileRecord.threat_name, FileRecord.file_hash).filter(
        FileRecord.scan_status.in_(_flagged_statuses()),
        path_under(FileRecord.filepath, folder)).all()
    return sorted((path, threat or "Unknown", digest) for path, threat, digest in rows)


def _print_some(paths: list[str], top: int, icon: str = "○") -> None:
    for path in paths[:top]:
        print_unwrapped(f"    [cyan]{icon}[/cyan] {shown(path)}")
    if len(paths) > top:
        print(f"    … and {len(paths) - top} more")


def allow_folder(engine: Engine, folder: str, signature: str | None, confirm, top: int = 10) -> int:
    """Allow every file under `folder` that `signature` flags right now.
    Asks once, after showing what would be allowed and what is left out.
    Returns how many files under the folder were allowed."""
    folder = _folder_text(folder)
    if os.path.lexists(folder) and not os.path.isdir(folder):
        print_unwrapped(f"[yellow]Not allowed:[/yellow] {shown(folder)} is a file, and --allow-folder "
                        f"takes a folder. To allow one file: {_command('--allow', folder)}")
        return 0
    with Session(engine) as session:
        flagged = _flagged_under(session, folder)
    if _PROTECTED:
        # Root's records still say infected for what your decisions already
        # allow (root's runs keep flagging it): leave those out, as your own
        # records would (they say allowed).
        done = allowed_pairs(engine)
        still = [f for f in flagged if (f[2], f[1]) not in done]
        if flagged and not still:
            print_unwrapped(f"[yellow]Nothing to allow:[/yellow] everything flagged under "
                            f"{shown(folder)} is already allowed.")
            return 0
        flagged = still
    if not flagged:
        print_unwrapped(f"[yellow]Nothing to allow:[/yellow] no file under {shown(folder)} is "
                        f"recorded as infected. Scan it first" + (" with sudo." if _PROTECTED else "."))
        return 0
    by_signature: dict[str, list[str]] = {}
    stored_hash: dict[str, str] = {}
    for path, threat, digest in flagged:
        by_signature.setdefault(threat, []).append(path)
        stored_hash[path] = digest
    if signature not in by_signature:
        if signature is None:
            print_unwrapped(f"[yellow]Not allowed:[/yellow] say which signature to allow under "
                            f"{shown(folder)} with --signature NAME.")
        else:
            print_unwrapped(f"[yellow]Nothing to allow:[/yellow] no file under {shown(folder)} is "
                            f"flagged by {shown(signature)} right now.")
        print("  Flagged there now:")
        for threat, paths in sorted(by_signature.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            print(f"    {shown(threat)}  ({len(paths)} file{'s' if len(paths) != 1 else ''})")
        return 0

    paths = by_signature[signature]
    code = [p for p in paths if loads_code(p)]
    rest = [p for p in paths if not loads_code(p)]
    if rest:
        print(f"\n  Checking {len(rest)} file{'s' if len(rest) != 1 else ''} again "
              f"(each one is hashed, so large files take a while)…")
    # An allowance goes by content, so allowing a file would also cover a
    # left-out file holding the very same bytes. Such a file is held back
    # with it, so "left out" always means "still infected". The hashes come
    # from the query above: asking for them again with one "IN (...)" over
    # every left-out path would exceed SQLite's limit on a large folder.
    code_hashes = {stored_hash[p] for p in code}
    ready: list[_Candidate] = []
    not_ready: list[tuple[str, str]] = []
    for path in rest:
        found = _candidate(engine, path)
        if isinstance(found, str):
            not_ready.append((path, found))
        elif found.digest in code_hashes:
            not_ready.append((path, "Its content is identical to a left-out file above. "
                                    "Allow that one by itself first."))
        else:
            ready.append(found)

    print_unwrapped(f"\n  Folder:    {shown(folder)}")
    print(f"  Signature: {shown(signature)}")
    if ready:
        print(f"  To allow:  {len(ready)} file{'s' if len(ready) != 1 else ''}")
        _print_some([c.path for c in ready], top)
    if code:
        print(f"  Left out:  {len(code)} file{'s' if len(code) != 1 else ''} in a format that can "
              f"run code when a program loads it ({', '.join(sorted(LOADS_CODE_EXTENSIONS))}). "
              f"These stay infected. If you've checked one, allow it by itself: "
              f"{_COMMAND} --allow PATH")
        _print_some(code, top, "!")
    if not_ready:
        print(f"  Left out:  {len(not_ready)} file{'s' if len(not_ready) != 1 else ''} Ensign "
              f"couldn't confirm. These stay infected.")
        for path, why in not_ready[:top]:
            print_unwrapped(f"    [yellow]![/yellow] {shown(path)}\n      {why}")
        if len(not_ready) > top:
            print(f"    … and {len(not_ready) - top} more")
    if not ready:
        print("  Nothing was allowed.")
        return 0
    print("  Allowing tells Ensign these are false positives: it stops counting each file's exact "
          "content, flagged by this exact signature, as infected. Nothing is allowed for being "
          "in this folder: a file that appears here later, or one of these once it changes, is "
          "flagged again. Only allow files you've checked.")
    count = f"these {len(ready)} files" if len(ready) != 1 else "this file"
    if not confirm(f"  Allow {count}? [y/N] "):
        print("  Not allowed.")
        return 0

    inside = {c.path for c in ready}
    with Session(engine) as session:
        marked = sum(_record(session, c) for c in ready)
        now = utcnow()
        row = session.query(AllowedFolder).filter(
            AllowedFolder.folder == folder, AllowedFolder.threat_name == signature).first()
        if row is None:
            session.add(AllowedFolder(folder=folder, threat_name=signature,
                                      allowed_at=now, last_allowed_at=now))
        else:
            row.last_allowed_at = now
        session.commit()
    others = marked - len(inside)
    also = f" (and {others} identical {'copy' if others == 1 else 'copies'} elsewhere)" if others > 0 else ""
    print_unwrapped(f"[green]  Allowed {len(inside)} file{'s' if len(inside) != 1 else ''}{also}.[/green] "
                    f"Undo with: {_command('--unallow-folder', folder, '--signature', signature)}")
    if _PROTECTED:
        print("  Your next run (as yourself) marks them allowed. Root's own runs keep flagging them.")
    return len(inside)


def unallow_folder(engine: Engine, folder: str, signature: str) -> bool:
    """Undo --allow-folder: everything allowed for `signature` under
    `folder`, or allowed from there (and its identical copies), is flagged
    as infected again, and the folder is forgotten."""
    folder = _folder_text(folder)
    with Session(engine) as session:
        # The folder itself, and any folder inside it you allowed for the
        # same signature: its files are flagged again below, so it must not
        # stay listed, or report them later as "new".
        remembered = session.query(AllowedFolder).filter(
            AllowedFolder.threat_name == signature,
            or_(AllowedFolder.folder == folder, path_under(AllowedFolder.folder, folder)),
        ).delete(synchronize_session=False)
        digests = set() if _PROTECTED else {h for (h,) in session.query(FileRecord.file_hash).filter(
            FileRecord.scan_status == ScanStatus.ALLOWED.value,
            FileRecord.threat_name == signature,
            path_under(FileRecord.filepath, folder))}
        # Also content that was allowed from this folder and has since
        # changed or gone: its allowance may still cover a copy elsewhere.
        digests |= {h for (h,) in session.query(Allowance.file_hash).filter(
            Allowance.threat_name == signature, path_under(Allowance.filepath, folder))}
        if not remembered and not digests:
            print_unwrapped(f"[yellow]Nothing to undo:[/yellow] nothing under {shown(folder)} is "
                            f"allowed for {shown(signature)}.")
            return False
        flagged = 0
        for digest in digests:
            session.query(Allowance).filter(
                Allowance.file_hash == digest, Allowance.threat_name == signature).delete()
            if not _PROTECTED:
                flagged += session.query(FileRecord).filter(
                    FileRecord.file_hash == digest,
                    FileRecord.threat_name == signature,
                    FileRecord.scan_status == ScanStatus.ALLOWED.value,
                ).update({FileRecord.scan_status: ScanStatus.INFECTED.value})
        session.commit()
    if _PROTECTED:
        print_unwrapped(f"[yellow]No longer allowed:[/yellow] {shown(signature)} under "
                        f"{shown(folder)}. Your next run flags those files as infected again.")
    else:
        print_unwrapped(f"[yellow]No longer allowed:[/yellow] {shown(signature)} under {shown(folder)} "
                        f"({flagged} file{'s' if flagged != 1 else ''} flagged as infected again).")
    return True


def new_in_allowed_folders(engine: Engine, paths: list[str] | None = None, top: int = 5) -> int:
    """The end-of-run section for folders you ran --allow-folder on: files
    there that the same signature flags and that aren't allowed, because
    they are new or have changed since. They are infected like any other
    (and already listed as such); this adds the commands for allowing them.
    Ensign runs neither. Returns how many files it listed."""
    from .reports import _scope_filter  # reports doesn't import this module; no cycle
    scope = _scope_filter(paths)
    groups: list[tuple[str, str, list[str]]] = []
    with Session(engine) as session:
        folders = session.query(AllowedFolder.folder, AllowedFolder.threat_name).all()
        seen: set[str] = set()
        # Deepest folder first, so a file is listed once, under the most
        # specific folder you allowed.
        for folder, threat in sorted(folders, key=lambda r: (-len(r[0]), r[0], r[1])):
            query = session.query(FileRecord.filepath).filter(
                FileRecord.scan_status == ScanStatus.INFECTED.value,
                FileRecord.threat_name == threat,
                path_under(FileRecord.filepath, folder))
            if scope is not None:
                query = query.filter(scope)
            found = sorted({p for (p,) in query} - seen)
            if found:
                seen.update(found)
                groups.append((folder, threat, found))
    if not groups:
        return 0
    total = sum(len(found) for _f, _t, found in groups)
    print(f"\n[bold]=== NEW IN FOLDERS YOU ALLOWED ({total} file{'s' if total != 1 else ''}) ===[/bold]")
    print("Flagged by a signature you allowed in the same folder before, but these files are new "
          "or have changed since, so they count as infected. Check them first. Ensign runs "
          "neither command for you.")
    for folder, threat, found in sorted(groups):
        print_unwrapped(f"\n  Folder: {shown(folder)}")
        print(f"  Signature: {shown(threat)}  ({len(found)} file{'s' if len(found) != 1 else ''})")
        _print_some(found, top, "!")
        code = sum(1 for p in found if loads_code(p))
        if code < len(found):
            print_unwrapped(f"    Allow them all: {_command('--allow-folder', folder, '--signature', threat)}")
        print_unwrapped(f"    Allow one:      {_command('--allow', found[0])}")
        if code:
            print(f"    {code} of these can run code when a program loads "
                  f"{'it' if code == 1 else 'them'}; --allow-folder leaves "
                  f"{'it' if code == 1 else 'them'} out, so allow each with {_COMMAND} --allow PATH.")
    return total


def _under(path: str, folder: str) -> bool:
    folder = _folder_text(folder)
    return path == folder or path.startswith(folder.rstrip("/") + "/")


# The allowed listings nest by four spaces a level: a folder or file, then
# what's under it (signatures, the hash), then -- with --list-allowed-all --
# a folder's files and theirs.
_L1, _L2, _L3 = " " * 2, " " * 6, " " * 10


def _gather(engine: Engine) -> tuple[dict, dict, dict]:
    """Everything allowed, arranged for the listings.

    folders: folder -> {"signatures": [(name, first, last, files now)],
             "infected": files there infected now and not allowed,
             "files": {path: {"hash", "signatures": [(name, date)]}} covered by it}
    files:   path -> {"hash", "signatures"}, for signatures no folder covers
    gone:    (path, hash) -> {"hash", "signatures"}, allowed content with no
             tracked file now, under the path it had when allowed
    A file allowed under one signature by a folder and under another on its
    own appears in both places, each with its own signatures.
    """
    with Session(engine) as session:
        folder_rows = session.query(AllowedFolder).order_by(AllowedFolder.folder,
                                                            AllowedFolder.threat_name).all()
        folders: dict[str, dict] = {}
        for f in folder_rows:
            entry = folders.setdefault(f.folder, {"signatures": [], "infected": 0, "files": {}})
            now_allowed = session.query(FileRecord).filter(
                FileRecord.scan_status == ScanStatus.ALLOWED.value,
                FileRecord.threat_name == f.threat_name,
                path_under(FileRecord.filepath, f.folder)).count()
            entry["signatures"].append((f.threat_name, f.allowed_at, f.last_allowed_at, now_allowed))
        for folder, entry in folders.items():
            # Flagged now and not allowed: a new or changed file in a folder you trusted.
            entry["infected"] = session.query(FileRecord).filter(
                FileRecord.scan_status == ScanStatus.INFECTED.value,
                path_under(FileRecord.filepath, folder)).count()
        allowances = session.query(Allowance).all()
        # Every tracked file with allowed content, whatever its status now: one
        # flagged since by a new signature is still that content, on disk.
        hashes = {a.file_hash for a in allowances}
        tracked = [(p, h) for p, h in session.query(FileRecord.filepath, FileRecord.file_hash)
                   if h in hashes]

    rules = [(f.folder, f.threat_name) for f in folder_rows]

    def covering(path: str, threat: str) -> str | None:
        """The innermost allowed folder that covers this file for this signature."""
        found = [folder for folder, t in rules if t == threat and _under(path, folder)]
        return max(found, key=len) if found else None

    # The database keeps one signature per file (the latest match), so the
    # others allowed on the same content are found by its hash.
    paths_of: dict[str, list[str]] = {}
    for path, digest in tracked:
        paths_of.setdefault(digest, []).append(path)
    files: dict[str, dict] = {}
    for a in sorted(allowances, key=lambda a: a.threat_name):
        for path in paths_of.get(a.file_hash, []):
            folder = covering(path, a.threat_name)
            into = folders[folder]["files"] if folder else files
            into.setdefault(path, {"hash": a.file_hash, "signatures": []})["signatures"].append(
                (a.threat_name, a.allowed_at))
    gone: dict[tuple[str, str], dict] = {}
    for a in allowances:
        if a.file_hash in paths_of or covering(a.filepath, a.threat_name):
            continue
        gone.setdefault((a.filepath, a.file_hash), {"hash": a.file_hash, "signatures": []})[
            "signatures"].append((a.threat_name, a.allowed_at))
    return folders, files, gone


def _print_file(path: str, entry: dict, indent: str, inner: str) -> None:
    print_unwrapped(f"\n{indent}File: {shown(path)}")
    width = max(len(shown(t)) for t, _ in entry["signatures"])
    for threat, at in sorted(entry["signatures"], key=lambda s: s[0]):
        print(f"{inner}{shown(threat):<{width}}  allowed {at:%Y-%m-%d}")
    print(f"{inner}SHA-256: {entry['hash']}")


def _print_folders(folders: dict, expand: bool) -> None:
    print(f"\n[bold]=== FOLDERS YOU ALLOWED ({len(folders)}) ===[/bold]")
    print("A folder allows nothing by itself: each file in it is allowed by its own content. "
          f"Undo one with {_COMMAND} --unallow-folder FOLDER --signature NAME.")
    for folder, entry in folders.items():
        print_unwrapped(f"\n{_L1}Folder: {shown(folder)}")
        width = max(len(shown(t)) for t, *_ in entry["signatures"])
        for threat, first, last, now_allowed in entry["signatures"]:
            again = f", last run {last:%Y-%m-%d}" if last.date() != first.date() else ""
            plural = "s" if now_allowed != 1 else ""
            print(f"{_L2}{shown(threat):<{width}}  {now_allowed} file{plural} allowed · "
                  f"since {first:%Y-%m-%d}{again}")
        if entry["infected"]:
            n = entry["infected"]
            print_unwrapped(f"{_L2}[red]●[/red] {n} file{'s' if n != 1 else ''} here "
                            f"{'are' if n != 1 else 'is'} infected now and not allowed: "
                            f"{_command('--list-infected', folder)}")
        if expand:
            for path, file_entry in sorted(entry["files"].items()):
                _print_file(path, file_entry, _L2, _L3)


def _print_files(title: str, entries: dict, note: str, top: int | None = None) -> None:
    print(f"\n[bold]=== {title} ({len(entries)}) ===[/bold]")
    print(note)
    for key, entry in sorted(entries.items())[:top]:
        _print_file(key if isinstance(key, str) else key[0], entry, _L1, _L2)
    if top is not None and len(entries) > top:
        print(f"\n{_L1}… and {len(entries) - top} more: ensign-scan --list-allowed")


def allowed_report(engine: Engine, paths: list[str] | None = None, top: int = 10) -> int:
    """The end-of-run section: the --list-allowed layout, limited to the
    run's scope (`paths`, as for the other reports). Every folder that
    overlaps the scope is shown; files stop at `top`. Returns how many
    folders and files there are in scope."""
    folders, files, _gone = _gather(engine)
    if paths:
        scope = [str(p).rstrip("/") or "/" for p in paths]
        folders = {f: e for f, e in folders.items()
                   if any(_under(f, p) or _under(p, f) for p in scope)}
        files = {f: e for f, e in files.items() if any(_under(f, p) for p in scope)}
    if folders:
        _print_folders(folders, expand=False)
    if files:
        _print_files("FILES YOU ALLOWED", files,
                     "Flagged by ClamAV, and marked by you as false positives; not counted as "
                     f"infected. Undo one with {_COMMAND} --unallow PATH.", top=top)
    return len(folders) + len(files)


def list_allowed(engine: Engine, expand: bool = False) -> int:
    """Everything you've allowed: each folder once, with its signatures, then
    each file once, with its signatures. A file that a folder covers (same
    signature, inside it) is counted under the folder; with `expand`
    (--list-allowed-all) it's also listed there, one level in. Returns how
    many folders and files were listed."""
    folders, files, gone = _gather(engine)
    if not folders and not files and not gone:
        print(f"Nothing is allowed. ({_COMMAND} --allow PATH marks a flagged file as a false positive.)")
        return 0
    if folders:
        _print_folders(folders, expand)
        if not expand:
            print(f"\n{_L1}ensign-scan --list-allowed-all also lists the files in each folder.")
    if files:
        _print_files("FILES YOU ALLOWED", files, f"Undo one with {_COMMAND} --unallow PATH.")
    if gone:
        _print_files("ALLOWED, BUT NOT ON DISK NOW", gone,
                     "No tracked file has this content right now; shown where it was when you "
                     "allowed it. If it comes back unchanged, it's still allowed.")
    return len(folders) + len(files) + len(gone)
